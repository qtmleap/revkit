#!/usr/bin/env python3
"""Netflix Frida Hook Runner with domain-based log organization.

Uses frida CLI subprocess (ObjC runtime works correctly with CLI).
Parses @@LOG@@ lines and saves to domain-based directory structure:
  logs/<session>/
    <domain>/
      <seq>_<event>.json
    crypto/
      <seq>_<event>.json
    capture.jsonl        (all entries, flat)
    console.log

Usage:
  python run.py [script]              # iOS (default)
  python run.py --android [script]    # Android (spawn mode)
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from dotenv import load_dotenv

load_dotenv()

LOG_PREFIX = "@@LOG@@"


def get_pid(host: str, bundle_id: str) -> int:
    """Get Netflix PID from frida-ps."""
    result = subprocess.run(
        ["frida-ps", "-H", host, "-a"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    for line in result.stdout.splitlines():
        if bundle_id in line:
            return int(line.split()[0])
    return 0


def kill_app(host: str, bundle_id: str) -> None:
    """Kill running app via Frida."""
    import frida

    try:
        device = frida.get_device_manager().add_remote_device(host)
        pid = get_pid(host, bundle_id)
        if pid:
            device.kill(pid)
            print(f"[*] Killed {bundle_id} (PID: {pid})")
            import time

            time.sleep(2)
    except Exception as e:
        print(f"[-] Kill failed: {e}")


def launch_app(host: str, bundle_id: str) -> None:
    """Launch app via Frida spawn+resume (no script injection)."""
    import frida
    import time

    device = frida.get_device_manager().add_remote_device(host)
    pid = device.spawn([bundle_id])
    device.resume(pid)
    print(f"[*] Spawned {bundle_id} (PID: {pid}), waiting for startup...")
    time.sleep(5)


def sanitize(name: str) -> str:
    """Sanitize filename component."""
    return re.sub(r"[^\w.\-]", "_", name)[:80]


def deep_parse_json(obj):
    """Recursively parse JSON strings embedded in dicts/lists."""
    if isinstance(obj, str):
        s = obj.strip()
        if s.startswith(("{", "[")):
            try:
                return deep_parse_json(json.loads(s))
            except (json.JSONDecodeError, TypeError):
                pass
        return obj
    if isinstance(obj, dict):
        return {k: deep_parse_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deep_parse_json(v) for v in obj]
    return obj


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Netflix Frida Hook Runner")
    parser.add_argument(
        "--android", action="store_true", help="Target Android device (spawn mode)"
    )
    parser.add_argument(
        "script", nargs="?", default=None, help="Frida script to inject"
    )
    return parser.parse_args()


def _export_cookies_and_headers(capture_file: Path, session_dir: Path):
    """capture.jsonl から cookies.txt と headers.txt を生成."""
    if not capture_file.exists():
        return

    all_cookies: dict[str, str] = {}
    all_headers: dict[str, str] = {}
    credentials: dict[str, str] = {}

    # cred イベント → cookie 名のマッピング
    cred_map = {
        "cred.netflixId": "NetflixId",
        "cred.secureNetflixId": "SecureNetflixId",
        "cred.nfvdid": "nfvdid",
    }

    with open(capture_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                event = entry.get("event", "")

                if event == "http.headers":
                    for k, v in entry.get("cookies", {}).items():
                        if v and (k not in all_cookies or len(v) > len(all_cookies[k])):
                            all_cookies[k] = v
                    for k, v in entry.get("headers", {}).items():
                        if k not in all_headers:
                            all_headers[k] = v
                elif event in cred_map:
                    val = entry.get("value", "")
                    cookie_name = cred_map[event]
                    if val and (
                        cookie_name not in credentials
                        or len(val) > len(credentials[cookie_name])
                    ):
                        credentials[cookie_name] = val
            except (json.JSONDecodeError, TypeError):
                continue

    # cred で取得した値を cookies にマージ (cred の方が完全な値)
    for k, v in credentials.items():
        if v and (k not in all_cookies or len(v) > len(all_cookies[k])):
            all_cookies[k] = v

    if all_cookies:
        cookies_file = session_dir / "cookies.txt"
        with open(cookies_file, "w") as f:
            for k, v in sorted(all_cookies.items()):
                f.write(f"{k}={v}\n")
        print(f"[*] Exported {len(all_cookies)} cookies → {cookies_file}")

    if all_headers:
        headers_file = session_dir / "headers.txt"
        with open(headers_file, "w") as f:
            for k, v in sorted(all_headers.items()):
                f.write(f"{k}: {v}\n")
        print(f"[*] Exported {len(all_headers)} headers → {headers_file}")


def main():
    args = parse_args()

    if args.android:
        host = os.getenv("ANDROID_HOST", "192.168.0.36")
        bundle_id = "com.netflix.mediaclient"
        script = args.script or "packages/frida/hook_netflix_android.js"
        platform = "android"
    else:
        host = os.getenv("IOS_HOST", "192.168.0.34")
        bundle_id = "com.netflix.Netflix"
        script = args.script or "packages/frida/hook_netflix.js"
        platform = "ios"

    if args.android:
        # Android: spawn mode (kills existing process automatically)
        print(f"[*] Platform: Android (spawn)")
        print(f"[*] Host: {host}")
        print(f"[*] Target: {bundle_id}")
        print(f"[*] Script: {script}")
        cmd = ["frida", "-f", bundle_id, "-l", script, "-H", host]
    else:
        # iOS: kill → launch → attach (クリーンスタート)
        pid = get_pid(host, bundle_id)
        if pid:
            print(f"[*] Netflix is running (PID: {pid}), killing...")
            kill_app(host, bundle_id)

        print(f"[*] Launching Netflix on {host}...")
        try:
            launch_app(host, bundle_id)
        except Exception as e:
            print(f"[-] Failed to launch: {e}")
            sys.exit(1)

        pid = get_pid(host, bundle_id)
        if not pid:
            print("[-] Netflix failed to start")
            sys.exit(1)

        print(f"[*] Platform: iOS (attach)")
        print(f"[*] Found Netflix (PID: {pid})")
        print(f"[*] Script: {script}")
        cmd = ["frida", "-p", str(pid), "-l", script, "-H", host]

    session_id = datetime.now().strftime("%Y%m%d")
    session_dir = Path("raws") / platform / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    capture_file = session_dir / "capture.jsonl"
    console_file = session_dir / "console.log"

    # 前回のログを削除
    for f in (capture_file, console_file):
        if f.exists():
            f.unlink()
            print(f"[*] Deleted {f}")

    print(f"[*] Session: {session_dir}")
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    def shutdown(sig, frame):
        print("\n[*] Shutting down...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    seq = 0
    domain_counts: dict[str, int] = {}
    log_count = 0

    # MSL 平文キュー: msl.api の params を domain 別に蓄積し、
    # 直後の http.request に紐付ける
    msl_plaintext_queue: dict[
        str, list[dict]
    ] = {}  # domain → [{params, url, ...}, ...]

    try:
        for line in proc.stdout:
            line = line.rstrip("\n")

            if line.startswith(LOG_PREFIX):
                json_str = line[len(LOG_PREFIX) :]
                try:
                    entry = json.loads(json_str)
                except json.JSONDecodeError:
                    print(line)
                    continue

                # Parse query parameters from URL
                url = entry.get("url") or ""
                if "?" in url:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    # Flatten single-value lists
                    queries = {}
                    for k, v in qs.items():
                        val = v[0] if len(v) == 1 else v
                        queries[k] = deep_parse_json(val)
                    entry["path"] = parsed.path
                    entry["queries"] = queries

                # Save to flat JSONL
                with open(capture_file, "a") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                log_count += 1
                seq += 1

                event = entry.get("event", "unknown")
                domain = entry.get("domain") or ""

                # MSL 平文の紐付け
                if event in ("msl.api", "msl.apiRequest"):
                    # 平文パラメータをキューに蓄積
                    # フック側のフィールド名は body または params
                    msl_body = entry.get("body") or entry.get("params")
                    msl_plaintext_queue.setdefault(domain, []).append(
                        {
                            "params": msl_body,
                            "url": entry.get("url"),
                            "headers": entry.get("headers"),
                            "userId": entry.get("userId"),
                            "userauthdata": entry.get("userauthdata"),
                        }
                    )
                elif event == "http.request" and domain:
                    # MSL 暗号化されたリクエストのみ平文を紐付け
                    req_headers = entry.get("headers") or {}
                    content_enc = (
                        req_headers.get("Content-Encoding")
                        or req_headers.get("content-encoding")
                        or ""
                    )
                    if "msl" in content_enc.lower():
                        queue = msl_plaintext_queue.get(domain, [])
                        if queue:
                            msl_info = queue.pop(0)
                            msl_params = msl_info.get("params")
                            if msl_params:
                                # body を復号済み MSL ペイロードに置換
                                try:
                                    entry["body"] = (
                                        json.loads(msl_params)
                                        if isinstance(msl_params, str)
                                        else msl_params
                                    )
                                except (json.JSONDecodeError, TypeError):
                                    entry["body"] = msl_params
                                entry["body_source"] = "msl_decrypted"
                                entry["msl_url"] = msl_info.get("url")
                            if not queue:
                                del msl_plaintext_queue[domain]

                # Determine save directory (domain + URL path segments)
                if domain:
                    save_dir = session_dir / sanitize(domain)
                    # URL パスに基づくネストされたディレクトリ構造
                    entry_url = entry.get("url") or ""
                    if entry_url:
                        try:
                            parsed_url = urlparse(entry_url)
                            path_segs = [
                                s for s in parsed_url.path.strip("/").split("/") if s
                            ]
                            for seg in path_segs:
                                save_dir = save_dir / sanitize(seg)
                        except Exception:
                            pass
                elif event.startswith("msl."):
                    save_dir = session_dir / "crypto"
                else:
                    save_dir = session_dir / "_other"

                save_dir.mkdir(parents=True, exist_ok=True)

                # Track per-path sequence
                path_key = str(save_dir.relative_to(session_dir))
                domain_counts[path_key] = domain_counts.get(path_key, 0) + 1
                dseq = domain_counts[path_key]

                # Save individual file per event
                domain_dir = save_dir

                body = entry.get("body") or entry.get("params")

                # Extract API path from MSL request/response for filename
                api_label = ""
                if event in ("msl.api", "msl.apiRequest") and body:
                    try:
                        body_obj = json.loads(body) if isinstance(body, str) else body
                        op = body_obj.get("operationName") or ""
                        inner_url = body_obj.get("url") or ""
                        if op:
                            api_label = f"_{sanitize(op)}"
                        elif inner_url:
                            api_label = f"_{sanitize(inner_url.strip('/'))}"
                    except (json.JSONDecodeError, TypeError):
                        pass
                elif event == "msl.api.response":
                    # url comes from x-originating-url header (set by hook)
                    resp_url = entry.get("url") or ""
                    if resp_url:
                        resp_parsed = urlparse(resp_url)
                        resp_path = resp_parsed.path.strip("/")
                        if resp_path:
                            api_label = f"_{sanitize(resp_path)}"

                base = f"{dseq:04d}_{sanitize(event)}{api_label}"
                response_str = entry.get("response")
                data_hex = entry.get("data_hex")
                has_b64 = any(k.endswith("_b64") for k in entry)

                # msl.api.response: responseフィールドをパースして個別保存
                if event == "msl.api.response" and response_str:
                    # メタデータ (response以外) を保存
                    meta = {k: v for k, v in entry.items() if k != "response"}
                    try:
                        resp_json = deep_parse_json(json.loads(response_str))
                        # パース済みレスポンスを保存
                        with open(domain_dir / f"{base}.json", "w") as f:
                            json.dump(
                                {**meta, "response": resp_json},
                                f,
                                ensure_ascii=False,
                                indent=2,
                            )
                    except (json.JSONDecodeError, TypeError):
                        # パース失敗 — そのまま保存
                        with open(domain_dir / f"{base}.json", "w") as f:
                            json.dump(
                                deep_parse_json(entry), f, ensure_ascii=False, indent=2
                            )
                elif has_b64:
                    # Crypto event with base64 fields — save as single JSON
                    with open(domain_dir / f"{base}.json", "w") as f:
                        json.dump(
                            deep_parse_json(entry), f, ensure_ascii=False, indent=2
                        )
                elif body is not None:
                    # Try to parse body as JSON
                    try:
                        body_json = json.loads(body) if isinstance(body, str) else body
                        body_json = deep_parse_json(body_json)
                        # Preserve metadata (event, ts, domain, url, etc.) alongside parsed body
                        meta = {
                            k: v
                            for k, v in entry.items()
                            if k not in ("body", "params")
                        }
                        out = {**meta, "body": body_json}
                        with open(domain_dir / f"{base}.json", "w") as f:
                            json.dump(out, f, ensure_ascii=False, indent=2)
                    except (json.JSONDecodeError, TypeError):
                        # Not JSON — save as text
                        with open(domain_dir / f"{base}.txt", "w") as f:
                            f.write(body if isinstance(body, str) else str(body))
                elif data_hex:
                    # Binary data — save as .bin + metadata .json
                    with open(domain_dir / f"{base}.bin", "wb") as f:
                        f.write(bytes.fromhex(data_hex))
                    meta = {k: v for k, v in entry.items() if k != "data_hex"}
                    with open(domain_dir / f"{base}.meta.json", "w") as f:
                        json.dump(meta, f, ensure_ascii=False, indent=2)
                else:
                    # URL or other metadata — save as .json
                    with open(domain_dir / f"{base}.json", "w") as f:
                        json.dump(
                            deep_parse_json(entry), f, ensure_ascii=False, indent=2
                        )

                # Console summary
                method = entry.get("method", "")
                url_disp = entry.get("url", "")
                size = entry.get("data_size") or entry.get("size", "")
                content_type = entry.get("content_type", "")

                # 暗号・認証に関係ないドメインは非表示
                _SKIP_DOMAINS = (
                    "recaptcha.net",
                    "fast.com",
                    "assets.nflxext.com",
                    "codepush.nflxext.com",
                    "ichnaea.netflix.com",
                    "nflxso.net",  # CDN 画像・BIF サムネイル
                    "nflximg.net",  # CDN 画像
                    "nflxvideo.net",  # 動画セグメント
                )
                if domain and any(d in domain for d in _SKIP_DOMAINS):
                    continue

                if event == "http.request":
                    ct_str = f", {content_type}" if content_type else ""
                    size_str = f" ({size}B{ct_str})" if size else ""
                    print(f"  > {method} {url_disp}{size_str}")
                elif event in ("msl.api", "msl.apiRequest"):
                    body_size = entry.get("body_size", 0)
                    print(f"  > MSL {url_disp} ({body_size}B)")
                elif event == "msl.api.response":
                    resp = entry.get("response", "") or ""
                    err = entry.get("error")
                    err_str = f" ERROR: {err}" if err else ""
                    print(f"  < MSL {url_disp} ({len(resp)}B){err_str}")
                elif event == "appboot.response":
                    resp = entry.get("response", "") or ""
                    err = entry.get("error")
                    err_str = f" ERROR: {err}" if err else ""
                    print(f"  < APPBOOT ({len(resp)}B){err_str}")
                elif event == "http.response":
                    status = entry.get("status", 0)
                    resp_size = entry.get("size", 0)
                    err = entry.get("error")
                    err_str = f" ERROR: {err}" if err else ""
                    print(f"  < {status} {url_disp} ({resp_size}B){err_str}")
                elif event == "url":
                    # URL 作成イベントは表示しない (http.request で十分)
                    pass
                elif event == "cronet.request":
                    req_hdrs = entry.get("requestHeaders", {})
                    ct = req_hdrs.get("Content-Type", req_hdrs.get("content-type", ""))
                    ct_str = f", {ct}" if ct else ""
                    print(f"  > {method} {url_disp}{ct_str}")
                elif event == "cronet.complete":
                    status = entry.get("statusCode", "?")
                    body_size = entry.get("bodySize", 0)
                    err = entry.get("error")
                    err_str = f" ERROR: {err}" if err else ""
                    print(f"  < {status} {url_disp} ({body_size}B){err_str}")
                elif event == "cronet.redirect":
                    new_url = entry.get("newUrl", "?")
                    status = entry.get("statusCode", "?")
                    print(f"  → {status} {url_disp} → {new_url}")
                elif event.startswith("msl."):
                    # crypto イベントはサイズと鍵取得状況を表示
                    pt = entry.get("plaintext_size", 0)
                    ct_size = entry.get("ciphertext_size", 0)
                    key_b64 = entry.get("key_b64")
                    key_str = (
                        f" key={'OK' if key_b64 else 'MISSING'}"
                        if event
                        in (
                            "msl.aesCbcEncrypt",
                            "msl.aesCbcDecrypt",
                            "msl.aesCbcEncryptDecrypt",
                        )
                        else ""
                    )
                    if pt or ct_size:
                        print(f"  [crypto] {event} ({ct_size}B → {pt}B){key_str}")
                    else:
                        size_str = f" ({size}B)" if size else ""
                        print(f"  [crypto] {event}{size_str}{key_str}")
                # その他は非表示

            else:
                # Regular console output — skip frida banner noise
                if line.startswith(("     ", "   . . .", "Attaching", "Spawned")):
                    continue
                print(line)
                with open(console_file, "a") as f:
                    f.write(line + "\n")

    except Exception as e:
        print(f"[!] {e}")
    finally:
        proc.wait()
        print(f"\n[*] {log_count} entries across {len(domain_counts)} domains")
        for d, c in sorted(domain_counts.items(), key=lambda x: -x[1]):
            print(f"    {d}: {c}")

        # キャプチャから cookies.txt と headers.txt を自動生成
        _export_cookies_and_headers(capture_file, session_dir)

        print(f"[*] Session: {session_dir}")


if __name__ == "__main__":
    main()
