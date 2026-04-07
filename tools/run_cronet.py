#!/usr/bin/env python3
"""Netflix Cronet HTTP キャプチャ — Frida Python API.

hook_cronet.js を Frida Python API で起動し、
リクエスト/レスポンスを紐付けて保存する。

Architecture:
  JS (hook_cronet.js)         Python (このファイル)
  ──────────────────          ────────────────────
  CronetUrlRequest.start()    on_message(req)
    → send({type:"req",...})    → pending[reqId] に保存

  onSucceeded                 on_message(resp)
    → send({type:"resp",...})   → pending[reqId] と結合
                                → .md ファイルに保存
                                → capture.jsonl に追記
  onFailed
    → send({type:"resp",       同上 (error フィールド付き)
            error:...})

Output:
  logs/android_YYYYMMDD/cronet/
    {domain}/
      {path_seg1}/
        {path_seg2}/
          0001.md             ← Request + Response 統合 (Proxyman 風)
          0001_req_plain.json ← MSL 復号済リクエスト (アプリ層 JSON)
          0001_resp_plain.json← MSL 復号済レスポンス (CBOR→GZIP→JSON)
    capture.jsonl             ← 全イベント (raw)

Usage:
  python run_cronet.py                  # デフォルト hook_cronet.js
  python run_cronet.py my_hook.js       # カスタムスクリプト
  Ctrl+C で停止
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import cbor2

import frida
import frida_tools
from dotenv import load_dotenv

load_dotenv()

# ─── Helpers ─────────────────────────────────────────────


def sanitize(name: str, max_len: int = 80) -> str:
    """ファイル名に使えない文字を _ に置換."""
    return re.sub(r"[^\w.\-]", "_", name)[:max_len]


def load_java_bridge() -> str:
    """frida-tools の Java ブリッジソースを読み込む.

    create_script() は素の JS ランタイムを作成するため、
    Java グローバルが存在しない。frida CLI が使用するのと同じ
    ブリッジファイルを先頭に付加して Java API を有効化する。
    """
    bridges_dir = Path(frida_tools.__file__).parent / "bridges"
    java_js = bridges_dir / "java.js"
    if not java_js.exists():
        raise FileNotFoundError(f"Java bridge not found: {java_js}")
    source = java_js.read_text(encoding="utf-8")
    # java.js は `var bridge=function(){...}();` 形式。
    # globalThis.Java に割り当てる。
    return (
        source + "\n"
        "Object.defineProperty(globalThis, 'Java', {"
        "  value: bridge, writable: false, configurable: true"
        "});\n"
    )


def fmt_size(n: int | str) -> str:
    """バイト数を人間可読に."""
    n = int(n) if n else 0
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n / (1024 * 1024):.1f}MB"


def is_text_content(ct: str) -> bool:
    """Content-Type がテキスト系か."""
    return any(
        t in ct
        for t in ("json", "text", "xml", "html", "javascript", "x-www-form-urlencoded")
    )


def pretty_json(text: str) -> str | None:
    """JSON 文字列を整形。失敗時は None."""
    try:
        return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
    except (json.JSONDecodeError, TypeError):
        return None


# ─── Core ────────────────────────────────────────────────


class CronetCapture:
    """Frida Python API を使った Cronet HTTP キャプチャ."""

    # 無視するドメイン（コンソール出力・ファイル保存ともにスキップ）
    _IGNORE_DOMAINS: set[str] = {
        "android14.logs.netflix.com",
    }

    def __init__(self, host: str, bundle_id: str, script_path: str):
        self.host = host
        self.bundle_id = bundle_id
        self.script_path = script_path

        # セッションディレクトリ
        session_id = datetime.now().strftime("%Y%m%d")
        self.session_dir = Path("logs") / f"android_{session_id}"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.capture_file = self.session_dir / "capture.jsonl"

        # Frida ハンドル
        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None
        self._script: frida.core.Script | None = None
        self._pid: int | None = None

        # リクエスト追跡
        self._pending: dict[str, dict] = {}  # reqId → request info
        self._seq = 0  # グローバル連番
        self._domain_seq: dict[str, int] = {}  # domain → 連番

        # エラー重複抑制
        self._error_counts: dict[str, int] = {}  # url_pattern → count

        # MSL 平文トラッキング
        self._msl_req_queue: dict[str, list[bytes]] = {}  # url_pattern → [body, ...]
        self._msl_last_save: dict | None = None  # {dir, base, url}
        self._msl_decrypt_buf: list[bytes] = []  # 復号チャンク蓄積

        # 統計
        self._stats = {
            "requests": 0,
            "responses": 0,
            "errors": 0,
            "bytes": 0,
            "msl_decrypted": 0,
        }

        # 停止イベント
        self._stop = threading.Event()

    # ─── ライフサイクル ───

    def start(self):
        """デバイスに接続し、アプリを起動してキャプチャを開始."""
        print(f"[*] Connecting to {self.host}...")
        mgr = frida.get_device_manager()
        self._device = mgr.add_remote_device(self.host)

        print(f"[*] Spawning {self.bundle_id}...")
        self._pid = self._device.spawn([self.bundle_id])

        print(f"[*] Attaching to PID {self._pid}...")
        self._session = self._device.attach(self._pid)
        self._session.on("detached", self._on_detached)

        print(f"[*] Resuming app (waiting for Java VM)...")
        self._device.resume(self._pid)
        time.sleep(2)

        print(f"[*] Loading Java bridge + {self.script_path}...")
        bridge = load_java_bridge()
        user_source = Path(self.script_path).read_text()
        source = bridge + "\n" + user_source
        self._script = self._session.create_script(source, runtime="v8")
        self._script.on("message", self._on_message)
        self._script.load()

        print(f"[*] Saving → {self.session_dir}")
        print(f"[*] Press Ctrl+C to stop\n")

        # メインスレッドをブロック
        self._stop.wait()

    def stop(self):
        """クリーンシャットダウン."""
        if self._stop.is_set():
            return
        self._stop.set()

        print(f"\n[*] Stopping...")
        try:
            if self._script:
                self._script.unload()
        except Exception:
            pass
        try:
            if self._session:
                self._session.detach()
        except Exception:
            pass
        try:
            if self._device and self._pid:
                self._device.kill(self._pid)
        except Exception:
            pass

        self._print_summary()

    def _on_detached(self, reason, crash):
        print(f"\n[*] Detached: {reason}")
        if crash:
            print(f"[!] Crash: {crash}")
        self._stop.set()

    # ─── メッセージハンドラ ───

    def _on_message(self, message: dict, data: bytes | None):
        msg_type = message.get("type")

        if msg_type == "send":
            self._handle_event(message["payload"], data)
        elif msg_type == "log":
            level = message.get("level", "info")
            text = message.get("payload", "")
            if level == "error":
                print(f"  [!] {text}", file=sys.stderr)
            else:
                print(f"  {text}")
        elif msg_type == "error":
            desc = message.get("description", "")
            print(f"  [!] Script error: {desc}", file=sys.stderr)

    def _handle_event(self, payload: dict, data: bytes | None):
        evt = payload.get("type")
        domain = payload.get("domain", "")

        # 無視リストに該当するドメインは完全スキップ
        if any(domain.endswith(d) for d in self._IGNORE_DOMAINS):
            return

        if evt == "req":
            self._on_request(payload)
        elif evt == "resp":
            self._on_response(payload)
        elif evt == "redirect":
            self._on_redirect(payload)
        elif evt == "msl_req":
            self._on_msl_request(payload)
        elif evt == "msl_decrypt":
            self._on_msl_decrypt(payload)

        # capture.jsonl に全イベントを記録
        self._append_jsonl(payload)

    # ─── イベント処理 ───

    def _on_request(self, p: dict):
        req_id = p["reqId"]
        self._pending[req_id] = {
            "reqId": req_id,
            "url": p.get("url"),
            "method": p.get("method", "GET"),
            "domain": p.get("domain", "unknown"),
            "headers": p.get("headers", {}),
            "hasBody": p.get("hasBody", False),
            "req_body_b64": p.get("req_body_b64"),
            "ts": p.get("ts"),
        }
        self._stats["requests"] += 1

        method = p.get("method", "?")
        url = p.get("url", "?")
        ct = (p.get("headers") or {}).get(
            "Content-Type", (p.get("headers") or {}).get("content-type", "")
        )
        enc = (p.get("headers") or {}).get(
            "Content-Encoding", (p.get("headers") or {}).get("content-encoding", "")
        )
        detail = f" [{enc}]" if enc else (f" ({ct})" if ct else "")
        print(f"  -> {method} {url}{detail}")

    def _on_response(self, p: dict):
        req_id = p["reqId"]
        req = self._pending.pop(req_id, None)

        if not req:
            # req が届く前に resp が来た場合のフォールバック
            req = {
                "reqId": req_id,
                "url": p.get("url", "unknown"),
                "method": p.get("method", "?"),
                "domain": p.get("domain", "unknown"),
                "headers": {},
                "ts": p.get("ts"),
            }

        # ボディをデコード
        body_bytes: bytes | None = None
        if p.get("body_b64"):
            try:
                body_bytes = base64.b64decode(p["body_b64"])
            except Exception:
                pass

        status = p.get("statusCode")
        error = p.get("error")
        proto = p.get("protocol", "?")
        body_size = len(body_bytes) if body_bytes else int(p.get("bodySize", 0) or 0)
        resp_headers = p.get("responseHeaders") or {}

        # cURL ファイルに保存
        self._seq += 1
        self._save_request(
            seq=self._seq,
            req=req,
            status=status,
            status_text=p.get("statusText", ""),
            protocol=proto,
            resp_headers=resp_headers,
            body=body_bytes,
            body_size=body_size,
            error=error,
        )

        # コンソール出力
        if error:
            self._stats["errors"] += 1
            url_pat = self._url_pattern(req.get("url", ""))
            self._error_counts[url_pat] = self._error_counts.get(url_pat, 0) + 1
            cnt = self._error_counts[url_pat]
            if cnt <= 3:
                print(f"  ✗ {req['method']} {req['url']}")
                print(f"    {error}")
            elif cnt == 4:
                print(f"    (以降同一パターンのエラーは省略)")
        else:
            self._stats["responses"] += 1
            self._stats["bytes"] += body_size
            body_preview = ""
            if body_bytes and body_size < 4096:
                ct = resp_headers.get("content-type", "")
                if is_text_content(ct):
                    try:
                        text = body_bytes.decode("utf-8")
                        bp = text[:120]
                        if len(text) > 120:
                            bp += "..."
                        body_preview = f"\n    {bp}"
                    except UnicodeDecodeError:
                        pass
            print(
                f"  <- {status} {req['method']} {req['url']}"
                f" ({fmt_size(body_size)}){body_preview}"
            )

    def _on_redirect(self, p: dict):
        print(f"  ~> {p.get('statusCode')} {p.get('url')} -> {p.get('newUrl')}")

    # ─── MSL 平文キャプチャ ───

    def _on_msl_request(self, p: dict):
        """ApiHandlerImpl.apiRequest からの MSL リクエスト平文."""
        url = p.get("url", "?")
        body_b64 = p.get("body_b64")
        body = base64.b64decode(body_b64) if body_b64 else None
        size = len(body) if body else 0

        url_key = self._url_pattern(url)
        self._msl_req_queue.setdefault(url_key, []).append(body)

        print(f"  \U0001f513 MSL req plaintext {url} ({fmt_size(size)})")

    def _on_msl_decrypt(self, p: dict):
        """WidevineCryptoContext.c からの復号済み MSL ペイロードチャンク."""
        b64 = p.get("plaintext_b64")
        if not b64:
            return
        plaintext = base64.b64decode(b64)

        # CBOR デコード → key 62 (GZIP データ) → 展開
        try:
            chunk = cbor2.loads(plaintext)
        except Exception:
            # CBOR デコード失敗時は生データを保存
            self._msl_decrypt_buf.append(plaintext)
            return

        end_of_msg = chunk.get(63, False)
        compressed = chunk.get(62)  # GZIP 圧縮済みペイロード

        if compressed:
            try:
                decompressed = gzip.decompress(compressed)
                self._msl_decrypt_buf.append(decompressed)
            except Exception:
                # GZIP 展開失敗 → 生データ
                self._msl_decrypt_buf.append(
                    compressed if isinstance(compressed, bytes) else plaintext
                )

        if end_of_msg and self._msl_decrypt_buf:
            combined = b"".join(self._msl_decrypt_buf)
            self._msl_decrypt_buf.clear()
            self._stats["msl_decrypted"] += 1

            # 最後に保存した MSL リクエストと同じディレクトリに保存
            if self._msl_last_save:
                save_dir = self._msl_last_save["dir"]
                base = self._msl_last_save["base"]
                self._save_msl_plaintext(save_dir, base, "resp", combined)
                url = self._msl_last_save.get("url", "?")
                print(
                    f"  \U0001f513 MSL resp decrypted {url} ({fmt_size(len(combined))})"
                )

    def _save_msl_plaintext(
        self, save_dir: Path, base: str, direction: str, data: bytes
    ):
        """MSL 平文をファイルに保存. JSON なら整形して .json, それ以外は .bin."""
        try:
            text = data.decode("utf-8")
            parsed = json.loads(text)
            content = json.dumps(parsed, indent=2, ensure_ascii=False)
            path = save_dir / f"{base}_{direction}_plain.json"
            path.write_text(content + "\n")
        except (UnicodeDecodeError, json.JSONDecodeError):
            path = save_dir / f"{base}_{direction}_plain.bin"
            path.write_bytes(data)

    # ─── ファイル保存 ───

    def _save_request(
        self,
        seq: int,
        req: dict,
        status,
        status_text: str,
        protocol: str,
        resp_headers: dict,
        body: bytes | None,
        body_size: int,
        error: str | None,
    ):
        domain = req.get("domain", "unknown")
        url = req.get("url", "unknown")
        method = req.get("method", "GET")
        req_headers = req.get("headers") or {}

        # URL パスに基づくネストされたディレクトリ構造
        parsed = urlparse(url)
        path_segments = [s for s in parsed.path.strip("/").split("/") if s]

        save_dir = self.session_dir / sanitize(domain)
        for seg in path_segments:
            save_dir = save_dir / sanitize(seg)
        save_dir.mkdir(parents=True, exist_ok=True)

        # パス単位で連番管理
        path_key = f"{domain}/{'/'.join(path_segments) or '/'}"
        self._domain_seq[path_key] = self._domain_seq.get(path_key, 0) + 1
        dseq = self._domain_seq[path_key]
        base_name = f"{dseq:04d}"

        lines: list[str] = []

        # ── Request セクション ──
        lines.append(f"## Request")
        lines.append("")
        lines.append(f"```")
        lines.append(
            f"{method} {parsed.path}{'?' + parsed.query if parsed.query else ''} {protocol}"
        )
        lines.append(f"Host: {parsed.netloc}")
        for k, v in req_headers.items():
            lines.append(f"{k}: {v}")
        lines.append(f"```")

        # リクエストボディ
        req_body_bytes: bytes | None = None
        req_body_b64 = req.get("req_body_b64")
        if req_body_b64:
            try:
                req_body_bytes = base64.b64decode(req_body_b64)
            except Exception:
                pass

        if req_body_bytes:
            ct = req_headers.get("Content-Type", req_headers.get("content-type", ""))
            lines.append("")
            lines.append(f"### Body ({fmt_size(len(req_body_bytes))})")
            lines.append("")
            if is_text_content(ct):
                try:
                    text = req_body_bytes.decode("utf-8")
                    pretty = pretty_json(text)
                    lang = "json" if pretty else ""
                    lines.append(f"```{lang}")
                    lines.append(pretty or text)
                    lines.append("```")
                except UnicodeDecodeError:
                    lines.append(f"*Binary data — {fmt_size(len(req_body_bytes))}*")
            else:
                lines.append(f"*Binary data — {fmt_size(len(req_body_bytes))}*")
        elif req.get("hasBody"):
            lines.append("")
            lines.append(f"### Body")
            lines.append("")
            lines.append(f"*Body not captured*")

        # MSL リクエスト平文
        req_enc = req_headers.get(
            "Content-Encoding", req_headers.get("content-encoding", "")
        )
        if "msl" in req_enc.lower():
            url_key = self._url_pattern(url)
            queue = self._msl_req_queue.get(url_key, [])
            msl_body = queue.pop(0) if queue else None
            if msl_body:
                self._save_msl_plaintext(save_dir, base_name, "req", msl_body)
                # インラインにも追加
                lines.append("")
                lines.append(f"### MSL Plaintext (decrypted request)")
                lines.append("")
                try:
                    text = msl_body.decode("utf-8")
                    pretty = pretty_json(text)
                    lines.append(f"```json")
                    lines.append(pretty or text)
                    lines.append("```")
                except UnicodeDecodeError:
                    lines.append(f"*Binary — {fmt_size(len(msl_body))}*")
            # レスポンス decrypt の紐付け用に保存先を記録
            self._msl_last_save = {"dir": save_dir, "base": base_name, "url": url}

        # ── Response セクション ──
        lines.append("")
        lines.append("---")
        lines.append("")

        if error:
            lines.append(f"## Response — ERROR")
            lines.append("")
            lines.append(f"```")
            lines.append(error)
            lines.append(f"```")
        elif status is not None:
            lines.append(f"## Response")
            lines.append("")
            lines.append(f"```")
            lines.append(f"{protocol} {status} {status_text}")
            for k, v in resp_headers.items():
                lines.append(f"{k}: {v}")
            lines.append(f"```")

            if body:
                ct = resp_headers.get("content-type", "")
                lines.append("")
                lines.append(f"### Body ({fmt_size(body_size)})")
                lines.append("")

                if is_text_content(ct):
                    try:
                        text = body.decode("utf-8")
                        pretty = pretty_json(text)
                        lang = "json" if pretty else ""
                        lines.append(f"```{lang}")
                        lines.append(pretty or text)
                        lines.append("```")
                    except UnicodeDecodeError:
                        lines.append(f"*Binary data — {fmt_size(body_size)}*")
                else:
                    lines.append(f"*Binary data — {fmt_size(body_size)}*")

        # ── メタデータ ──
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(f"<!-- {req.get('reqId', '?')} | {req.get('ts', '?')} -->")

        # .md ファイル書き出し
        md_path = save_dir / f"{base_name}.md"
        md_path.write_text("\n".join(lines) + "\n")

    # ─── ユーティリティ ───

    def _url_pattern(self, url: str) -> str:
        """URL をパターン化 (重複抑制用)."""
        try:
            p = urlparse(url)
            return f"{p.netloc}{p.path}"
        except Exception:
            return url

    def _append_jsonl(self, payload: dict):
        """capture.jsonl にイベントを追記."""
        with open(self.capture_file, "a") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _print_summary(self):
        s = self._stats
        print(f"\n{'=' * 60}")
        print(f"  Capture Summary")
        print(f"  Requests:      {s['requests']}")
        print(f"  Responses:     {s['responses']}")
        print(f"  MSL Decrypted: {s['msl_decrypted']}")
        print(f"  Errors:        {s['errors']}")
        print(f"  Data:          {fmt_size(s['bytes'])}")
        print(f"  Saved to:      {self.session_dir}")
        print()

        for domain_dir in sorted(self.session_dir.iterdir()):
            if domain_dir.is_dir():
                md_files = list(domain_dir.rglob("*.md"))
                plain_files = list(domain_dir.rglob("*_plain.*"))
                if md_files:
                    extra = f", {len(plain_files)} decrypted" if plain_files else ""
                    print(f"  {domain_dir.name}/  ({len(md_files)} files{extra})")
                    for f in sorted(md_files)[:8]:
                        rel = f.relative_to(domain_dir)
                        print(f"    {rel}")
                    if len(md_files) > 8:
                        print(f"    ... and {len(md_files) - 8} more")

        # エラー頻度の高い URL パターン
        if self._error_counts:
            print()
            print(f"  Error patterns:")
            for pat, cnt in sorted(self._error_counts.items(), key=lambda x: -x[1])[:5]:
                print(f"    {cnt:>4}x  {pat}")

        print(f"{'=' * 60}")


# ─── Main ────────────────────────────────────────────────


def main():
    script = sys.argv[1] if len(sys.argv) > 1 else "hook_cronet.js"
    host = os.getenv("ANDROID_HOST", "192.168.0.37")
    bundle_id = "com.netflix.mediaclient"

    if not Path(script).exists():
        print(f"[!] Script not found: {script}")
        sys.exit(1)

    print(f"[*] Platform: Android (Frida Python API)")
    print(f"[*] Host:     {host}")
    print(f"[*] Target:   {bundle_id}")
    print(f"[*] Script:   {script}")

    capture = CronetCapture(host, bundle_id, script)

    def shutdown(sig, frame):
        capture.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        capture.start()
    except KeyboardInterrupt:
        pass
    except frida.ServerNotRunningError:
        print(f"[!] Frida server is not running on {host}")
        print(f"    Start frida-server on the device first.")
        sys.exit(1)
    except frida.ProcessNotFoundError:
        print(f"[!] Could not spawn {bundle_id}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] {type(e).__name__}: {e}")
    finally:
        capture.stop()


if __name__ == "__main__":
    main()
