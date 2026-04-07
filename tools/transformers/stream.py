#!/usr/bin/env python3
"""StreamFab Proxyman キャプチャ → Chrome extension 形式変換.

Proxyman でキャプチャした StreamFab の通信ログ (headers/, msl/, cookies/, capture_log.jsonl)
を Chrome extension と同一形式の出力に変換する。

Usage:
  python -m tools.transformers.stream raws/stream
  python -m tools.transformers.stream raws/stream -o logs/stream
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def _load_capture_log(path: Path) -> list[dict]:
    """capture_log.jsonl を読み込む."""
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def _load_cookies(cookies_dir: Path) -> dict[str, str]:
    """cookies/cookies.txt (Netscape形式) からクッキーを読み込む."""
    cookies: dict[str, str] = {}
    cookies_file = cookies_dir / "cookies.txt"
    if not cookies_file.exists():
        return cookies
    with open(cookies_file) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies[parts[5]] = parts[6]
    return cookies


def _load_set_cookies_log(cookies_dir: Path) -> list[dict]:
    """cookies/set_cookies.log からSet-Cookie履歴を読み込む."""
    entries = []
    log_file = cookies_dir / "set_cookies.log"
    if not log_file.exists():
        return entries
    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Format: <timestamp> <cookie_string>
            parts = line.split(" ", 1)
            if len(parts) == 2:
                entries.append({"ts": parts[0], "setCookie": parts[1]})
    return entries


def _classify_url(url: str) -> str:
    """URL をカテゴリに分類."""
    base = url.split("?")[0]
    if "/licensedmanifest/" in base:
        return "msl.licensedManifest"
    if "/cadmium/manifest/" in base:
        return "msl.manifest"
    if "/pbo_manifests/" in base:
        return "msl.pboManifest"
    if "/pbo_licenses/" in base:
        return "msl.pboLicense"
    if "/pbo_tokens/" in base:
        return "msl.pboTokens"
    if "/graphql" in base:
        return "graphql"
    if "/metadata" in base:
        return "metadata"
    if "/pathEvaluator" in base:
        return "pathEvaluator"
    if "/appboot" in base:
        return "appboot"
    if "/ftl/probe" in base:
        return "ftl.probe"
    if "/pulse.perfmetrics" in base:
        return "perfmetrics"
    if "/log" in base or "ichnaea" in base:
        return "logging"
    if "/event/" in base:
        return "msl.event"
    if "/logblob" in base:
        return "msl.logblob"
    if "/push" in base or "pushnotify" in base:
        return "notification"
    if "service-worker" in base:
        return "service-worker"
    if "/browse" in base or "/title/" in base:
        return "page"
    if "/iosui/" in base:
        return "ios.ui"
    return "other"


class StreamTransformer:
    """Proxyman キャプチャの StreamFab データを変換."""

    def __init__(self):
        self.seq = 0
        self.capture_entries: list[dict] = []
        self.msl_messages: list[dict] = []
        self.http_captures: list[dict] = []
        self.esn: dict = {"prv": None, "pxa": None, "capturedAt": ""}
        self.manifests_raw: list[dict] = []
        self._cookies: dict[str, str] = {}
        self.crypto_keys: dict = {"generateKey": [], "importKey": [], "deriveKey": []}
        self.ale_keys: list[dict] = []
        self.licenses: list[dict] = []
        self.provisions: list[dict] = []

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def transform(self, raw_dir: Path):
        """raws/stream/ ディレクトリ全体を読み込んで変換."""
        # ESN
        esn_file = raw_dir / "esn.txt"
        if esn_file.exists():
            esn = esn_file.read_text().strip()
            if esn:
                self.esn["prv"] = esn

        # Cookies
        cookies_dir = raw_dir / "cookies"
        if cookies_dir.exists():
            self._cookies = _load_cookies(cookies_dir)

        # capture_log.jsonl → HTTP captures
        capture_log = raw_dir / "capture_log.jsonl"
        if capture_log.exists():
            log_entries = _load_capture_log(capture_log)
            for e in log_entries:
                self._process_capture_entry(e)
            if not self.esn["capturedAt"] and log_entries:
                self.esn["capturedAt"] = log_entries[0].get("ts", "")

        # headers/ → request/response ヘッダー詳細
        headers_dir = raw_dir / "headers"
        if headers_dir.exists():
            for hf in sorted(headers_dir.iterdir()):
                if hf.suffix == ".json":
                    self._process_header_file(hf)

        # msl/ → MSL メッセージ (デコード済み)
        msl_dir = raw_dir / "msl"
        if msl_dir.exists():
            for mf in sorted(msl_dir.iterdir()):
                if mf.suffix == ".json":
                    self._process_msl_file(mf)

    def _process_capture_entry(self, e: dict):
        """capture_log.jsonl の各エントリを処理."""
        url = e.get("url", "")
        entry = {
            "seq": self.next_seq(),
            "type": "http.xhr",
            "ts": e.get("ts", ""),
            "url": url,
            "method": None,
            "requestHeaders": None,
            "statusCode": e.get("statusCode", 0),
            "statusText": "OK" if e.get("statusCode") == 200 else "",
            "responseHeaders": None,
            "category": _classify_url(url),
        }

        # ESN がキャプチャログに含まれる場合
        esn = e.get("esn", "")
        if esn:
            self._update_esn(esn, e.get("ts", ""))

        self.http_captures.append(entry)

    def _process_header_file(self, path: Path):
        """headers/*.json を処理してリクエスト/レスポンスヘッダーを記録."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return

        url = data.get("url", "")
        req_headers = data.get("requestHeaders", {})
        resp_headers = data.get("responseHeaders", {})

        # HTTP captures にヘッダー情報を補完
        entry = {
            "seq": data.get("seq", 0),
            "type": "http.xhr",
            "ts": data.get("ts", ""),
            "url": url,
            "method": req_headers.get(":method", "GET") if req_headers else "GET",
            "requestHeaders": req_headers,
            "statusCode": data.get("statusCode", 0),
            "statusText": "OK" if data.get("statusCode") == 200 else "",
            "responseHeaders": resp_headers,
            "category": _classify_url(url),
        }
        self.capture_entries.append(entry)

        # リクエストヘッダーから Cookie 抽出
        cookie_str = req_headers.get("Cookie", req_headers.get("cookie", ""))
        if cookie_str:
            for pair in cookie_str.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, _, value = pair.partition("=")
                    name = name.strip()
                    value = value.strip()
                    if name and value:
                        self._cookies[name] = value

    def _process_msl_file(self, path: Path):
        """msl/*.json を処理して MSL メッセージを記録."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return

        url = data.get("url", "")
        messages = data.get("messages", [])

        entry = {
            "seq": self.next_seq(),
            "type": "msl.message",
            "direction": data.get("direction", "response"),
            "ts": data.get("ts", ""),
            "url": url,
            "statusCode": data.get("statusCode", 0),
            "algorithm": "AES-CBC",
            "size": 0,
            "format": "json",
            "envelope": None,
            "header": None,
            "useridtoken": None,
            "servicetokens": None,
            "payload": messages[0] if len(messages) == 1 else None,
            "payloads": messages if len(messages) > 1 else None,
            "messageCount": len(messages),
            "category": _classify_url(url),
        }
        self.msl_messages.append(entry)
        self.capture_entries.append(entry)

        # マニフェスト・ライセンス抽出
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            self._extract_from_message(msg, data.get("ts", ""))

    def _extract_from_message(self, msg: dict, ts: str):
        """MSL メッセージからマニフェスト・ライセンスを抽出."""
        # result が直接存在する場合
        result = msg.get("result")
        if isinstance(result, dict):
            self._process_result(result, ts)
        elif isinstance(result, list):
            for item in result:
                if isinstance(item, dict):
                    self._process_result(item, ts)

        # data.result (GraphQL 形式)
        data = msg.get("data")
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, dict) and "result" in v:
                    r = v["result"]
                    if isinstance(r, dict):
                        self._process_result(r, ts)

    def _process_result(self, result: dict, ts: str):
        """result オブジェクトからマニフェスト/ライセンスを抽出."""
        # マニフェスト
        if "video_tracks" in result or "audio_tracks" in result:
            self.manifests_raw.append({"result": result})

        # ライセンス
        if "licenseResponseBase64" in result:
            self.licenses.append(
                {
                    "licenseResponseBase64": result.get("licenseResponseBase64", ""),
                    "drmGroupId": result.get("drmGroupId"),
                    "licenseType": result.get("licenseType"),
                    "expiration": result.get("expiration"),
                    "ts": ts,
                }
            )

    def _update_esn(self, esn: str, ts: str):
        """ESN を更新."""
        if not esn:
            return
        if "-PXA-" in esn.upper():
            self.esn["pxa"] = esn
        else:
            self.esn["prv"] = esn
        self.esn["capturedAt"] = ts


def write_output(t: StreamTransformer, out_dir: Path):
    """Chrome extension 互換形式で出力."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "keys").mkdir(exist_ok=True)
    (out_dir / "eme").mkdir(exist_ok=True)
    (out_dir / "eme" / "challenges").mkdir(exist_ok=True)
    (out_dir / "eme" / "responses").mkdir(exist_ok=True)

    # cookies.txt
    if t._cookies:
        with open(out_dir / "cookies.txt", "w") as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.write("# https://curl.se/docs/http-cookies.html\n")
            f.write("# Extracted from StreamFab Proxyman capture\n\n")
            for name, value in sorted(t._cookies.items()):
                f.write(f".netflix.com\tTRUE\t/\tTRUE\t0\t{name}\t{value}\n")

    # capture.jsonl
    with open(out_dir / "capture.jsonl", "w") as f:
        for entry in t.capture_entries:
            f.write(json.dumps(entry, indent=2, ensure_ascii=False) + "\n")

    # msl_messages.jsonl
    if t.msl_messages:
        with open(out_dir / "msl_messages.jsonl", "w") as f:
            for msg in t.msl_messages:
                f.write(json.dumps(msg, indent=2, ensure_ascii=False) + "\n")

    # http_captures.json
    if t.http_captures:
        with open(out_dir / "http_captures.json", "w") as f:
            json.dump(t.http_captures, f, indent=2, ensure_ascii=False)

    # esn.json
    if t.esn["prv"] or t.esn["pxa"]:
        with open(out_dir / "esn.json", "w") as f:
            json.dump(t.esn, f, indent=2)

    # manifest_<id>.json
    seen_movies: dict[str, dict] = {}
    for m in t.manifests_raw:
        mid = str(m.get("result", {}).get("movieId", "unknown"))
        seen_movies[mid] = m
    for mid, m in seen_movies.items():
        with open(out_dir / f"manifest_{mid}.json", "w") as f:
            json.dump(m, f, indent=2, ensure_ascii=False)

    # licenses.json
    if t.licenses:
        with open(out_dir / "keys" / "licenses.json", "w") as f:
            json.dump(t.licenses, f, indent=2, ensure_ascii=False)

    # Empty EME placeholders (StreamFab doesn't expose EME)
    with open(out_dir / "eme" / "sessions.json", "w") as f:
        json.dump([], f)
    with open(out_dir / "eme" / "key_statuses.json", "w") as f:
        json.dump([], f)


def print_summary(t: StreamTransformer):
    """変換結果のサマリーを表示."""
    print(f"[+] Transformed (StreamFab): {len(t.capture_entries)} entries")
    print(f"    MSL messages:  {len(t.msl_messages)}")
    print(f"    HTTP captures: {len(t.http_captures)}")
    print(f"    Cookies:       {len(t._cookies)}")
    print(f"    ESN:           {t.esn['prv'] or '(none)'}")
    print(f"    Licenses:      {len(t.licenses)}")
    movie_ids = {str(m.get("result", {}).get("movieId", "?")) for m in t.manifests_raw}
    print(
        f"    Manifests:     {len(movie_ids)} ({', '.join(sorted(movie_ids)) if movie_ids else 'none'})"
    )

    # カテゴリ別集計
    from collections import Counter

    cats = Counter()
    for e in t.http_captures:
        cats[e.get("category", "other")] += 1
    print("    --- URL categories ---")
    for cat, count in cats.most_common():
        print(f"    {cat:30s} {count:4d}")


def main():
    p = argparse.ArgumentParser(
        description="StreamFab Proxyman → Chrome log transformer"
    )
    p.add_argument("input", help="StreamFab raw data directory (e.g. raws/stream)")
    p.add_argument("-o", "--output", help="Output directory (default: logs/stream)")
    args = p.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[-] Directory not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output) if args.output else Path("logs") / "stream"

    print(f"[*] Input:  {input_path}")
    print(f"[*] Output: {out_dir}")

    t = StreamTransformer()
    t.transform(input_path)
    write_output(t, out_dir)
    print_summary(t)


if __name__ == "__main__":
    main()
