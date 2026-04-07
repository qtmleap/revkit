"""
Netflix Raw Capture — mitmproxy addon

通信を一切改変せず、リクエスト/レスポンスの生データを保存する。
User-Agent / URL からプラットフォーム (ios, android, chrome) を自動判別。

使い方:
    mitmdump -p 8080 --set stream_large_bodies=0 \
        -s packages/mitmproxy/netflix_ios_capture.py

    デバイス側で Wi-Fi プロキシを <このマシンのIP>:8080 に設定し、
    http://mitm.it から CA 証明書をインストールする。

保存先: raws/<platform>/<date>/
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http, tls


# ── 設定 ──
BASE_DIR = Path(__file__).resolve().parent.parent.parent / "raws"

# ── TLS パススルー (SSL pinning 回避不可なホスト) ──
TLS_PASSTHROUGH_HOSTS = {
    "gateway.icloud.com",
    "mesu.apple.com",
}

# サフィックスマッチ (*.icloud.com, *.apple.com 等)
TLS_PASSTHROUGH_SUFFIXES = (
    ".icloud.com",
    ".apple.com",
    ".googleapis.com",
    ".gstatic.com",
)


# ── ログ抑制 (非対象ドメインの connect/disconnect/TLS エラーを非表示) ──
_INTERCEPT_DOMAINS = ("netflix.com", "nflxext.com", "nflxso.net", "nflximg.net", "nflxvideo.net")
_HOST_RE = re.compile(r"([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})(?::\d+)?")
_NOISE_KEYWORDS = (
    "client connect",
    "client disconnect",
    "server connect",
    "server disconnect",
    "handshake failed",
    "does not trust the proxy",
    "disconnected during the handshake",
)


def _should_intercept(hostname: str) -> bool:
    return any(hostname == d or hostname.endswith(f".{d}") for d in _INTERCEPT_DOMAINS)


class _NoiseFilter(logging.Filter):
    """非対象ドメインの接続系ログを抑制する."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        msg_lower = msg.lower()
        if not any(kw in msg_lower for kw in _NOISE_KEYWORDS):
            return True
        hosts = _HOST_RE.findall(msg)
        if not hosts:
            # ホスト名なし (bare "client connect" 等) → 抑制
            return False
        return any(_should_intercept(h) for h in hosts)


def _detect_platform(flow: http.HTTPFlow) -> str:
    ua = flow.request.headers.get("User-Agent", "")
    url = flow.request.pretty_url

    # iOS
    if "Darwin/" in ua or "CFNetwork/" in ua:
        return "ios"
    if "ios.prod." in url or "/iosui/" in url or "/iosplatform/" in url:
        return "ios"

    # Android
    if "okhttp/" in ua or "Cronet/" in ua:
        return "android"
    if "android" in ua.lower():
        return "android"

    # Chrome / browser
    if "Chrome/" in ua or "Mozilla/" in ua:
        return "chrome"

    return "unknown"


def _output_dir(platform: str) -> Path:
    return BASE_DIR / platform / datetime.now(timezone.utc).strftime("%Y%m%d")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S-%f")[:-3] + "Z"


def _classify(url: str) -> str:
    patterns = [
        ("pbo_manifests", "pbo_manifests"),
        ("pbo_license", "pbo_license"),
        ("pbo_tokens", "pbo_tokens"),
        ("licensedmanifest", "licensedmanifest"),
        ("playapi/ios/manifest", "ios_manifest"),
        ("playapi/ios/logblob", "ios_logblob"),
        ("/msl_v1/", "msl"),
        ("/msl/", "msl"),
        ("/license", "license"),
        ("/events", "events"),
        ("getProxyEsn", "getProxyEsn"),
        ("pathEvaluator", "pathEvaluator"),
        ("graphql", "graphql"),
        ("/iosui/", "iosui"),
        ("/appboot/", "appboot"),
        ("/config", "config"),
        ("/metadata", "metadata"),
        ("/shakti", "shakti"),
        ("/api/", "api"),
    ]
    for pattern, name in patterns:
        if pattern in url:
            return name
    return "other"


def _safe_json(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)


def _append(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(data)


# ── シーケンス番号 ──
_seq = 0


class NetflixCapture:
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """TLS パススルー: 指定ホストは MITM せずそのまま通す。"""
        if data.context.server.address:
            host = data.context.server.address[0]
            if host in TLS_PASSTHROUGH_HOSTS or host.endswith(TLS_PASSTHROUGH_SUFFIXES):
                data.ignore_connection = True

    def response(self, flow: http.HTTPFlow) -> None:
        """レスポンス受信時に呼ばれる。通信は改変しない。"""
        global _seq

        url = flow.request.pretty_url
        if "netflix.com" not in url and "netflix.net" not in url:
            return

        _seq += 1
        seq = _seq
        now = _ts()
        platform = _detect_platform(flow)
        endpoint = _classify(url)
        out = _output_dir(platform)

        # ── リクエスト生ボディ ──
        req_body = flow.request.raw_content
        if req_body:
            _write(out / "raw" / f"req_{seq}_{endpoint}_{now}.bin", req_body)

        # ── レスポンス生ボディ ──
        res_body = flow.response.raw_content if flow.response else b""
        if res_body:
            _write(out / "raw" / f"res_{seq}_{endpoint}_{now}.bin", res_body)

        # ── ヘッダー + メタデータ ──
        meta = {
            "seq": seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "url": url,
            "method": flow.request.method,
            "platform": platform,
            "endpoint": endpoint,
            "statusCode": flow.response.status_code if flow.response else None,
            "requestHeaders": dict(flow.request.headers),
            "responseHeaders": dict(flow.response.headers) if flow.response else {},
            "requestBodySize": len(req_body) if req_body else 0,
            "responseBodySize": len(res_body) if res_body else 0,
        }
        _write(out / "headers" / f"{seq}_{endpoint}_{now}.json", _safe_json(meta))

        # ── Cookie ──
        cookie_header = flow.request.headers.get("Cookie", "")
        if cookie_header:
            lines = []
            cookie_obj = {}
            for c in cookie_header.split(";"):
                c = c.strip()
                if "=" in c:
                    name, val = c.split("=", 1)
                    lines.append(f".netflix.com\tTRUE\t/\tTRUE\t0\t{name}\t{val}")
                    cookie_obj[name] = val
            _write(out / "cookies" / "cookies.txt", "\n".join(lines) + "\n")
            _write(out / "cookies" / "cookies.json", _safe_json(cookie_obj))

        # ── Set-Cookie ──
        set_cookie = (
            flow.response.headers.get("Set-Cookie", "") if flow.response else ""
        )
        if set_cookie:
            _append(
                out / "cookies" / "set_cookies.log",
                f"{datetime.now(timezone.utc).isoformat()} {url}\n{set_cookie}\n\n",
            )

        # ── JSON レスポンス ──
        if res_body:
            try:
                parsed = json.loads(res_body)
                _write(
                    out / "json" / f"res_{seq}_{endpoint}_{now}.json",
                    _safe_json(parsed),
                )
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # ── JSONL ログ ──
        log_entry = {
            "seq": seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "url": url,
            "method": flow.request.method,
            "platform": platform,
            "endpoint": endpoint,
            "statusCode": flow.response.status_code if flow.response else None,
            "requestBodySize": len(req_body) if req_body else 0,
            "responseBodySize": len(res_body) if res_body else 0,
        }
        _append(out / "capture_log.jsonl", json.dumps(log_entry) + "\n")


def load(loader):
    """addon ロード時にログフィルタを登録する."""
    noise_filter = _NoiseFilter()
    for name in ("mitmproxy.proxy", "mitmproxy.proxy.layers", "mitmproxy.proxy.layers.tls"):
        logging.getLogger(name).addFilter(noise_filter)
    logging.getLogger().addFilter(noise_filter)


addons = [NetflixCapture()]
