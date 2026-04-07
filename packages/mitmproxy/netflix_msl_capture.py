"""
Netflix MSL Capture — mitmproxy addon

Proxyman スクリプト (netflix-msl-capture.js + NetflixMSLParser.js) の
mitmproxy 移植版。通信を一切改変せずに MSL メッセージをデコードし、
マニフェスト・ALE 鍵・ESN・KID テーブルを抽出・保存する。

使い方:
    mitmdump --listen-port 9080 --set block_global=false \
        -s packages/mitmproxy/netflix_msl_capture.py

保存先: raws/<platform>/<date>/
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from mitmproxy import ctx, http

logger = logging.getLogger(__name__)

# ── 設定 ──
BASE_DIR = Path(__file__).resolve().parent.parent.parent / "raws"


# ════════════════════════════════════════════════════════════════
# Base64 helpers
# ════════════════════════════════════════════════════════════════


def b64_decode(s: str) -> bytes | None:
    try:
        return base64.b64decode(s)
    except Exception:
        return None


def b64url_decode(s: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════
# LZW Decoder (Netflix MSL variant)
# ════════════════════════════════════════════════════════════════


def decode_lzw(data_b64: str) -> str | None:
    raw = b64_decode(data_b64)
    if not raw:
        return None
    try:
        data = list(raw)
        if not data:
            return None

        bit_pos = 0
        total_bits = len(data) * 8

        def read_bits(n: int) -> int:
            nonlocal bit_pos
            if bit_pos + n > total_bits:
                return -1
            val = 0
            for i in range(n):
                byte_idx = (bit_pos + i) >> 3
                bit_idx = 7 - ((bit_pos + i) & 7)
                if data[byte_idx] & (1 << bit_idx):
                    val |= 1 << (n - 1 - i)
            bit_pos += n
            return val

        dictionary: list[list[int]] = [list([i]) for i in range(256)]
        bits = 8
        output: list[int] = []

        code = read_bits(bits)
        if code == -1 or code >= len(dictionary):
            return None
        prev = dictionary[code]
        output.extend(prev)

        while True:
            if len(dictionary) == 1 << bits:
                bits += 1
            code = read_bits(bits)
            if code == -1:
                break
            if code < len(dictionary):
                entry = dictionary[code]
            elif code == len(dictionary):
                entry = prev + [prev[0]]
            else:
                break
            output.extend(entry)
            dictionary.append(prev + [entry[0]])
            prev = entry

        return bytes(output).decode("utf-8", errors="replace")
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════
# JSON helpers
# ════════════════════════════════════════════════════════════════


def try_parse_json(text: str | bytes | None) -> Any:
    if not text:
        return None
    try:
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="replace")
        return json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def safe_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


# ════════════════════════════════════════════════════════════════
# AES-CBC Decryption
# ════════════════════════════════════════════════════════════════


def decrypt_aes_cbc(data_b64: str, key_hex: str) -> str | None:
    """MSL format: base64(IV[16] || ciphertext)"""
    if not data_b64 or not key_hex:
        return None
    try:
        raw = base64.b64decode(data_b64)
        if len(raw) < 17:
            return None
        iv = raw[:16]
        ciphertext = raw[16:]
        key = bytes.fromhex(key_hex)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode("utf-8", errors="replace")
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════
# MSL Envelope Decoder
# ════════════════════════════════════════════════════════════════


class MSLDecoder:
    def __init__(self) -> None:
        self.encryption_key: str | None = None
        self.hmac_key: str | None = None

    def set_keys(self, enc_key: str, hmac_key: str) -> None:
        self.encryption_key = enc_key
        self.hmac_key = hmac_key

    def decode_chunk_data(self, data_str: str, compress: str | None = None) -> Any:
        if not data_str:
            return None

        # 1. LZW
        if compress == "LZW":
            decompressed = decode_lzw(data_str)
            if decompressed:
                return try_parse_json(decompressed) or decompressed

        # 2. Base64
        inner = b64_decode(data_str)
        if inner:
            parsed = try_parse_json(inner)
            if parsed:
                return parsed
            try:
                text = inner.decode("utf-8", errors="replace")
                if text and ord(text[0]) >= 0x20:
                    return text
            except Exception:
                pass

        # 3. AES-CBC (if ALE keys available)
        if self.encryption_key:
            decrypted = decrypt_aes_cbc(data_str, self.encryption_key)
            if decrypted:
                if compress == "LZW":
                    decompressed = decode_lzw(decrypted)
                    if decompressed:
                        return try_parse_json(decompressed) or decompressed
                return try_parse_json(decrypted) or decrypted

        return None

    def deep_decode(self, obj: dict) -> dict:
        if not obj or not isinstance(obj, dict):
            return obj

        decoded = dict(obj)
        compress = decoded.get("compressionalgo")

        # headerdata
        if isinstance(decoded.get("headerdata"), str):
            hdr_bytes = b64_decode(decoded["headerdata"])
            hdr = try_parse_json(hdr_bytes)
            if hdr and isinstance(hdr, dict):
                decoded["_headerdata_decoded"] = hdr

        # payload (single)
        if isinstance(decoded.get("payload"), str):
            chunk_bytes = b64_decode(decoded["payload"])
            chunk = try_parse_json(chunk_bytes)
            if chunk:
                decoded["_payload_decoded"] = chunk
                if chunk.get("data"):
                    algo = chunk.get("compressionalgo") or compress
                    decoded["_payload_data"] = self.decode_chunk_data(
                        chunk["data"], algo
                    )

        # data field (payload chunk format)
        if isinstance(decoded.get("data"), str) and "messageid" in decoded:
            decoded["_data_decoded"] = self.decode_chunk_data(decoded["data"], compress)

        # payloads array
        if isinstance(decoded.get("payloads"), list):
            payloads_decoded = []
            for p in decoded["payloads"]:
                if isinstance(p, str):
                    chunk_bytes = b64_decode(p)
                    chunk = try_parse_json(chunk_bytes)
                    if chunk and chunk.get("data"):
                        algo = chunk.get("compressionalgo") or compress
                        inner = self.decode_chunk_data(chunk["data"], algo)
                        payloads_decoded.append({"_chunk": chunk, "_data": inner})
                    else:
                        payloads_decoded.append(chunk or p)
                else:
                    payloads_decoded.append(p)
            decoded["_payloads_decoded"] = payloads_decoded

        # servicetokens
        if isinstance(decoded.get("servicetokens"), list):
            tokens_decoded = []
            for st in decoded["servicetokens"]:
                if isinstance(st, dict) and isinstance(st.get("tokendata"), str):
                    td_bytes = b64_decode(st["tokendata"])
                    td = try_parse_json(td_bytes)
                    if td:
                        result = dict(td)
                        if td.get("servicedata"):
                            sd_bytes = b64_decode(td["servicedata"])
                            result["_servicedata_decoded"] = (
                                try_parse_json(sd_bytes) if sd_bytes else None
                            )
                        tokens_decoded.append(result)
                    else:
                        tokens_decoded.append(st)
                else:
                    tokens_decoded.append(st)
            decoded["_servicetokens_decoded"] = tokens_decoded

        # useridtoken
        uit = decoded.get("useridtoken")
        if isinstance(uit, dict) and isinstance(uit.get("tokendata"), str):
            uit_bytes = b64_decode(uit["tokendata"])
            decoded["_useridtoken_decoded"] = try_parse_json(uit_bytes)

        return decoded


# ════════════════════════════════════════════════════════════════
# MSL Body Parser
# ════════════════════════════════════════════════════════════════


def parse_msl_body(body: bytes | str) -> list[dict]:
    if not body:
        return []
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except Exception:
            return []

    single = try_parse_json(body)
    if single:
        return [single] if isinstance(single, dict) else []

    messages = []
    for line in body.split("\n"):
        line = line.strip()
        if not line:
            continue
        parsed = try_parse_json(line)
        if parsed and isinstance(parsed, dict):
            messages.append(parsed)
    return messages


# ════════════════════════════════════════════════════════════════
# Extractors
# ════════════════════════════════════════════════════════════════


def extract_decoded_payload(expanded: dict) -> Any:
    return (
        expanded.get("_data_decoded")
        or expanded.get("_payload_data")
        or expanded.get("_payload_decoded")
    )


def format_drm_header_id(hex_str: str) -> str | None:
    if not hex_str or len(hex_str) != 32:
        return hex_str or None
    return (
        f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}"
        f"-{hex_str[16:20]}-{hex_str[20:]}"
    )


def extract_manifest(payload: dict) -> dict | None:
    if not payload or not isinstance(payload, dict):
        return None
    raw = payload.get("result", payload)
    if not raw or (not raw.get("video_tracks") and not raw.get("audio_tracks")):
        return None

    manifest: dict[str, Any] = {
        "movieId": str(raw["movieId"]) if raw.get("movieId") is not None else None,
        "duration": raw.get("duration"),
        "servers": raw.get("servers", []),
        "videoTracks": [],
        "audioTracks": [],
        "textTracks": [],
    }

    for vt in raw.get("video_tracks", []):
        track = {
            "trackType": vt.get("trackType"),
            "track_id": vt.get("track_id"),
            "maxWidth": vt.get("maxWidth"),
            "maxHeight": vt.get("maxHeight"),
            "drmHeader": (
                {
                    "bytes": vt["drmHeader"].get("bytes"),
                    "keyId": vt["drmHeader"].get("keyId"),
                }
                if vt.get("drmHeader")
                else None
            ),
            "streams": [
                {
                    "res_w": s.get("res_w"),
                    "res_h": s.get("res_h"),
                    "bitrate": s.get("bitrate"),
                    "size": s.get("size"),
                    "vmaf": s.get("vmaf"),
                    "content_profile": s.get("content_profile"),
                    "downloadable_id": s.get("downloadable_id"),
                    "kid": format_drm_header_id(s.get("drmHeaderId", "")),
                    "urls": s.get("urls", []),
                }
                for s in vt.get("streams", [])
            ],
        }
        manifest["videoTracks"].append(track)

    for at in raw.get("audio_tracks", []):
        track = {
            "language": at.get("language"),
            "languageDescription": at.get("languageDescription"),
            "channels": at.get("channels"),
            "trackType": at.get("trackType"),
            "track_id": at.get("track_id"),
            "streams": [
                {
                    "bitrate": s.get("bitrate"),
                    "size": s.get("size"),
                    "content_profile": s.get("content_profile"),
                    "downloadable_id": s.get("downloadable_id"),
                    "urls": s.get("urls", []),
                }
                for s in at.get("streams", [])
            ],
        }
        manifest["audioTracks"].append(track)

    for tt in raw.get("timedtexttracks", []):
        if tt.get("isNoneTrack"):
            continue
        manifest["textTracks"].append(
            {
                "language": tt.get("language"),
                "languageDescription": tt.get("languageDescription"),
                "trackType": tt.get("trackType"),
                "downloadableId": tt.get("downloadableId"),
                "urls": tt.get("ttDownloadables"),
            }
        )

    return manifest


def extract_ale_keys(payload: dict) -> dict | None:
    if not payload or not isinstance(payload, dict):
        return None
    prov = payload.get("provisionResponse")
    if not prov:
        return None

    token_obj = try_parse_json(prov) if isinstance(prov, str) else prov
    if not token_obj or not isinstance(token_obj, dict):
        return None
    keyx = token_obj.get("keyx")
    if not keyx or not keyx.get("data", {}).get("key"):
        return None

    key_bytes = b64url_decode(keyx["data"]["key"])
    if not key_bytes or len(key_bytes) < 32:
        return None

    hmac_hex = key_bytes[:16].hex()
    aes_hex = key_bytes[16:32].hex()

    # JWE header
    jwe_token = token_obj.get("token", "")
    jwe_alg = "?"
    jwe_enc = "?"
    if jwe_token:
        parts = jwe_token.split(".")
        if len(parts) == 5:
            hdr_bytes = b64url_decode(parts[0])
            hdr = try_parse_json(hdr_bytes)
            if hdr:
                jwe_alg = hdr.get("alg", "?")
                jwe_enc = hdr.get("enc", "?")

    return {
        "encryptionKey": aes_hex,
        "hmacKey": hmac_hex,
        "kid": keyx.get("kid", ""),
        "jweToken": jwe_token,
        "scheme": keyx.get("scheme", ""),
        "rawKeyHex": key_bytes.hex(),
        "jweAlg": jwe_alg,
        "jweEnc": jwe_enc,
        "capturedAt": datetime.now(timezone.utc).isoformat(),
    }


def extract_esn_from_headers(headers: dict) -> dict | None:
    esn = None
    for key in ("x-netflix.esn", "X-Netflix.esn", "X-Netflix.Esn", "X-NETFLIX.ESN"):
        if key in headers:
            esn = headers[key]
            break
    if not esn:
        return None
    parts = esn.split("|")
    return {
        "esn": esn,
        "prv": parts[0] if parts else None,
        "pxa": parts[1] if len(parts) >= 2 else None,
    }


def extract_esn_from_sender(sender: str) -> dict | None:
    if not sender:
        return None
    return {"esn": sender, "prv": sender, "pxa": None}


def build_kid_table(manifest: dict) -> list[dict]:
    rows = []
    for vt in manifest.get("videoTracks", []):
        sorted_streams = sorted(
            vt.get("streams", []), key=lambda s: s.get("bitrate", 0)
        )
        prev_kid = None
        for s in sorted_streams:
            kid = s.get("kid")
            boundary = prev_kid is not None and kid != prev_kid
            rows.append(
                {
                    "res_w": s.get("res_w"),
                    "res_h": s.get("res_h"),
                    "bitrate": s.get("bitrate"),
                    "kid": kid,
                    "kid_short": (kid[:8] + "..." if kid else "-"),
                    "content_profile": s.get("content_profile"),
                    "boundary": boundary,
                }
            )
            prev_kid = kid
    return rows


# ════════════════════════════════════════════════════════════════
# File I/O
# ════════════════════════════════════════════════════════════════


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S-%f")[:-3] + "Z"


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


def _detect_platform(flow: http.HTTPFlow) -> str:
    ua = flow.request.headers.get("User-Agent", "")
    url = flow.request.pretty_url
    if "Darwin/" in ua or "CFNetwork/" in ua:
        return "ios"
    if "ios.prod." in url or "/iosui/" in url or "/iosplatform/" in url:
        return "ios"
    if "okhttp/" in ua or "Cronet/" in ua:
        return "android"
    if "android" in ua.lower():
        return "android"
    if "Chrome/" in ua or "Mozilla/" in ua:
        return "chrome"
    return "unknown"


def _classify(url: str) -> str:
    patterns = [
        ("pbo_manifests", "manifest_msl"),
        ("pbo_license", "license"),
        ("pbo_tokens", "ale_provision"),
        ("licensedmanifest", "licensedmanifest"),
        ("playapi/ios/manifest", "ios_manifest"),
        ("/events", "events"),
        ("getProxyEsn", "getProxyEsn"),
        ("pathEvaluator", "pathEvaluator"),
        ("graphql", "graphql"),
        ("/config", "config"),
        ("/msl_v1/", "msl"),
        ("/msl/", "msl"),
    ]
    for pattern, name in patterns:
        if pattern in url:
            return name
    return "other"


def _output_dir(platform: str) -> Path:
    return BASE_DIR / platform / datetime.now(timezone.utc).strftime("%Y%m%d")


# ════════════════════════════════════════════════════════════════
# mitmproxy addon
# ════════════════════════════════════════════════════════════════


class NetflixMSLCapture:
    def __init__(self) -> None:
        self.seq = 0
        self.decoder = MSLDecoder()
        self.captured_esn: str | None = None

    def response(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        if "netflix.com" not in url and "netflix.net" not in url:
            return

        self.seq += 1
        seq = self.seq
        now = _ts()
        ts = datetime.now(timezone.utc).isoformat()
        platform = _detect_platform(flow)
        endpoint = _classify(url)
        out = _output_dir(platform)

        req_body = flow.request.raw_content
        res_body = flow.response.raw_content if flow.response else b""

        # ── ESN from headers ──
        esn_info = extract_esn_from_headers(dict(flow.request.headers))
        if not esn_info and flow.response:
            esn_info = extract_esn_from_headers(dict(flow.response.headers))
        if esn_info:
            self.captured_esn = esn_info["esn"]

        # ── Raw bodies ──
        if req_body:
            _write(out / "raw" / f"req_{seq}_{endpoint}_{now}.bin", req_body)
        if res_body:
            _write(out / "raw" / f"res_{seq}_{endpoint}_{now}.bin", res_body)

        # ── Headers ──
        _write(
            out / "headers" / f"{seq}_{endpoint}_{now}.json",
            safe_json(
                {
                    "seq": seq,
                    "ts": ts,
                    "url": url,
                    "method": flow.request.method,
                    "platform": platform,
                    "endpoint": endpoint,
                    "statusCode": flow.response.status_code if flow.response else None,
                    "requestHeaders": dict(flow.request.headers),
                    "responseHeaders": dict(flow.response.headers)
                    if flow.response
                    else {},
                }
            ),
        )

        # ── Cookies ──
        cookie_header = flow.request.headers.get("Cookie", "")
        if cookie_header:
            lines = []
            for c in cookie_header.split(";"):
                c = c.strip()
                if "=" in c:
                    name, val = c.split("=", 1)
                    lines.append(f".netflix.com\tTRUE\t/\tTRUE\t0\t{name}\t{val}")
            _write(out / "cookies" / "cookies.txt", "\n".join(lines) + "\n")

        set_cookie = (
            flow.response.headers.get("Set-Cookie", "") if flow.response else ""
        )
        if set_cookie:
            _append(out / "cookies" / "set_cookies.log", f"{ts} {set_cookie}\n")

        # ── MSL Request decode ──
        if req_body:
            req_messages = parse_msl_body(req_body)
            if req_messages:
                all_decoded = []
                for msg in req_messages:
                    expanded = self.decoder.deep_decode(msg)
                    all_decoded.append(expanded)
                    if msg.get("sender"):
                        esn = extract_esn_from_sender(msg["sender"])
                        if esn:
                            self.captured_esn = esn["esn"]

                _write(
                    out / "msl" / f"req_{seq}_{endpoint}_{now}.json",
                    safe_json(
                        {
                            "seq": seq,
                            "direction": "request",
                            "endpoint": endpoint,
                            "ts": ts,
                            "url": url,
                            "messages": all_decoded,
                        }
                    ),
                )

        # ── MSL Response decode ──
        found_manifest = None
        found_ale_keys = None

        if res_body:
            res_messages = parse_msl_body(res_body)
            if res_messages:
                all_decoded = []
                for msg in res_messages:
                    expanded = self.decoder.deep_decode(msg)
                    all_decoded.append(expanded)
                    decoded_payload = extract_decoded_payload(expanded)

                    if msg.get("sender"):
                        esn = extract_esn_from_sender(msg["sender"])
                        if esn:
                            self.captured_esn = esn["esn"]

                    if decoded_payload and isinstance(decoded_payload, dict):
                        # Manifest
                        manifest = extract_manifest(decoded_payload)
                        if manifest:
                            found_manifest = manifest

                        # ALE keys
                        ale = extract_ale_keys(
                            decoded_payload.get("result", decoded_payload)
                        )
                        if ale:
                            found_ale_keys = ale
                            self.decoder.set_keys(ale["encryptionKey"], ale["hmacKey"])

                _write(
                    out / "msl" / f"res_{seq}_{endpoint}_{now}.json",
                    safe_json(
                        {
                            "seq": seq,
                            "direction": "response",
                            "ts": ts,
                            "url": url,
                            "statusCode": (
                                flow.response.status_code if flow.response else None
                            ),
                            "messages": all_decoded,
                        }
                    ),
                )

        # ── Manifest save ──
        if found_manifest:
            movie_id = found_manifest.get("movieId", "unknown")
            _write(
                out / "manifests" / f"manifest_{movie_id}_{now}.json",
                safe_json(found_manifest),
            )

            kid_table = build_kid_table(found_manifest)
            if kid_table:
                _write(
                    out / "manifests" / f"kid_table_{movie_id}_{now}.json",
                    safe_json(kid_table),
                )

                lines = [f"# KID Table — movieId: {movie_id}\n"]
                lines.append("| Resolution | Bitrate | KID | Profile |")
                lines.append("|------------|---------|-----|---------|")
                for row in kid_table:
                    if row.get("boundary"):
                        lines.append("|---|---|---|---|")
                    br = row.get("bitrate", 0)
                    br_kbps = f"{br // 1000}" if br and br > 10000 else str(br)
                    lines.append(
                        f"| {row['res_w']}x{row['res_h']}"
                        f" | {br_kbps} kbps"
                        f" | {row['kid_short']}"
                        f" | {row['content_profile']} |"
                    )
                _write(
                    out / "manifests" / f"kid_table_{movie_id}.md",
                    "\n".join(lines) + "\n",
                )

            video_count = sum(
                len(vt.get("streams", []))
                for vt in found_manifest.get("videoTracks", [])
            )
            audio_count = sum(
                len(at.get("streams", []))
                for at in found_manifest.get("audioTracks", [])
            )
            logger.info(
                "[MSL] Manifest: movieId=%s video=%d audio=%d",
                movie_id,
                video_count,
                audio_count,
            )

        # ── ALE keys save ──
        if found_ale_keys:
            _append(
                out / "keys" / "ale_keys.jsonl",
                json.dumps(found_ale_keys) + "\n",
            )
            kid = found_ale_keys.get("kid", str(seq))
            _write(
                out / "keys" / f"ale_{kid}_{now}.json",
                safe_json(found_ale_keys),
            )
            logger.info(
                "[MSL] ALE Keys: scheme=%s kid=%s\n"
                "  HMAC-SHA256: %s\n"
                "  AES-CBC:     %s",
                found_ale_keys["scheme"],
                found_ale_keys["kid"],
                found_ale_keys["hmacKey"],
                found_ale_keys["encryptionKey"],
            )

        # ── ESN save ──
        if self.captured_esn:
            _write(out / "esn.txt", self.captured_esn + "\n")

        # ── JSONL log ──
        log_entry: dict[str, Any] = {
            "seq": seq,
            "ts": ts,
            "url": url,
            "platform": platform,
            "endpoint": endpoint,
            "statusCode": flow.response.status_code if flow.response else None,
            "esn": self.captured_esn,
        }
        if found_manifest:
            log_entry["manifestDetected"] = True
            log_entry["movieId"] = found_manifest.get("movieId")
        if found_ale_keys:
            log_entry["aleKeysDetected"] = True
            log_entry["aleScheme"] = found_ale_keys.get("scheme")

        _append(out / "capture_log.jsonl", json.dumps(log_entry) + "\n")


addons = [NetflixMSLCapture()]
