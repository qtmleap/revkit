"""Netflix MSL CBOR Decoder

iOS Netflix は MSL プロトコルに CBOR (RFC 7049) エンコーディングを使用する。
CBOR メッセージは数値キーを使い、値自体もネストされた CBOR バイト列を含む。
このモジュールは raw バイナリを受け取り、人間が読める Python dict に変換する。

使い方::

    from msl_decoder import decode_msl_message

    with open("req_appboot.bin", "rb") as f:
        result = decode_msl_message(f.read())

    import json
    print(json.dumps(result, indent=2, ensure_ascii=False))
"""

from __future__ import annotations

import gzip
import io
import json
from typing import Any

import cbor2

# ════════════════════════════════════════════════════════════════
# Numeric key → human-readable name mappings
#
# These come from analysis of captured iOS Netflix MSL traffic.
# CBOR uses compact integer keys instead of JSON string keys.
# ════════════════════════════════════════════════════════════════

# Top-level MSL message keys
MSL_TOP_KEYS: dict[int, str] = {
    16: "signature",
    32: "header",
    33: "payload",
    34: "entityauthdata",
}

# Header fields (inside key 32)
MSL_HEADER_KEYS: dict[int, str] = {
    10: "mastertoken",
    11: "sender_numeric",
    12: "messageid",
    13: "timestamp",
    14: "sequence_number",
    15: "capabilities",
    16: "renewable",
    94: "handshake_options",
    95: "handshake",
}

# Capabilities sub-fields (inside header → 15)
MSL_CAPABILITIES_KEYS: dict[int, str] = {
    10: "mastertoken",
    11: "sender_numeric",
    12: "messageid",
    13: "timestamp",
    14: "sequence_number",
    94: "handshake_options",
    95: "handshake",
}

# Payload / key exchange fields (inside key 33)
MSL_PAYLOAD_KEYS: dict[int, str] = {
    6: "ciphertext_or_scheme",
    7: "iv_or_keydata",
    8: "keyid",
    9: "sha256_or_hmac",
}

# Entity auth data (inside key 34)
MSL_ENTITY_AUTH_KEYS: dict[int, str] = {
    30: "scheme",
    35: "authdata",
}

# Entity auth → authdata sub-fields
MSL_AUTHDATA_KEYS: dict[int, str] = {
    50: "device_key_data",
    80: "esn_prefix",
    81: "esn",
}

# String keys that already appear with names (not remapped)
_STRING_KEY_PASSTHROUGH = {
    "apphmac",
    "appid",
    "appkeyversion",
    "devicetoken",
}


# ════════════════════════════════════════════════════════════════
# CBOR-aware recursive decoder
# ════════════════════════════════════════════════════════════════


def _try_cbor_decode(raw: bytes) -> Any | None:
    """Try to decode bytes as CBOR. Returns None on failure."""
    try:
        return cbor2.loads(raw)
    except Exception:
        return None


def _try_utf8(raw: bytes) -> str | None:
    """Try to decode bytes as UTF-8 text."""
    try:
        return raw.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


def _bytes_to_value(raw: bytes, max_hex_len: int = 512) -> Any:
    """Convert bytes to best human-readable representation.

    Priority:
    1. Nested CBOR → recursively decode
    2. Valid UTF-8 string
    3. Hex string (if short enough)
    4. Truncated hex summary
    """
    # 1. Try nested CBOR
    inner = _try_cbor_decode(raw)
    if inner is not None and not isinstance(inner, (int, float, bool)):
        # Avoid interpreting short byte sequences as bare CBOR integers
        return _decode_value(inner)

    # 2. Try UTF-8
    text = _try_utf8(raw)
    if text is not None:
        return text

    # 3. Hex encode
    if len(raw) <= max_hex_len:
        return raw.hex()
    return f"<bytes:{len(raw)}>{raw[:64].hex()}..."


def _decode_value(obj: Any) -> Any:
    """Recursively decode a CBOR-decoded Python value into JSON-safe form."""
    if isinstance(obj, bytes):
        return _bytes_to_value(obj)

    if isinstance(obj, dict):
        result: dict[str, Any] = {}
        for k, v in obj.items():
            key_str = str(k)
            result[key_str] = _decode_value(v)
        return result

    if isinstance(obj, list):
        return [_decode_value(item) for item in obj]

    if isinstance(obj, cbor2.CBORTag):
        return {"__cbor_tag__": obj.tag, "value": _decode_value(obj.value)}

    # Handle cbor2 break marker
    type_name = type(obj).__name__
    if "break_marker" in type_name:
        return "__CBOR_BREAK__"

    # int, float, bool, str, None are already JSON-safe
    return obj


def _remap_keys(obj: Any, key_map: dict[int, str] | None = None) -> Any:
    """Apply human-readable key names to a decoded dict."""
    if not isinstance(obj, dict) or not key_map:
        return obj

    result: dict[str, Any] = {}
    for k, v in obj.items():
        try:
            int_key = int(k)
            name = key_map.get(int_key, k)
        except (ValueError, TypeError):
            name = k
        result[name] = v
    return result


# ════════════════════════════════════════════════════════════════
# High-level MSL message mapping
# ════════════════════════════════════════════════════════════════


def _map_authdata(authdata: Any) -> Any:
    """Apply known field name mappings to entity auth data."""
    if not isinstance(authdata, dict):
        return authdata

    result: dict[str, Any] = {}
    for k, v in authdata.items():
        try:
            int_key = int(k)
            name = MSL_AUTHDATA_KEYS.get(int_key, k)
        except (ValueError, TypeError):
            name = k
        result[name] = v
    return result


def _map_entity_auth(entity_auth: Any) -> Any:
    """Map entity auth fields (key 34)."""
    if not isinstance(entity_auth, dict):
        return entity_auth

    mapped = _remap_keys(entity_auth, MSL_ENTITY_AUTH_KEYS)

    if "authdata" in mapped and isinstance(mapped["authdata"], dict):
        mapped["authdata"] = _map_authdata(mapped["authdata"])

    return mapped


def _map_header(header: Any) -> Any:
    """Map header fields (key 32)."""
    if not isinstance(header, dict):
        return header
    return _remap_keys(header, MSL_HEADER_KEYS)


def _map_payload(payload: Any) -> Any:
    """Map payload / key exchange fields (key 33)."""
    if not isinstance(payload, dict):
        return payload
    return _remap_keys(payload, MSL_PAYLOAD_KEYS)


def _apply_msl_field_names(decoded: dict[str, Any]) -> dict[str, Any]:
    """Apply all known MSL field name mappings to a decoded message."""
    result: dict[str, Any] = {}

    for k, v in decoded.items():
        try:
            int_key = int(k)
            name = MSL_TOP_KEYS.get(int_key, k)
        except (ValueError, TypeError):
            name = k

        if name == "header":
            v = _map_header(v)
        elif name == "payload":
            v = _map_payload(v)
        elif name == "entityauthdata":
            v = _map_entity_auth(v)

        result[name] = v

    return result


# ════════════════════════════════════════════════════════════════
# Format detection
# ════════════════════════════════════════════════════════════════


def _is_gzip(data: bytes) -> bool:
    """Check for gzip magic bytes."""
    return len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B


def _is_cbor(data: bytes) -> bool:
    """Heuristic: CBOR self-describe tag (0xD9D9F7) or common CBOR map prefix."""
    if len(data) < 2:
        return False
    # Self-describe tag
    if data[:3] == b"\xd9\xd9\xf7":
        return True
    # Major type 5 (map) with various lengths
    first = data[0]
    major = first >> 5
    return major == 5  # map


def _is_json(data: bytes) -> bool:
    """Check if data looks like JSON."""
    stripped = data.lstrip()
    return len(stripped) > 0 and stripped[0:1] in (b"{", b"[")


# ════════════════════════════════════════════════════════════════
# Streaming CBOR decoder (for responses with multiple items)
# ════════════════════════════════════════════════════════════════


def _decode_cbor_stream(data: bytes) -> list[Any]:
    """Decode potentially concatenated CBOR items from a byte stream."""
    buf = io.BytesIO(data)
    items: list[Any] = []
    decoder = cbor2.CBORDecoder(buf)
    while buf.tell() < len(data):
        try:
            item = decoder.decode()
            items.append(item)
        except Exception:
            break
    return items


# ════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════


def decode_msl_message(
    raw: bytes,
    *,
    apply_names: bool = True,
) -> dict[str, Any]:
    """Decode a Netflix MSL message from raw bytes.

    Handles:
    - Gzip-compressed data (responses are often gzipped)
    - CBOR-encoded messages (iOS)
    - JSON-encoded messages (Chrome / Android)
    - URL-encoded form data (iosui endpoints)
    - Nested CBOR within byte string values
    - Encrypted payloads (returned as hex strings)

    Args:
        raw: Raw bytes from the captured request/response body.
        apply_names: If True, map numeric CBOR keys to human-readable names.

    Returns:
        A dict with keys:
        - ``format``: ``"cbor"``, ``"json"``, or ``"unknown"``
        - ``compressed``: bool, whether gzip was detected
        - ``messages``: list of decoded message dicts
    """
    if not raw:
        return {"format": "unknown", "compressed": False, "messages": []}

    compressed = _is_gzip(raw)
    data = raw

    if compressed:
        try:
            data = gzip.decompress(raw)
        except Exception:
            return {
                "format": "unknown",
                "compressed": True,
                "messages": [],
                "error": "gzip decompression failed",
            }

    # ── Try CBOR ──
    if _is_cbor(data):
        items = _decode_cbor_stream(data)
        if items:
            messages = []
            for item in items:
                decoded = _decode_value(item)
                if apply_names and isinstance(decoded, dict):
                    decoded = _apply_msl_field_names(decoded)
                messages.append(decoded)
            return {
                "format": "cbor",
                "compressed": compressed,
                "messages": messages,
            }

    # ── Try JSON (Chrome / Android MSL) ──
    if _is_json(data):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        # MSL JSON can be newline-delimited (header + payload chunks)
        messages = []
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    messages.append(obj)
            except json.JSONDecodeError:
                continue

        if not messages:
            # Try as single JSON object
            try:
                single = json.loads(text)
                if isinstance(single, dict):
                    messages = [single]
                elif isinstance(single, list):
                    messages = [{"__array__": single}]
            except json.JSONDecodeError:
                pass

        if messages:
            return {
                "format": "json",
                "compressed": compressed,
                "messages": messages,
            }

    # ── Fallback: try CBOR anyway (no self-describe tag) ──
    try:
        items = _decode_cbor_stream(data)
        if items:
            messages = []
            for item in items:
                decoded = _decode_value(item)
                if apply_names and isinstance(decoded, dict):
                    decoded = _apply_msl_field_names(decoded)
                messages.append(decoded)
            return {
                "format": "cbor",
                "compressed": compressed,
                "messages": messages,
            }
    except Exception:
        pass

    # ── Unknown format ──
    return {
        "format": "unknown",
        "compressed": compressed,
        "messages": [],
        "raw_preview": data[:256].hex(),
    }


def decode_msl_file(path: str, *, apply_names: bool = True) -> dict[str, Any]:
    """Convenience: decode from a file path."""
    with open(path, "rb") as f:
        return decode_msl_message(f.read(), apply_names=apply_names)


def decode_to_json(raw: bytes, *, apply_names: bool = True, indent: int = 2) -> str:
    """Decode and return a JSON string."""
    result = decode_msl_message(raw, apply_names=apply_names)
    return json.dumps(result, indent=indent, ensure_ascii=False, default=str)


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════


def main() -> None:
    """Command-line entry point for decoding MSL binary files."""
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.bin> [file2.bin ...]", file=sys.stderr)
        sys.exit(1)

    for path in sys.argv[1:]:
        if len(sys.argv) > 2:
            print(f"=== {path} ===")
        result = decode_msl_file(path)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        if len(sys.argv) > 2:
            print()


if __name__ == "__main__":
    main()
