#!/usr/bin/env python3
"""test_msl_manifest.py — iOS MSL appboot replay to manifest request

End-to-end flow:
  Step 1: Replay saved appboot request  -> get CBOR response + session keys
  Step 2: Derive session keys via DH shared secret + Phase 2/3 KDF
  Step 3: Build encrypted MSL manifest request (CBOR)
  Step 4: POST to iOS manifest endpoint, decode response

Usage:
    uv run python tools/test_msl_manifest.py
    uv run python tools/test_msl_manifest.py --viewable-id 81215567
    uv run python tools/test_msl_manifest.py --no-proxy
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import struct
import sys
import time
from pathlib import Path

import cbor2
import requests

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from netflix_msl.cbor_encoder import nf_cbor_encode  # noqa: E402
from netflix_msl.constants import IOS_APPBOOT_ENDPOINT  # noqa: E402
from netflix_msl.crypto import NetflixCrypto  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ESN = "NFAPPL-02-IPHONE9=1-AD0455EF27D3A7B8F0872932FD9837874AF3E6F90157195BD22A8063FEB0B79E"

# Phase 0 MGK keys (from verify_full_key_chain.py test vectors, confirmed against live capture)
MGK_ENC_KEY_0 = bytes.fromhex("0817065e29e6d1c8668473af9e13b3c2")
MGK_SIGN_KEY_0 = bytes.fromhex(
    "91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1"
)

# Paths
RAWS_DIR = _PROJECT_ROOT / "raws" / "ios" / "20260408" / "raw"
MSL_KEYS_FILE = _PROJECT_ROOT / "raws" / "msl_keys.json"
APPBOOT_REQ_FILE = RAWS_DIR / "req_709_appboot_2026-04-08T10-01-27-066Z.bin"
APPBOOT_RESP_FILE = RAWS_DIR / "res_709_appboot_2026-04-08T10-01-27-066Z.bin"

# Endpoints
APPBOOT_URL = IOS_APPBOOT_ENDPOINT + "NFAPPL-02-IPHONE9=1-"
MANIFEST_URL = "https://ios.prod.ftl.netflix.com/msl/playapi/ios/manifest"

# CBOR numeric key constants (matching cbor_decoder.py)
KEY_HEADER = 32
KEY_KEY_EXCHANGE = 33
KEY_ENTITY_AUTH = 34
KEY_PAYLOAD_CHUNK = 64
KEY_MESSAGE_SIG = 16

PAYLOAD_CIPHERTEXT = 6
PAYLOAD_IV = 7
PAYLOAD_KEYID = 8
PAYLOAD_HMAC = 9

# appboot response key_response_data sub-keys
KRD_NON_REPLAYABLE = 19
KRD_RENEWABLE = 21
KRD_MESSAGE_ID = 22
KRD_KEY_EXCHANGE_DATA = 23
KRD_TIMESTAMP = 24
KRD_CAPABILITIES = 36

# key_exchange_data sub-keys
KED_SCHEME = 30
KED_KEY_DATA = 31
KED_MASTER_TOKEN = 32

# key_data sub-keys (AUTHENTICATED_DH)
KD_IV = 65
KD_SERVER_DH_PUB = 53
KD_KEY_VERSION = 58

# Default proxy (mitmproxy / Proxyman)
DEFAULT_PROXY = "http://192.168.0.51:9080"

# HTTP headers for iOS Netflix
IOS_HEADERS = {
    "User-Agent": "Netflix/24 CFNetwork/1335.0.3.4 Darwin/21.6.0",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Netflix.APIAction": "appboot",
    "X-Netflix.client.ftl.esn": ESN,
    "X-Netflix.Request.Attempt": "1",
    "X-Netflix.Request.Client.Context": '{"appState":"foreground"}',
}

MANIFEST_HEADERS = {
    "User-Agent": "Netflix/24 CFNetwork/1335.0.3.4 Darwin/21.6.0",
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "X-Netflix.client.type": "argo",
    "X-Netflix.Request.Client.Context": '{"appState":"foreground"}',
    "X-Netflix.Request.Attempt": "1",
    "X-Netflix.client.ftl.esn": ESN,
    "content-encoding": "msl_v1",
    "x-allowcompression": "false",
    "x-netflix.argo.nfnsm": "3",
    "x-netflix.argo.translated": "true",
    "x-netflix.client.appversion": "15.48.1",
    "x-netflix.client.iosversion": "15.8.3",
    "x-netflix.client.idiom": "phone",
    "x-netflix.pbobrahv": "6",
    "x-netflix.client.request.name": "prefetch/manifest",
    "x-netflix.request.expiry.timeout": "15000",
}

# ---------------------------------------------------------------------------
# Step 1: appboot replay
# ---------------------------------------------------------------------------


def replay_appboot(
    proxy_url: str | None,
    timeout: int,
) -> tuple[bytes, str]:
    """Replay the saved appboot request to get a fresh CBOR response.

    Returns:
        (response_bytes, device_id_token)
    """
    print("[Step 1] Replaying saved appboot request...")
    print(f"    Request file: {APPBOOT_REQ_FILE.name}")

    req_bytes = APPBOOT_REQ_FILE.read_bytes()
    print(f"    Request size: {len(req_bytes)} bytes")

    session = requests.Session()
    session.headers.update(IOS_HEADERS)

    proxies = {"https": proxy_url, "http": proxy_url} if proxy_url else None

    url = APPBOOT_URL
    params = {"keyVersion": "1"}

    print(f"    POST {url}?keyVersion=1")
    if proxy_url:
        print(f"    Proxy: {proxy_url}")

    resp = session.post(
        url,
        params=params,
        data=req_bytes,
        proxies=proxies,
        verify=False,
        timeout=timeout,
    )

    print(f"    HTTP {resp.status_code} ({len(resp.content)} bytes)")

    if resp.status_code != 200:
        raise RuntimeError(
            f"appboot failed: HTTP {resp.status_code} - {resp.text[:300]}"
        )

    device_id_token = resp.headers.get("x-netflix-deviceidtoken", "")
    if device_id_token:
        print(f"    x-netflix-deviceidtoken: {device_id_token[:50]}...")
    else:
        print("    x-netflix-deviceidtoken: (none)")

    return resp.content, device_id_token


def load_saved_appboot_response() -> tuple[bytes, str]:
    """Load the saved appboot response from disk (offline mode).

    Returns:
        (response_bytes, device_id_token)
    """
    print("[Step 1] Loading saved appboot response (offline)...")
    print(f"    Response file: {APPBOOT_RESP_FILE.name}")

    resp_bytes = APPBOOT_RESP_FILE.read_bytes()
    print(f"    Response size: {len(resp_bytes)} bytes")

    # No device_id_token available in saved response (it was in HTTP headers)
    return resp_bytes, ""


# ---------------------------------------------------------------------------
# Step 1b: Parse appboot response
# ---------------------------------------------------------------------------


def parse_appboot_response(
    raw: bytes,
) -> tuple[bytes, dict]:
    """Parse appboot CBOR response.

    Extracts:
      - server DH public key from key 23.31.53 (128B after stripping leading 0x00)
      - master token dict from key 23.32

    Returns:
        (server_dh_pub_key_128b, master_token_dict)
    """
    print("[Step 1b] Parsing appboot response...")

    top = cbor2.loads(raw)
    print(f"    Top-level keys: {sorted(top.keys())}")

    krd_raw = top.get(KEY_KEY_EXCHANGE)
    if krd_raw is None:
        raise ValueError(f"No key_response_data (key {KEY_KEY_EXCHANGE}) in response")

    krd = cbor2.loads(krd_raw) if isinstance(krd_raw, bytes) else krd_raw
    print(f"    key_response_data keys: {sorted(krd.keys())}")

    # Extract key_exchange_data (key 23)
    ked = krd.get(KRD_KEY_EXCHANGE_DATA)
    if ked is None:
        raise ValueError(f"No key_exchange_data (key {KRD_KEY_EXCHANGE_DATA}) in krd")

    scheme = ked.get(KED_SCHEME, "?")
    print(f"    Key exchange scheme: {scheme}")

    # Extract server DH public key from key 23.31.53
    kd = ked.get(KED_KEY_DATA)
    if kd is None:
        raise ValueError(f"No key_data (key {KED_KEY_DATA}) in key_exchange_data")

    server_dh_pub_raw = kd.get(KD_SERVER_DH_PUB)
    if not isinstance(server_dh_pub_raw, bytes):
        raise ValueError(f"server_dh_pub (key {KD_SERVER_DH_PUB}) not bytes")

    print(
        f"    server_dh_pub raw: {server_dh_pub_raw[:8].hex()}... ({len(server_dh_pub_raw)}B)"
    )

    # Strip leading 0x00 byte (big-endian encoding of 1024-bit key may add a zero)
    if len(server_dh_pub_raw) == 129 and server_dh_pub_raw[0] == 0x00:
        server_dh_pub = server_dh_pub_raw[1:]
        print("    server_dh_pub: stripped leading 0x00 -> 128B")
    elif len(server_dh_pub_raw) == 128:
        server_dh_pub = server_dh_pub_raw
    else:
        raise ValueError(
            f"Unexpected server_dh_pub length: {len(server_dh_pub_raw)} (expected 128 or 129)"
        )

    # Extract master token (key 23.32)
    master_token = ked.get(KED_MASTER_TOKEN)
    if master_token is None:
        raise ValueError(
            f"No master_token (key {KED_MASTER_TOKEN}) in key_exchange_data"
        )

    print(f"    master_token keys: {sorted(master_token.keys())}")
    for k, v in master_token.items():
        if isinstance(v, bytes):
            print(f"      [{k}]: {len(v)}B")

    print(f"    server_dh_pub: {server_dh_pub[:8].hex()}... (128B)")
    return server_dh_pub, master_token


# ---------------------------------------------------------------------------
# Step 2: Compute session keys
# ---------------------------------------------------------------------------


def derive_session_keys(server_dh_pub: bytes) -> tuple[bytes, bytes]:
    """Compute DH shared secret and derive session keys.

    Uses DH private key from raws/msl_keys.json.
    Derives keys via Phase 2/3 KDF (derive_full_key_chain).

    Returns:
        (enc_key_16b, sign_key_32b)
            enc_key:  AES-128 key for payload encryption
            sign_key: HMAC-SHA256 key for message signing (bootstrap_key)
    """
    print("[Step 2] Deriving session keys...")

    keys_data = json.loads(MSL_KEYS_FILE.read_text())
    dh_priv_hex = keys_data["dh_priv_key"]
    dh_priv = bytes.fromhex(dh_priv_hex)
    print(f"    DH private key: {dh_priv[:8].hex()}... ({len(dh_priv)}B)")

    # Compute DH shared secret: pow(server_pub, priv, p)
    dh_shared = NetflixCrypto.compute_dh_shared_secret(
        peer_public=server_dh_pub,
        private_key=dh_priv,
    )
    print(f"    DH shared secret: {dh_shared[:8].hex()}... ({len(dh_shared)}B)")

    # Verify against saved value if available
    saved_shared = keys_data.get("dh_shared_secret", "")
    if saved_shared:
        if dh_shared.hex() == saved_shared:
            print("    DH shared secret: VERIFIED against saved value")
        else:
            print("    WARNING: DH shared secret does not match saved value")
            print(f"      computed: {dh_shared.hex()}")
            print(f"      saved:    {saved_shared}")

    # Derive session keys via Phase 2/3 KDF
    session_keys = NetflixCrypto.derive_full_key_chain(
        enc_key_0=MGK_ENC_KEY_0,
        sign_key_0=MGK_SIGN_KEY_0,
        dh_shared_secret=dh_shared,
    )

    enc_key = session_keys.enc_key
    sign_key = session_keys.bootstrap_key

    print(f"    enc_key (AES):   {enc_key.hex()}")
    print(f"    sign_key (HMAC): {sign_key.hex()}")

    # Verify against saved session keys
    saved_enc = keys_data.get("session_enc_key", "")
    saved_hmac = keys_data.get("session_hmac_key", "")
    if saved_enc and enc_key.hex() == saved_enc:
        print("    enc_key: VERIFIED against saved session_enc_key")
    elif saved_enc:
        print(f"    WARNING: enc_key mismatch (saved: {saved_enc})")

    if saved_hmac and sign_key.hex() == saved_hmac:
        print("    sign_key: VERIFIED against saved session_hmac_key")
    elif saved_hmac:
        print(f"    WARNING: sign_key mismatch (saved: {saved_hmac})")

    return enc_key, sign_key


# ---------------------------------------------------------------------------
# Step 3: Build encrypted MSL manifest request
# ---------------------------------------------------------------------------


def _aes_cbc_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """AES-128-CBC encrypt with PKCS7 padding. Returns (ciphertext, iv)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv = os.urandom(16)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return ciphertext, iv


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    import hashlib
    import hmac as hmac_mod

    return hmac_mod.new(key, data, hashlib.sha256).digest()


def build_manifest_request(
    enc_key: bytes,
    sign_key: bytes,
    master_token: dict,
    viewable_id: int,
) -> bytes:
    """Build an encrypted CBOR MSL manifest request.

    Message structure (matching captured req_269/req_270 format):
      {
        KEY_HEADER (32):      master_token_cbor_bytes    # {15: ..., 16: ...}
        KEY_KEY_EXCHANGE (33): payload_chunk_cbor_bytes  # {6: IV+ct, 7: b"", 8: keyid, 9: hmac}
        KEY_MESSAGE_SIG (16): hmac_sha256_32b            # HMAC-SHA256(sign_key, payload_chunk)
      }

    Returns:
        CBOR-encoded MSL message bytes
    """
    print("[Step 3] Building encrypted MSL manifest request...")

    message_id = random.randint(0, 2**52)
    print(f"    message_id: {message_id}")
    print(f"    viewable_id: {viewable_id}")

    # Build manifest payload body
    payload_body = {
        "version": 2,
        "url": "/manifest",
        "id": message_id,
        "languages": ["en-US"],
        "params": {
            "type": "standard",
            "viewableId": viewable_id,
            "profiles": [
                "heaac-2-dash",
                "heaac-2hq-dash",
                "playready-h264mpl30-dash",
                "playready-h264mpl31-dash",
                "playready-h264hpl30-dash",
                "playready-h264hpl31-dash",
                "vp9-profile0-L30-dash-cenc",
                "vp9-profile0-L31-dash-cenc",
                "dfxp-ls-sdh",
                "simplesdh",
                "nflx-cmisc",
                "BIF240",
                "BIF320",
            ],
            "flavor": "STANDARD",
            "drmType": "fairplay",
            "drmVersion": 25,
            "usePsshBox": True,
            "isBranching": False,
            "useHttpsStreams": True,
            "imageSubtitleHeight": 189,
            "uiVersion": "shakti-v25d2fa21",
            "uiPlatform": "SHAKTI",
            "clientVersion": "6.0011.474.011",
            "supportsPreReleasePin": True,
            "supportsWatermark": True,
            "showAllSubDubTracks": False,
            "titleSpecificData": {
                viewable_id: {
                    "unletterboxed": False,
                }
            },
            "videoOutputInfo": [
                {
                    "type": "DigitalVideoOutputDescriptor",
                    "outputType": "unknown",
                    "supportedHdcpVersions": [],
                    "isHdcpEngaged": False,
                }
            ],
            "preferAssistiveAudio": False,
            "isNonMember": False,
            "supportsAdBreakHydration": False,
            "requestEligibleABTests": True,
            "supportsUnequalizedDownloadables": True,
        },
    }

    # Wrap in MSL payload envelope:
    # {messageid, sequencenumber, compressionalgo, endofmsg, data}
    payload_data_bytes = json.dumps(payload_body).encode("utf-8")
    payload_envelope = {
        "messageid": message_id,
        "sequencenumber": 1,
        "compressionalgo": "",
        "endofmsg": True,
        "data": base64.b64encode(payload_data_bytes).decode("utf-8"),
    }
    payload_plaintext = json.dumps(payload_envelope).encode("utf-8")
    print(f"    Payload plaintext: {len(payload_plaintext)} bytes")

    # AES-128-CBC encrypt: IV is prepended to ciphertext (iOS format)
    ciphertext, iv = _aes_cbc_encrypt(payload_plaintext, enc_key)
    iv_plus_ct = iv + ciphertext
    print(f"    IV+ciphertext: {len(iv_plus_ct)} bytes (IV={iv.hex()})")

    # keyid = ESN + "_" + session_index (matching live captures: ESN_5, ESN_8 etc.)
    keyid = ESN + "_1"

    # Payload chunk: {6: IV+ciphertext, 7: b"", 8: keyid, 9: hmac_16b}
    # key 9 = first 16 bytes of HMAC-SHA256(sign_key, IV+ciphertext)
    payload_hmac_full = _hmac_sha256(sign_key, iv_plus_ct)
    payload_hmac_16 = payload_hmac_full[:16]

    # Encode payload chunk using nf_cbor_encode
    payload_chunk = {
        PAYLOAD_CIPHERTEXT: iv_plus_ct,
        PAYLOAD_IV: b"",
        PAYLOAD_KEYID: keyid,
        PAYLOAD_HMAC: payload_hmac_16,
    }
    payload_chunk_bytes = nf_cbor_encode(payload_chunk)
    print(f"    Payload chunk: {len(payload_chunk_bytes)} bytes")

    # Encode master_token header using nf_cbor_encode
    # master_token from appboot response is already {15: bytes, 16: bytes}
    header_bytes = nf_cbor_encode(master_token)
    print(f"    Header (master_token): {len(header_bytes)} bytes")

    # Message signature: HMAC-SHA256(sign_key, header_bytes + payload_chunk_bytes)
    # From cbor_encoder.py sign_message(): sign(header + payload)
    message_sig = _hmac_sha256(sign_key, header_bytes + payload_chunk_bytes)
    print(f"    Message signature: {message_sig.hex()}")

    # Build top-level MSL message
    msl_message = {
        KEY_KEY_EXCHANGE: payload_chunk_bytes,
        KEY_HEADER: header_bytes,
        KEY_MESSAGE_SIG: message_sig,
    }
    cbor_message = nf_cbor_encode(msl_message)
    print(f"    MSL message: {len(cbor_message)} bytes")

    return cbor_message


# ---------------------------------------------------------------------------
# Step 4: POST manifest request and parse response
# ---------------------------------------------------------------------------


def post_manifest(
    cbor_message: bytes,
    proxy_url: str | None,
    timeout: int,
    nfvdid_cookie: str = "",
) -> bytes:
    """POST the MSL manifest request to the iOS FTL endpoint.

    Returns:
        Raw response bytes
    """
    print("[Step 4] POSTing manifest request...")
    print(f"    URL: {MANIFEST_URL}")
    print(f"    Request size: {len(cbor_message)} bytes")

    session = requests.Session()
    headers = dict(MANIFEST_HEADERS)
    headers["Content-Length"] = str(len(cbor_message))

    if nfvdid_cookie:
        headers["Cookie"] = f"nfvdid={nfvdid_cookie}"

    proxies = {"https": proxy_url, "http": proxy_url} if proxy_url else None

    resp = session.post(
        MANIFEST_URL,
        data=cbor_message,
        headers=headers,
        proxies=proxies,
        verify=False,
        timeout=timeout,
    )

    print(f"    HTTP {resp.status_code} ({len(resp.content)} bytes)")
    print(f"    Content-Type: {resp.headers.get('content-type', 'N/A')}")

    nfstatus = resp.headers.get("X-Netflix.nfstatus", "")
    if nfstatus:
        print(f"    X-Netflix.nfstatus: {nfstatus}")

    return resp.content, resp.status_code


# ---------------------------------------------------------------------------
# Step 4b: Decode MSL response
# ---------------------------------------------------------------------------


def decode_manifest_response(
    raw: bytes,
    enc_key: bytes,
    sign_key: bytes,
) -> dict | None:
    """Decode and decrypt the MSL manifest response.

    Returns:
        Decrypted payload dict, or None if decryption failed
    """
    import gzip as _gzip
    import hashlib
    import hmac as hmac_mod
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    print("[Step 4b] Decoding manifest response...")

    # Decompress if gzip
    if raw[:2] == b"\x1f\x8b":
        raw = _gzip.decompress(raw)
        print(f"    Decompressed to {len(raw)} bytes")

    # Try CBOR decode first
    try:
        top = cbor2.loads(raw)
        print(f"    CBOR top-level keys: {sorted(top.keys())}")
    except Exception:
        # Maybe JSON MSL error response
        try:
            err = json.loads(raw)
            errordata_b64 = err.get("errordata", "")
            if errordata_b64:
                pad = 4 - len(errordata_b64) % 4
                try:
                    error_dict = json.loads(base64.b64decode(errordata_b64 + "=" * pad))
                    print(f"    MSL error: {json.dumps(error_dict, indent=2)}")
                except Exception:
                    print(f"    JSON response: {json.dumps(err, indent=2)[:500]}")
            else:
                print(f"    JSON response: {json.dumps(err, indent=2)[:500]}")
        except Exception:
            print(f"    Raw response (first 200B): {raw[:200]}")
        return None

    # Extract payload chunk (key 33 or 64)
    payload_raw = top.get(KEY_KEY_EXCHANGE) or top.get(KEY_PAYLOAD_CHUNK)
    if payload_raw is None:
        print(f"    No payload chunk (key {KEY_KEY_EXCHANGE} or {KEY_PAYLOAD_CHUNK})")
        print(f"    Full response: {top}")
        return None

    # Decode payload chunk CBOR
    payload_chunk = (
        cbor2.loads(payload_raw) if isinstance(payload_raw, bytes) else payload_raw
    )
    print(f"    Payload chunk keys: {sorted(payload_chunk.keys())}")

    ciphertext_raw = payload_chunk.get(PAYLOAD_CIPHERTEXT, b"")
    iv_field = payload_chunk.get(PAYLOAD_IV, b"")

    if not isinstance(ciphertext_raw, bytes) or len(ciphertext_raw) == 0:
        print(f"    No ciphertext in payload chunk")
        print(f"    Payload chunk: {payload_chunk}")
        return None

    # iOS format: IV is prepended to ciphertext if PAYLOAD_IV (key 7) is empty
    if not isinstance(iv_field, bytes) or len(iv_field) < 16:
        if len(ciphertext_raw) > 16:
            iv = ciphertext_raw[:16]
            ciphertext = ciphertext_raw[16:]
            print(f"    IV extracted from ciphertext prefix: {iv.hex()}")
        else:
            print(
                f"    Cannot extract IV: ciphertext too short ({len(ciphertext_raw)}B)"
            )
            return None
    else:
        iv = iv_field
        ciphertext = ciphertext_raw
        print(f"    IV from key 7: {iv.hex()}")

    print(f"    Ciphertext: {len(ciphertext)} bytes")

    # AES-128-CBC decrypt + PKCS7 unpad
    try:
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        pad_len = padded[-1]
        if 0 < pad_len <= 16:
            plaintext = padded[:-pad_len]
        else:
            plaintext = padded
        print(f"    Decrypted plaintext: {len(plaintext)} bytes")
    except Exception as e:
        print(f"    Decryption failed: {e}")
        return None

    # Parse the plaintext as JSON payload envelope
    try:
        envelope = json.loads(plaintext)
        print(f"    Envelope keys: {list(envelope.keys())}")
    except json.JSONDecodeError as e:
        print(f"    JSON decode failed: {e}")
        print(f"    Plaintext (first 200B): {plaintext[:200]}")
        return None

    # Decode the data field
    data_b64 = envelope.get("data", "")
    if not data_b64:
        print("    No data field in payload envelope")
        return envelope

    try:
        data_bytes = base64.b64decode(data_b64)
        compressionalgo = envelope.get("compressionalgo", "")
        if compressionalgo == "GZIP":
            import gzip as _gz

            data_bytes = _gz.decompress(data_bytes)
        payload = json.loads(data_bytes)
        print(f"    Payload decoded: {len(data_bytes)} bytes")
        return payload
    except Exception as e:
        print(f"    Data decode failed: {e}")
        return envelope


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="iOS MSL appboot replay to manifest request",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--viewable-id",
        type=int,
        default=81215567,
        help="Netflix viewable ID (default: 81215567)",
    )
    parser.add_argument(
        "--proxy",
        default=DEFAULT_PROXY,
        help=f"HTTP proxy URL (default: {DEFAULT_PROXY})",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Disable HTTP proxy",
    )
    parser.add_argument(
        "--offline-appboot",
        action="store_true",
        default=True,
        help="Use saved appboot response instead of replaying (default: True)",
    )
    parser.add_argument(
        "--live-appboot",
        action="store_true",
        help="Replay the saved appboot request to get a fresh response",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    proxy_url = None if args.no_proxy else args.proxy
    do_live_appboot = args.live_appboot
    viewable_id = args.viewable_id

    sep = "=" * 65
    print(sep)
    print("  iOS MSL: appboot replay -> session keys -> manifest request")
    print(sep)
    print(f"  ESN:         {ESN[:50]}...")
    print(f"  viewable_id: {viewable_id}")
    print(f"  proxy:       {proxy_url or '(none)'}")
    print(
        f"  mode:        {'live appboot' if do_live_appboot else 'saved appboot response'}"
    )
    print(sep)
    print()

    # Step 1: appboot replay or load saved response
    try:
        if do_live_appboot:
            appboot_resp, device_id_token = replay_appboot(proxy_url, args.timeout)
        else:
            appboot_resp, device_id_token = load_saved_appboot_response()
    except RuntimeError as e:
        print(f"[ERROR] appboot failed: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e}")
        sys.exit(1)
    print()

    # Step 1b: parse appboot response
    try:
        server_dh_pub, master_token = parse_appboot_response(appboot_resp)
    except ValueError as e:
        print(f"[ERROR] Failed to parse appboot response: {e}")
        sys.exit(1)
    print()

    # Step 2: derive session keys
    try:
        enc_key, sign_key = derive_session_keys(server_dh_pub)
    except Exception as e:
        print(f"[ERROR] Session key derivation failed: {e}")
        sys.exit(1)
    print()

    # Step 3: build manifest request
    try:
        cbor_message = build_manifest_request(
            enc_key, sign_key, master_token, viewable_id
        )
    except Exception as e:
        print(f"[ERROR] Failed to build manifest request: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    print()

    # Verify the built message is valid CBOR
    try:
        decoded_check = cbor2.loads(cbor_message)
        print(f"    CBOR verification: OK (keys={sorted(decoded_check.keys())})")
    except Exception as e:
        print(f"[ERROR] CBOR verification failed: {e}")
        sys.exit(1)
    print()

    # Step 4: POST manifest request

    try:
        resp_bytes, status_code = post_manifest(
            cbor_message,
            proxy_url,
            args.timeout,
        )
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] Connection failed: {e}")
        print()
        print("  Possible causes:")
        print("  - Proxy not running (mitmproxy / Proxyman)")
        print("  - Network unreachable")
        print(f"  - Proxy URL: {proxy_url}")
        print()
        print(
            "  Built manifest request successfully. Run with --no-proxy to skip POST."
        )
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"[ERROR] Request timed out after {args.timeout}s")
        sys.exit(1)
    print()

    # Step 4b: decode response
    if status_code == 200:
        result = decode_manifest_response(resp_bytes, enc_key, sign_key)
        print()
        if result is not None:
            print(sep)
            print("  RESULT: Manifest response decoded successfully")
            print(sep)
            if "result" in result:
                manifest_result = result["result"]
                if isinstance(manifest_result, dict):
                    print(f"  Manifest keys: {list(manifest_result.keys())[:10]}")
                    movie_id = manifest_result.get("movieId")
                    if movie_id:
                        print(f"  movieId: {movie_id}")
                else:
                    print(f"  result type: {type(manifest_result).__name__}")
            elif "errorcode" in result or "errorsummary" in result:
                print(f"  MSL error: {json.dumps(result, indent=2)[:500]}")
            else:
                print(f"  Response keys: {list(result.keys())[:10]}")
                print(f"  Response (first 500 chars): {json.dumps(result)[:500]}")
        else:
            print(sep)
            print("  RESULT: Response received but decryption failed")
            print(sep)
            print(f"  Raw response (first 200B hex): {resp_bytes[:200].hex()}")
    else:
        print(sep)
        print(f"  RESULT: HTTP {status_code}")
        print(sep)
        try:
            err = json.loads(resp_bytes)
            print(f"  Error: {json.dumps(err, indent=2)[:500]}")
        except Exception:
            print(f"  Response (first 300B): {resp_bytes[:300]}")


if __name__ == "__main__":
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
