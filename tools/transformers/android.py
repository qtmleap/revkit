#!/usr/bin/env python3
"""Android Frida ログ → Chrome extension 形式変換.

Usage:
  python -m tools.transformers.android raws/android/20260404/capture.jsonl
  python -m tools.transformers.android raws/android/20260404/capture.jsonl -o logs/android
"""

import argparse
import sys
from pathlib import Path

from tools.transformers.base import (
    BaseTransformer,
    load_entries,
    print_summary,
    write_output,
)


class AndroidTransformer(BaseTransformer):
    """Android Frida ログ用のイベントハンドラマッピング.

    Android 固有のイベント (Java MSL / Cronet / ALE BouncyCastle 等) を
    Chrome extension 形式にマッピングする。
    """

    def handle_esn_android(self, e: dict):
        """Android ESN は PRV / PXA を区別する."""
        esn = e.get("esn", "")
        if not esn:
            return
        if "PRV" in esn.upper():
            self.esn["prv"] = esn
        elif "PXA" in esn.upper():
            self.esn["pxa"] = esn
        else:
            self.esn["prv"] = esn
        self.esn["capturedAt"] = e.get("ts", "")

    _handlers: dict = {
        # MSL
        "msl.message": BaseTransformer.handle_msl_message,
        "msl.api": BaseTransformer.handle_msl_api,
        "msl.api.response": BaseTransformer.handle_msl_api_response,
        "appboot.response": BaseTransformer.handle_msl_api_response,
        # MSL response payload (MessageInputStream / PayloadChunk)
        "msl.response.payload": BaseTransformer.handle_msl_response_payload,
        "msl.payload": BaseTransformer.handle_msl_response_payload,
        # HTTP
        "http.request": BaseTransformer.handle_http_request,
        "http.response": BaseTransformer.handle_http_response,
        # Crypto (Java MSL AesCbcEncryptor)
        "msl.aesCbcEncrypt": BaseTransformer.handle_aes_cbc_encrypt_combined,
        "msl.aesCbcDecrypt": BaseTransformer.handle_aes_cbc_decrypt,
        "msl.hmacSha256": BaseTransformer.handle_hmac,
        "msl.hmacSha256.sign": BaseTransformer.handle_hmac,
        "msl.aesKwUnwrap": BaseTransformer.handle_aes_kw_unwrap,
        "msl.dhSharedSecret": BaseTransformer.handle_dh_shared_secret,
        "msl.rsaEncrypt": BaseTransformer.handle_rsa,
        "msl.rsaDecrypt": BaseTransformer.handle_rsa,
        # Crypto (WidevineCryptoContext / SymmetricCryptoContext)
        "msl.widevine.encrypt": BaseTransformer.handle_noop,
        "msl.widevine.decrypt": BaseTransformer.handle_aes_cbc_decrypt,  # CBOR チャンク蓄積 (iOS と同じ)
        "msl.widevine.sign": BaseTransformer.handle_noop,
        "msl.widevine.verify": BaseTransformer.handle_noop,
        "msl.symmetric.encrypt": BaseTransformer.handle_noop,
        "msl.symmetric.decrypt": BaseTransformer.handle_noop,
        "msl.symmetric.sign": BaseTransformer.handle_noop,
        "msl.symmetric.verify": BaseTransformer.handle_noop,
        # Crypto (JWE)
        "msl.jwe.wrap": BaseTransformer.handle_noop,
        "msl.jwe.unwrap": BaseTransformer.handle_noop,
        # DRM
        "drm.keyRequest": BaseTransformer.handle_noop,
        "drm.keyResponse": BaseTransformer.handle_noop,
        "drm.openSession": BaseTransformer.handle_noop,
        "drm.property": BaseTransformer.handle_noop,
        "drm.propertyString": BaseTransformer.handle_noop,
        # ALE (BouncyCastle)
        "ale.keys": BaseTransformer.handle_ale_keys,
        # Keys / ESN / Manifest
        "esn.detected": handle_esn_android,
        "manifest": BaseTransformer.handle_manifest,
        # Auth
        "msl.userauthdata": BaseTransformer.handle_noop,
        # Storage
        "storage.sharedPreferences": BaseTransformer.handle_storage_shared_prefs,
        "storage.file": BaseTransformer.handle_storage_file,
        "storage.appFiles": BaseTransformer.handle_storage_sandbox,
        # Skip
        "manifest.kidTable": BaseTransformer.handle_noop,
        "msl.encrypt.input": BaseTransformer.handle_noop,
        "msl.decrypt.output": BaseTransformer.handle_noop,
        "url": BaseTransformer.handle_noop,
    }


def main():
    p = argparse.ArgumentParser(description="Android → Chrome log transformer")
    p.add_argument("input", help="Android capture.jsonl path")
    p.add_argument("-o", "--output", help="Output directory (default: logs/android)")
    args = p.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[-] File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output) if args.output else Path("logs") / "android"

    print(f"[*] Input:  {input_path}")
    print(f"[*] Output: {out_dir}")

    entries = load_entries(input_path)
    print(f"[*] Loaded {len(entries)} entries")

    t = AndroidTransformer()
    t.transform(entries)
    write_output(t, out_dir)
    print_summary(t, "Android")


if __name__ == "__main__":
    main()
