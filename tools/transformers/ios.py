#!/usr/bin/env python3
"""iOS Frida ログ → Chrome extension 形式変換.

Usage:
  python -m tools.transformers.ios raws/ios/20260404/capture.jsonl
  python -m tools.transformers.ios raws/ios/20260404/capture.jsonl -o logs/ios
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


class IOSTransformer(BaseTransformer):
    """iOS Frida ログ用のイベントハンドラマッピング."""

    _handlers: dict = {
        # MSL
        "msl.message": BaseTransformer.handle_msl_message,
        "msl.api": BaseTransformer.handle_msl_api,
        "msl.api.response": BaseTransformer.handle_msl_api_response,
        "appboot.response": BaseTransformer.handle_msl_api_response,
        # HTTP
        "http.request": BaseTransformer.handle_http_request,
        "http.response": BaseTransformer.handle_http_response,
        # Crypto (MslClient native)
        "msl.aesCbcEncrypt": BaseTransformer.handle_aes_cbc_encrypt_combined,
        "msl.aesCbcDecrypt": BaseTransformer.handle_aes_cbc_decrypt,
        "msl.hmacSha256": BaseTransformer.handle_hmac,
        "msl.aesKwUnwrap": BaseTransformer.handle_aes_kw_unwrap,
        "msl.dhSharedSecret": BaseTransformer.handle_dh_shared_secret,
        "msl.rsaEncrypt": BaseTransformer.handle_rsa,
        "msl.rsaDecrypt": BaseTransformer.handle_rsa,
        # Keys / ESN / Manifest
        "ale.keys": BaseTransformer.handle_ale_keys,
        "esn.detected": BaseTransformer.handle_esn,
        "manifest": BaseTransformer.handle_manifest,
        # Storage
        "storage.userDefaults": BaseTransformer.handle_storage_user_defaults,
        "storage.keychain": BaseTransformer.handle_storage_keychain,
        "storage.file": BaseTransformer.handle_storage_file,
        "storage.sandbox": BaseTransformer.handle_storage_sandbox,
        # Skip
        "manifest.kidTable": BaseTransformer.handle_noop,
        "msl.encrypt.input": BaseTransformer.handle_noop,
        "msl.decrypt.output": BaseTransformer.handle_noop,
        "url": BaseTransformer.handle_noop,
    }


def main():
    p = argparse.ArgumentParser(description="iOS → Chrome log transformer")
    p.add_argument("input", help="iOS capture.jsonl path")
    p.add_argument("-o", "--output", help="Output directory (default: logs/ios)")
    args = p.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[-] File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output) if args.output else Path("logs") / "ios"

    print(f"[*] Input:  {input_path}")
    print(f"[*] Output: {out_dir}")

    entries = load_entries(input_path)
    print(f"[*] Loaded {len(entries)} entries")

    t = IOSTransformer()
    t.transform(entries)
    write_output(t, out_dir)
    print_summary(t, "iOS")


if __name__ == "__main__":
    main()
