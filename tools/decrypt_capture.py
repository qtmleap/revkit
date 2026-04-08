#!/usr/bin/env python3
"""decrypt_capture.py — MSL キャプチャファイルのオフライン復号 CLI

Frida / mitmproxy でキャプチャしたバイナリファイルと鍵素材を入力に、
AES-CBC 復号した結果を出力する。

使い方:
  python tools/decrypt_capture.py --keys keys.json --input capture.bin
  python tools/decrypt_capture.py --keys keys.json --input capture.bin --output decrypted.json
  python tools/decrypt_capture.py --enc-key <hex> --sign-key <hex> --input capture.bin
  python tools/decrypt_capture.py --keys keys.json --input-dir ./captures/
  python tools/decrypt_capture.py --keys keys.json --input capture.bin --format raw
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# src/ をモジュール検索パスに追加
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from netflix_msl.cbor_decoder import CborMslDecoder
from netflix_msl.crypto import NetflixCrypto


def build_crypto(args: argparse.Namespace) -> NetflixCrypto:
    """引数から NetflixCrypto インスタンスを構築して返す."""
    crypto = NetflixCrypto()

    if args.keys:
        crypto.import_keys_from_file(str(args.keys))
    elif args.enc_key and args.sign_key:
        enc = bytes.fromhex(args.enc_key)
        sign = bytes.fromhex(args.sign_key)
        crypto.import_session_keys(enc, sign)
    else:
        print(
            "[!] --keys または --enc-key / --sign-key のいずれかを指定してください",
            file=sys.stderr,
        )
        sys.exit(1)

    return crypto


def process_file(
    decoder: CborMslDecoder,
    path: Path,
    fmt: str,
    output_path: Path | None,
) -> bool:
    """単一ファイルを処理する. 成功時 True を返す."""
    raw = path.read_bytes()

    try:
        result = decoder.process_message(raw)
    except Exception as e:
        print(f"[E] {path.name}: {e}", file=sys.stderr)
        return False

    payloads = result.get("payloads", [])
    if not payloads:
        print(f"[W] {path.name}: ペイロードなし", file=sys.stderr)
        return False

    # 復号されたペイロードを出力
    output_data: dict | list = {
        "file": path.name,
        "signature_valid": result.get("signature_valid"),
        "payloads": payloads,
    }

    if fmt == "hex":
        output_str = json.dumps(output_data, ensure_ascii=False, default=repr)
    elif fmt == "raw":
        output_str = json.dumps(output_data, ensure_ascii=False, indent=2, default=repr)
    else:
        output_str = json.dumps(output_data, ensure_ascii=False, indent=2, default=repr)

    if output_path is not None:
        output_path.write_text(output_str, encoding="utf-8")
        print(f"[+] {path.name} -> {output_path}", file=sys.stderr)
    else:
        print(output_str)

    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MSL キャプチャファイルのオフライン復号",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # 鍵素材
    key_group = parser.add_argument_group("鍵素材 (いずれか必須)")
    key_group.add_argument(
        "--keys",
        type=Path,
        metavar="FILE",
        help='Frida が出力した鍵 JSON ファイル ({"enc_key": "<hex>", "sign_key": "<hex>"})',
    )
    key_group.add_argument(
        "--enc-key",
        metavar="HEX",
        help="AES-128 暗号化鍵を hex で直接指定",
    )
    key_group.add_argument(
        "--sign-key",
        metavar="HEX",
        help="HMAC-SHA256 署名鍵を hex で直接指定",
    )

    # 入力
    input_group = parser.add_argument_group("入力 (いずれか必須)")
    input_ex = input_group.add_mutually_exclusive_group(required=True)
    input_ex.add_argument(
        "--input",
        type=Path,
        metavar="FILE",
        help="単一の .bin ファイル",
    )
    input_ex.add_argument(
        "--input-dir",
        type=Path,
        metavar="DIR",
        help="ディレクトリ内の全 .bin ファイルを処理",
    )

    # 出力
    parser.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="出力先ファイル (省略時は stdout)。--input-dir 使用時は無視される",
    )
    parser.add_argument(
        "--format",
        choices=["json", "raw", "hex"],
        default="json",
        help="出力フォーマット (default: json)",
    )

    args = parser.parse_args()

    # 鍵素材の相互排他チェック
    if args.keys and (args.enc_key or args.sign_key):
        parser.error("--keys と --enc-key/--sign-key は同時に指定できません")
    if not args.keys and not (args.enc_key and args.sign_key):
        parser.error("--keys か --enc-key と --sign-key の両方を指定してください")

    crypto = build_crypto(args)
    decoder = CborMslDecoder(crypto)

    # 入力ファイルの収集
    if args.input is not None:
        if not args.input.exists():
            print(f"[!] ファイルが見つかりません: {args.input}", file=sys.stderr)
            sys.exit(1)
        files = [args.input]
        output_path = args.output
    else:
        if not args.input_dir.is_dir():
            print(
                f"[!] ディレクトリが見つかりません: {args.input_dir}", file=sys.stderr
            )
            sys.exit(1)
        files = sorted(args.input_dir.glob("*.bin"))
        if not files:
            print(
                f"[!] .bin ファイルが見つかりません: {args.input_dir}", file=sys.stderr
            )
            sys.exit(1)
        output_path = None  # ディレクトリ処理時は stdout に個別出力

    success = 0
    failure = 0

    for path in files:
        if args.input_dir is not None and len(files) > 1:
            # 複数ファイル処理: ファイル名をヘッダとして表示
            print(f"\n=== {path.name} ===", file=sys.stderr)

        ok = process_file(decoder, path, args.format, output_path)
        if ok:
            success += 1
        else:
            failure += 1

    if len(files) > 1:
        print(
            f"\n[*] 完了: {success} 成功 / {failure} 失敗 (合計 {len(files)} ファイル)",
            file=sys.stderr,
        )
        if failure > 0:
            sys.exit(1)


if __name__ == "__main__":
    main()
