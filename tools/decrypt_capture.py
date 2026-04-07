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


def verify_hmac(crypto: NetflixCrypto, data: bytes, expected_hmac: bytes) -> bool:
    """HMAC-SHA256 を検証する.

    data に対して sign() を実行し expected_hmac と比較する。
    sign() は文字列 → bytes.decode() 前提なので、ここでは低レベルで計算する。
    """
    import hashlib
    import hmac as hmac_mod

    if crypto.sign_key is None:
        return False

    computed = hmac_mod.new(crypto.sign_key, data, hashlib.sha256).digest()
    return hmac_mod.compare_digest(computed, expected_hmac)


def try_cbor_decode(data: bytes) -> dict | None:
    """CBOR デコードを試みる. 失敗時は None を返す."""
    try:
        import cbor2

        return cbor2.loads(data)
    except Exception:
        return None


def try_decrypt_payload(crypto: NetflixCrypto, data: bytes) -> bytes | None:
    """MSL ペイロード (IV + CT 形式) または生 AES-CBC の復号を試みる.

    まず CBOR デコードして iv / ciphertext フィールドを取得。
    失敗した場合は先頭 16 bytes を IV として残りを CT とみなして復号する。
    """
    import base64

    cbor_obj = try_cbor_decode(data)
    if cbor_obj is not None and isinstance(cbor_obj, dict):
        # CBOR ペイロード: {"iv": bytes, "ciphertext": bytes} または Base64 文字列
        iv_raw = cbor_obj.get("iv") or cbor_obj.get(b"iv")
        ct_raw = cbor_obj.get("ciphertext") or cbor_obj.get(b"ciphertext")

        if iv_raw is None or ct_raw is None:
            return None

        # Base64 文字列の場合はデコード
        if isinstance(iv_raw, str):
            iv_raw = base64.b64decode(iv_raw)
        if isinstance(ct_raw, str):
            ct_raw = base64.b64decode(ct_raw)

        return crypto.decrypt(bytes(ct_raw), bytes(iv_raw))

    # 生バイナリ: 先頭 16 bytes = IV、残り = CT
    if len(data) < 32 or len(data) % 16 != 0:
        return None

    iv = data[:16]
    ct = data[16:]
    return crypto.decrypt(ct, iv)


def decrypt_file(
    crypto: NetflixCrypto,
    path: Path,
) -> tuple[bytes | None, str | None]:
    """ファイルを復号して (plaintext, error_message) を返す.

    復号に成功した場合 error_message は None。
    """
    raw = path.read_bytes()

    # --- HMAC 検証 (末尾 32 bytes を HMAC として扱う) ---
    hmac_warning: str | None = None
    if len(raw) > 32:
        body = raw[:-32]
        tail = raw[-32:]
        if not verify_hmac(crypto, body, tail):
            hmac_warning = f"[W] {path.name}: HMAC-SHA256 検証失敗 (処理は続行)"

    plaintext = try_decrypt_payload(crypto, raw)
    if plaintext is None:
        return None, f"[E] {path.name}: 復号失敗 (フォーマット不一致または鍵不一致)"

    return plaintext, hmac_warning


def format_output(plaintext: bytes, fmt: str) -> str:
    """復号結果を指定フォーマットに変換する."""
    if fmt == "hex":
        return plaintext.hex()

    if fmt == "raw":
        # バイナリをそのまま返す (呼び出し側で bytes.write を使う)
        return plaintext.decode("latin-1")

    # json (default)
    # JSON として解釈を試みる
    try:
        obj = json.loads(plaintext)
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # CBOR として解釈を試みる
    cbor_obj = try_cbor_decode(plaintext)
    if cbor_obj is not None:
        try:
            return json.dumps(cbor_obj, ensure_ascii=False, indent=2, default=repr)
        except Exception:
            pass

    # どちらでもない場合は hex で返す
    return plaintext.hex()


def process_file(
    crypto: NetflixCrypto,
    path: Path,
    fmt: str,
    output_path: Path | None,
) -> bool:
    """単一ファイルを処理する. 成功時 True を返す."""
    plaintext, error = decrypt_file(crypto, path)

    if error and plaintext is None:
        print(error, file=sys.stderr)
        return False

    if error:
        # HMAC 警告
        print(error, file=sys.stderr)

    assert plaintext is not None
    result = format_output(plaintext, fmt)

    if output_path is not None:
        if fmt == "raw":
            output_path.write_bytes(plaintext)
        else:
            output_path.write_text(result, encoding="utf-8")
        print(f"[+] {path.name} -> {output_path}", file=sys.stderr)
    else:
        if fmt == "raw":
            sys.stdout.buffer.write(plaintext)
        else:
            print(result)

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

        ok = process_file(crypto, path, args.format, output_path)
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
