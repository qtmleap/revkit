#!/usr/bin/env python3
"""Chrome Widevine WVD Builder

Frida で抽出した private_key と、キャプチャ済みチャレンジから取得した
client_id を組み合わせて pywidevine 用の WVD ファイルを構築する。

使い方:
  # 1. Frida ログから秘密鍵を抽出し、チャレンジから client_id を取得して WVD を構築
  python extract_wvd.py

  # 2. 手動でファイルを指定
  python extract_wvd.py --private-key private_key.der --client-id client_id.bin -o chrome_l3.wvd
"""

import argparse
import base64
import glob
import json
import sys
from pathlib import Path


def find_latest_session_dir() -> Path | None:
    """最新の Frida ログセッションディレクトリを見つける。"""
    sessions = sorted(glob.glob("logs/chrome_*/"), reverse=True)
    if sessions:
        return Path(sessions[0])
    return None


def extract_private_key_from_logs(session_dir: Path) -> bytes | None:
    """Frida キャプチャログから RSA 秘密鍵を抽出する。"""
    # capture.jsonl から cdm.privateKey イベントを探す
    capture_file = session_dir / "capture.jsonl"
    if capture_file.exists():
        for line in capture_file.read_text().splitlines():
            try:
                entry = json.loads(line)
                if entry.get("event") == "cdm.privateKey":
                    key_hex = entry.get("key_hex", "")
                    if key_hex:
                        print(f"[+] Found private key in {capture_file}")
                        print(f"    Format: {entry.get('format', '?')}")
                        print(f"    Length: {entry.get('length', '?')} bytes")
                        print(f"    Location: {entry.get('location', '?')}")
                        return bytes.fromhex(key_hex)
            except (json.JSONDecodeError, ValueError):
                continue

    # cdm/ ディレクトリの個別 JSON ファイルも確認
    cdm_dir = session_dir / "cdm"
    if cdm_dir.exists():
        for f in sorted(cdm_dir.glob("*privateKey*.json")):
            try:
                entry = json.loads(f.read_text())
                key_hex = entry.get("key_hex", "")
                if key_hex:
                    print(f"[+] Found private key in {f}")
                    return bytes.fromhex(key_hex)
            except (json.JSONDecodeError, ValueError):
                continue

    return None


def extract_client_id_from_challenge(challenge_path: Path) -> bytes | None:
    """キャプチャ済みチャレンジから ClientIdentification を抽出する。"""
    try:
        from pywidevine.license_protocol_pb2 import SignedMessage, LicenseRequest
    except ImportError:
        print("[!] pywidevine is required: pip install pywidevine")
        sys.exit(1)

    data = json.loads(challenge_path.read_text())

    # message_b64 フィールドからチャレンジを取得
    msg_b64 = (
        data.get("message_b64") or data.get("challenge_b64") or data.get("message")
    )
    if not msg_b64:
        return None

    signed_message = SignedMessage()
    signed_message.ParseFromString(base64.b64decode(msg_b64))

    license_request = LicenseRequest()
    license_request.ParseFromString(signed_message.msg)

    client_id_bytes = license_request.client_id.SerializeToString()
    if client_id_bytes:
        print(
            f"[+] Extracted client_id ({len(client_id_bytes)} bytes) from {challenge_path}"
        )
        return client_id_bytes
    return None


def find_challenge_file() -> Path | None:
    """キャプチャ済みチャレンジファイルを探す。"""
    # dumps/chrome/eme/challenges/ を探す
    patterns = [
        "dumps/chrome/eme/challenges/*.json",
        "dumps/chrome/challenges/*.json",
        "dumps/chrome/*.json",
    ]
    for pattern in patterns:
        files = sorted(glob.glob(pattern))
        if files:
            return Path(files[0])

    # Frida ログからも探す (createSession イベント)
    session_dir = find_latest_session_dir()
    if session_dir:
        cdm_dir = session_dir / "cdm"
        if cdm_dir.exists():
            for f in sorted(cdm_dir.glob("*createSession*.json")):
                return f

    return None


def build_wvd(private_key: bytes, client_id: bytes, output_path: Path) -> None:
    """WVD ファイルを構築する。"""
    try:
        from pywidevine.device import Device, DeviceTypes
    except ImportError:
        print("[!] pywidevine is required: pip install pywidevine")
        sys.exit(1)

    # PKCS#8 かどうかを判定
    # PKCS#8 RSA: 30 82 xx xx 02 01 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01
    is_pkcs8 = (
        len(private_key) > 20
        and private_key[0] == 0x30
        and private_key[7] == 0x30
        and private_key[9] == 0x06
        and private_key[10] == 0x09
    )

    if is_pkcs8:
        print("[*] Key format: PKCS#8 (converting to PKCS#1 for pywidevine)")
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PrivateFormat,
            NoEncryption,
            load_der_private_key,
        )

        rsa_key = load_der_private_key(private_key, password=None)
        private_key_pkcs1 = rsa_key.private_bytes(
            Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
    else:
        print("[*] Key format: PKCS#1")
        private_key_pkcs1 = private_key

    device = Device(
        type_=DeviceTypes.CHROME,
        security_level=3,
        flags={},
        private_key=private_key_pkcs1,
        client_id=client_id,
    )
    device.dump(output_path)
    print(f"[+] WVD saved to {output_path}")
    print(f"    Type: CHROME, Security Level: 3")


def verify_wvd(wvd_path: Path) -> None:
    """構築した WVD の検証。"""
    try:
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
    except ImportError:
        print("[!] pywidevine is required for verification")
        return

    device = Device.load(wvd_path)
    cdm = Cdm.from_device(device)
    session_id = cdm.open()

    # テスト PSSH でチャレンジ生成
    test_pssh = PSSH(
        "AAAANHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABQIARIQAAAAAAPSZ0kAAAAAAAAAAA=="
    )
    challenge = cdm.get_license_challenge(session_id, test_pssh)

    print(f"[+] Verification successful!")
    print(f"    Challenge size: {len(challenge)} bytes")
    print(f"    WVD is functional")
    cdm.close(session_id)


def main():
    parser = argparse.ArgumentParser(description="Chrome Widevine WVD Builder")
    parser.add_argument("--private-key", type=Path, help="RSA 秘密鍵ファイル (DER)")
    parser.add_argument(
        "--client-id", type=Path, help="ClientIdentification ファイル (protobuf bytes)"
    )
    parser.add_argument(
        "--challenge", type=Path, help="チャレンジ JSON ファイル (client_id 抽出用)"
    )
    parser.add_argument(
        "--session-dir", type=Path, help="Frida ログセッションディレクトリ"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("chrome_l3.wvd"),
        help="出力 WVD ファイルパス",
    )
    parser.add_argument("--verify", action="store_true", help="構築後にWVDを検証")
    parser.add_argument(
        "--save-key", type=Path, help="抽出した秘密鍵を別途保存するパス"
    )
    parser.add_argument(
        "--save-client-id", type=Path, help="抽出した client_id を別途保存するパス"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("Chrome Widevine WVD Builder")
    print("=" * 60)

    # 1. Private Key を取得
    private_key: bytes | None = None
    if args.private_key:
        private_key = args.private_key.read_bytes()
        print(
            f"[+] Loaded private key from {args.private_key} ({len(private_key)} bytes)"
        )
    else:
        session_dir = args.session_dir or find_latest_session_dir()
        if session_dir:
            print(f"[*] Searching for private key in {session_dir}...")
            private_key = extract_private_key_from_logs(session_dir)

    if not private_key:
        print("[!] Private key not found.")
        print("    Run the Frida hook first to extract the key:")
        print("    python run_chrome_cdm.py")
        print("    Then play DRM content in Chrome.")
        sys.exit(1)

    # 2. Client ID を取得
    client_id: bytes | None = None
    if args.client_id:
        client_id = args.client_id.read_bytes()
        print(f"[+] Loaded client_id from {args.client_id} ({len(client_id)} bytes)")
    else:
        challenge_path = args.challenge or find_challenge_file()
        if challenge_path:
            print(f"[*] Extracting client_id from {challenge_path}...")
            client_id = extract_client_id_from_challenge(challenge_path)

    if not client_id:
        print("[!] Client ID not found.")
        print("    Provide a challenge JSON with --challenge,")
        print("    or a raw client_id file with --client-id.")
        sys.exit(1)

    # 3. オプション: 中間ファイルを保存
    if args.save_key:
        args.save_key.write_bytes(private_key)
        print(f"[+] Private key saved to {args.save_key}")

    if args.save_client_id:
        args.save_client_id.write_bytes(client_id)
        print(f"[+] Client ID saved to {args.save_client_id}")

    # 4. WVD を構築
    print()
    build_wvd(private_key, client_id, args.output)

    # 5. 検証
    if args.verify:
        print()
        verify_wvd(args.output)


if __name__ == "__main__":
    main()
