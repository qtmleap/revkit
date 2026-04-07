#!/usr/bin/env python3
"""RSA Private Key ↔ Client ID Verifier

抽出した RSA 秘密鍵が CDM の client_id 内の公開鍵と対応するか検証する。

使い方:
  # チャレンジファイルがある場合
  python verify_key.py private_key.der --challenge challenge.json

  # client_id バイナリがある場合
  python verify_key.py private_key.der --client-id client_id.bin

  # 鍵の情報だけ表示
  python verify_key.py private_key.der
"""

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    """DER または PEM 形式の RSA 秘密鍵を読み込む。"""
    data = path.read_bytes()

    # PEM?
    if b"-----BEGIN" in data:
        return serialization.load_pem_private_key(data, password=None)

    # DER: PKCS#8 or PKCS#1
    try:
        return serialization.load_der_private_key(data, password=None)
    except Exception:
        pass

    # PKCS#1 (TraditionalOpenSSL)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    try:
        from cryptography.hazmat.backends import default_backend

        return serialization.load_der_private_key(
            data, password=None, backend=default_backend()
        )
    except Exception:
        pass

    print(f"[!] Cannot parse key from {path}")
    sys.exit(1)


def extract_public_key_from_client_id(client_id_bytes: bytes):
    """ClientIdentification protobuf から RSA 公開鍵を抽出する。"""
    try:
        from pywidevine.license_protocol_pb2 import ClientIdentification
    except ImportError:
        print("[!] pywidevine required: pip install pywidevine")
        sys.exit(1)

    cid = ClientIdentification()
    cid.ParseFromString(client_id_bytes)

    # Token フィールドに DER エンコードされた証明書チェーンが含まれる
    token = cid.token
    if not token:
        print("[!] client_id.token is empty")
        return None

    # Token は DrmCertificate (SignedDrmCertificate) を含む
    try:
        from pywidevine.license_protocol_pb2 import SignedDrmCertificate, DrmCertificate

        signed_cert = SignedDrmCertificate()
        signed_cert.ParseFromString(token)

        cert = DrmCertificate()
        cert.ParseFromString(signed_cert.drm_certificate)

        pub_key_bytes = cert.public_key
        if pub_key_bytes:
            print(
                f"[*] Found public key in DrmCertificate ({len(pub_key_bytes)} bytes)"
            )
            return serialization.load_der_public_key(pub_key_bytes)
    except Exception as e:
        print(f"[*] Could not parse DrmCertificate from token: {e}")

    return None


def extract_client_id_from_challenge(challenge_path: Path) -> bytes | None:
    """チャレンジ JSON から client_id を抽出。"""
    try:
        from pywidevine.license_protocol_pb2 import SignedMessage, LicenseRequest
    except ImportError:
        print("[!] pywidevine required")
        sys.exit(1)

    data = json.loads(challenge_path.read_text())
    msg_b64 = (
        data.get("message_b64") or data.get("challenge_b64") or data.get("message")
    )
    if not msg_b64:
        print(f"[!] No message field in {challenge_path}")
        return None

    signed_msg = SignedMessage()
    signed_msg.ParseFromString(base64.b64decode(msg_b64))

    lr = LicenseRequest()
    lr.ParseFromString(signed_msg.msg)

    return lr.client_id.SerializeToString()


def main():
    parser = argparse.ArgumentParser(
        description="Verify RSA private key against CDM client_id"
    )
    parser.add_argument("key", type=Path, help="RSA private key file (DER/PEM)")
    parser.add_argument("--challenge", type=Path, help="Challenge JSON file")
    parser.add_argument("--client-id", type=Path, help="Raw client_id binary file")
    args = parser.parse_args()

    print("=" * 60)
    print("[*] RSA Private Key Verifier")
    print("=" * 60)

    # 秘密鍵をロード
    priv_key = load_private_key(args.key)
    pub_from_priv = priv_key.public_key()
    pub_numbers = pub_from_priv.public_numbers()

    key_size = priv_key.key_size
    modulus_hex = format(pub_numbers.n, "x")
    print(f"[*] Private key: {args.key}")
    print(f"    Key size: {key_size} bits")
    print(f"    Exponent: {pub_numbers.e}")
    print(f"    Modulus (first 32 hex): {modulus_hex[:32]}...")

    # 公開鍵の DER を取得
    pub_der = pub_from_priv.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print(f"    Public key DER: {len(pub_der)} bytes")

    # client_id がある場合は照合
    client_id_bytes = None
    if args.client_id:
        client_id_bytes = args.client_id.read_bytes()
        print(f"\n[*] Client ID: {args.client_id} ({len(client_id_bytes)} bytes)")
    elif args.challenge:
        client_id_bytes = extract_client_id_from_challenge(args.challenge)
        if client_id_bytes:
            print(
                f"\n[*] Client ID extracted from {args.challenge} ({len(client_id_bytes)} bytes)"
            )

    if client_id_bytes:
        pub_from_cid = extract_public_key_from_client_id(client_id_bytes)
        if pub_from_cid:
            cid_numbers = pub_from_cid.public_numbers()
            cid_modulus_hex = format(cid_numbers.n, "x")
            print(f"    CID public key size: {pub_from_cid.key_size} bits")
            print(f"    CID modulus (first 32 hex): {cid_modulus_hex[:32]}...")

            if pub_numbers.n == cid_numbers.n and pub_numbers.e == cid_numbers.e:
                print()
                print("=" * 60)
                print("[+] MATCH! Private key corresponds to client_id public key.")
                print("    This IS the CDM device private key.")
                print("=" * 60)
            else:
                print()
                print("=" * 60)
                print("[-] NO MATCH. Private key does NOT match client_id.")
                print("    This is NOT the CDM device private key.")
                print("=" * 60)
        else:
            print("[!] Could not extract public key from client_id")
    else:
        print()
        print("[*] No client_id provided. Cannot verify key correspondence.")
        print("    Use --challenge or --client-id to verify.")

    # 署名テスト
    print()
    print("[*] Self-sign test...")
    try:
        test_data = b"widevine_key_test"
        signature = priv_key.sign(test_data, padding.PKCS1v15(), hashes.SHA1())
        pub_from_priv.verify(signature, test_data, padding.PKCS1v15(), hashes.SHA1())
        print("[+] Sign/verify: OK (key is valid RSA key)")
    except Exception as e:
        print(f"[-] Sign/verify FAILED: {e}")


if __name__ == "__main__":
    main()
