#!/usr/bin/env python3
"""
Netflix iOS MSL HKDF パラメータ探索スクリプト
shared_secret から enc_key / hmac_key を導出するパラメータを特定する
"""

import hashlib
import hmac
import itertools

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# キャプチャ済みデータ
DH_SHARED_SECRET = bytes.fromhex(
    "76d784d86009dcc43eb5fdbe6bd53fdc6c4e3774a1c73e12468190735b11df7"
    "95f18c4917b79dad9ba5a14a4c9951437a4a85a3d2ab1099072f517389fd8cb"
    "7313092639a5d36bff8f819d034bceb9ed2f1369f2cb67a4667623b96832183"
    "3717a9563c768fd8b4313b08ee9bae7d661146e09d03b6d7989f9705d51ae92"
    "7275"
)

TARGET_ENC_KEY = bytes.fromhex("f4b5e0519e8022b2801768cdc88816d6")
TARGET_HMAC_KEY = bytes.fromhex(
    "b733c6b8bd3c2d02098c6c679daa9b138f9e0d9d76f95d2c85240937d53c66c9"
)

TARGET_BOTH_ENC_FIRST = TARGET_ENC_KEY + TARGET_HMAC_KEY  # 48 bytes
TARGET_BOTH_HMAC_FIRST = TARGET_HMAC_KEY + TARGET_ENC_KEY  # 48 bytes

print(f"shared_secret ({len(DH_SHARED_SECRET)} bytes): {DH_SHARED_SECRET.hex()}")
print(f"target enc_key  ({len(TARGET_ENC_KEY)} bytes): {TARGET_ENC_KEY.hex()}")
print(f"target hmac_key ({len(TARGET_HMAC_KEY)} bytes): {TARGET_HMAC_KEY.hex()}")
print()

found: list[str] = []


def check(label: str, derived: bytes) -> bool:
    if derived[:16] == TARGET_ENC_KEY and derived[16:48] == TARGET_HMAC_KEY:
        print(f"[ENC+HMAC MATCH] {label}")
        found.append(label)
        return True
    if derived[:32] == TARGET_HMAC_KEY and derived[32:48] == TARGET_ENC_KEY:
        print(f"[HMAC+ENC MATCH] {label}")
        found.append(label)
        return True
    if derived[:16] == TARGET_ENC_KEY:
        print(f"[ENC ONLY MATCH] {label}  derived={derived.hex()}")
        found.append(f"ENC_ONLY: {label}")
    if derived[16:48] == TARGET_HMAC_KEY:
        print(f"[HMAC ONLY (offset 16)] {label}  derived={derived.hex()}")
        found.append(f"HMAC_ONLY_16: {label}")
    if derived[:32] == TARGET_HMAC_KEY:
        print(f"[HMAC ONLY (offset 0)] {label}")
        found.append(f"HMAC_ONLY_0: {label}")
    return False


# ハッシュアルゴリズム候補
HASH_ALGS = {
    "SHA-1": hashes.SHA1(),
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
}

# info 候補
INFO_CANDIDATES: list[tuple[str, bytes]] = [
    ("b''", b""),
    ("b'AES'", b"AES"),
    ("b'HMAC'", b"HMAC"),
    ("b'Netflix'", b"Netflix"),
    ("b'MSL'", b"MSL"),
    ("b'enc'", b"enc"),
    ("b'sign'", b"sign"),
    ("b'encryption'", b"encryption"),
    ("b'hmac'", b"hmac"),
    ("b'session'", b"session"),
    ("b'\\x00'", b"\x00"),
    ("b'\\x01'", b"\x01"),
    ("b'\\x02'", b"\x02"),
    ("b'\\x00\\x01'", b"\x00\x01"),
    ("b'KEY'", b"KEY"),
    ("b'WRAP'", b"WRAP"),
    ("b'SIGN'", b"SIGN"),
    ("b'ENC'", b"ENC"),
    ("b'wrapping'", b"wrapping"),
    ("b'signing'", b"signing"),
    ("b'Netflix MSL'", b"Netflix MSL"),
    ("b'Netflix MSL enc'", b"Netflix MSL enc"),
    ("b'Netflix MSL hmac'", b"Netflix MSL hmac"),
]

# salt 候補
SALT_CANDIDATES: list[tuple[str, bytes | None]] = [
    ("salt=None", None),
    ("salt=b''", b""),
    ("salt=b'\\x00'*32", b"\x00" * 32),
    ("salt=b'\\x00'*16", b"\x00" * 16),
    ("salt=b'\\x00'*20", b"\x00" * 20),
]

# 出力長候補
OUTPUT_LENGTHS = [48, 16, 32, 64]

print("=" * 70)
print("1. HKDF (extract + expand) の全組み合わせ試行")
print("=" * 70)

for hash_name, hash_alg in HASH_ALGS.items():
    for salt_name, salt_val in SALT_CANDIDATES:
        for info_name, info_val in INFO_CANDIDATES:
            for out_len in OUTPUT_LENGTHS:
                try:
                    # cryptography の HKDF は salt=None と salt=b"" の挙動が異なる
                    hkdf = HKDF(
                        algorithm=hash_alg,
                        length=out_len,
                        salt=salt_val,
                        info=info_val,
                    )
                    derived = hkdf.derive(DH_SHARED_SECRET)
                    label = f"HKDF hash={hash_name} {salt_name} info={info_name} len={out_len}"
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("2. HKDFExpand のみ (PRK として shared_secret をそのまま使用)")
print("=" * 70)

for hash_name, hash_alg in HASH_ALGS.items():
    for info_name, info_val in INFO_CANDIDATES:
        for out_len in OUTPUT_LENGTHS:
            try:
                hkdf_expand = HKDFExpand(
                    algorithm=hash_alg,
                    length=out_len,
                    info=info_val,
                )
                derived = hkdf_expand.derive(DH_SHARED_SECRET)
                label = f"HKDFExpand hash={hash_name} info={info_name} len={out_len}"
                check(label, derived)
            except Exception:
                pass

print()
print("=" * 70)
print("3. 単純ハッシュ截断")
print("=" * 70)

# SHA-256(shared_secret)
h256 = hashlib.sha256(DH_SHARED_SECRET).digest()
print(f"SHA-256(shared_secret) = {h256.hex()}")
check("SHA-256(shared_secret)", h256 + b"\x00" * 16)

# SHA-384(shared_secret)
h384 = hashlib.sha384(DH_SHARED_SECRET).digest()
print(f"SHA-384(shared_secret) = {h384.hex()}")
check("SHA-384(shared_secret) enc[:16]+hmac[16:48]", h384)

# SHA-512(shared_secret)
h512 = hashlib.sha512(DH_SHARED_SECRET).digest()
print(f"SHA-512(shared_secret) = {h512.hex()}")
check("SHA-512(shared_secret) enc[:16]+hmac[16:48]", h512)

# SHA-1(shared_secret)
h1 = hashlib.sha1(DH_SHARED_SECRET).digest()
print(f"SHA-1(shared_secret) = {h1.hex()}")

print()
print("=" * 70)
print("4. shared_secret[:16] が enc_key か確認")
print("=" * 70)

print(f"shared_secret[:16] = {DH_SHARED_SECRET[:16].hex()}")
print(f"target enc_key     = {TARGET_ENC_KEY.hex()}")
if DH_SHARED_SECRET[:16] == TARGET_ENC_KEY:
    print("[MATCH] shared_secret[:16] == enc_key")
else:
    print("[NO MATCH]")

print()
print("=" * 70)
print("5. HMAC-SHA256 ベースの KDF")
print("=" * 70)

# HMAC-SHA256(key=shared_secret, msg=various_inputs)
hmac_inputs: list[tuple[str, bytes]] = [
    ("msg=b'\\x00'", b"\x00"),
    ("msg=b'\\x01'", b"\x01"),
    ("msg=b''", b""),
    ("msg=b'enc'", b"enc"),
    ("msg=b'hmac'", b"hmac"),
    ("msg=b'\\x00'*16", b"\x00" * 16),
    ("msg=b'\\x00'*32", b"\x00" * 32),
]

for msg_name, msg_val in hmac_inputs:
    h = hmac.new(DH_SHARED_SECRET, msg_val, hashlib.sha256).digest()
    label = f"HMAC-SHA256(key=shared_secret, {msg_name})"
    check(label + " [full]", h + b"\x00" * 16)

# HMAC-SHA256(key=SHA256(shared_secret), msg=various)
prk = hashlib.sha256(DH_SHARED_SECRET).digest()
for msg_name, msg_val in hmac_inputs:
    h = hmac.new(prk, msg_val, hashlib.sha256).digest()
    label = f"HMAC-SHA256(key=SHA256(shared_secret), {msg_name})"
    check(label + " [full]", h + b"\x00" * 16)

print()
print("=" * 70)
print("6. 2ステップ HKDF (enc と hmac を別々に導出)")
print("=" * 70)

for hash_name, hash_alg in HASH_ALGS.items():
    for salt_name, salt_val in SALT_CANDIDATES:
        for info_enc_name, info_enc_val in INFO_CANDIDATES:
            for info_hmac_name, info_hmac_val in INFO_CANDIDATES:
                if info_enc_name == info_hmac_name:
                    continue
                try:
                    hkdf_enc = HKDF(
                        algorithm=hash_alg,
                        length=16,
                        salt=salt_val,
                        info=info_enc_val,
                    )
                    enc = hkdf_enc.derive(DH_SHARED_SECRET)
                    if enc != TARGET_ENC_KEY:
                        continue
                    # enc が一致したら hmac も試す
                    hkdf_hmac = HKDF(
                        algorithm=hash_alg,
                        length=32,
                        salt=salt_val,
                        info=info_hmac_val,
                    )
                    hmac_key = hkdf_hmac.derive(DH_SHARED_SECRET)
                    label = (
                        f"2-step HKDF hash={hash_name} {salt_name} "
                        f"info_enc={info_enc_name} info_hmac={info_hmac_name}"
                    )
                    if enc == TARGET_ENC_KEY and hmac_key == TARGET_HMAC_KEY:
                        print(f"[FULL MATCH] {label}")
                        found.append(label)
                    elif enc == TARGET_ENC_KEY:
                        print(f"[ENC ONLY] {label}  hmac={hmac_key.hex()}")
                        found.append(f"ENC_ONLY_2STEP: {label}")
                except Exception:
                    pass

print()
print("=" * 70)
print("7. DH 秘密鍵から HKDF (dh_priv_key をソルトとして使用)")
print("=" * 70)

DH_PRIV_KEY = bytes.fromhex(
    "46fe2839cd0e88e509d75e2b818cfe0f836e9c409ff684bfa4d3f79f1ddd931"
    "690dedb9e379ce82f68db8d5b2acb10ae2c17f136010e3dca2698a593bbb91d"
    "10a833df9f5d88d07905f8b5e55b9db592fc1811c9f5da0d9eeb11d0b3c7966"
    "d1d6b1e2226f5b3c9359d05f48d97ee6c40623adc68d507fa871ab416786f6a"
    "c038"
)

extra_salts: list[tuple[str, bytes]] = [
    ("salt=dh_priv_key", DH_PRIV_KEY),
    ("salt=SHA256(dh_priv_key)", hashlib.sha256(DH_PRIV_KEY).digest()),
]

for salt_name, salt_val in extra_salts:
    for hash_name, hash_alg in HASH_ALGS.items():
        for info_name, info_val in INFO_CANDIDATES:
            for out_len in OUTPUT_LENGTHS:
                try:
                    hkdf = HKDF(
                        algorithm=hash_alg,
                        length=out_len,
                        salt=salt_val,
                        info=info_val,
                    )
                    derived = hkdf.derive(DH_SHARED_SECRET)
                    label = f"HKDF hash={hash_name} {salt_name} info={info_name} len={out_len}"
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("8. aes_key_history の他エントリとの関係確認")
print("=" * 70)

# 他の aes_key を確認
other_enc_keys = [
    "0817065e29e6d1c8668473af9e13b3c2",
    "97b99f4e88e8e73779aa20ac11877c5d",
]
print("shared_secret[:16]:", DH_SHARED_SECRET[:16].hex())
for k in other_enc_keys:
    print(f"other enc_key: {k}")

print()
print("=" * 70)
print("結果サマリー")
print("=" * 70)
if found:
    print(f"一致したパラメータ ({len(found)}件):")
    for f in found:
        print(f"  - {f}")
else:
    print("一致するパラメータは見つかりませんでした")
