#!/usr/bin/env python3
"""
HKDF パラメータ徹底探索
- aes_key_history と hmac_key_history の全ペアを試す
- DH shared_secret を入力に全 HKDF パラメータを試す
- 結果を全てレポート
"""

import hashlib
import hmac as hmac_mod
import json
from itertools import product

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

with open("/home/vscode/app/raws/msl_keys.json") as f:
    keys = json.load(f)

DH_SHARED = bytes.fromhex(keys["dh_shared_secret"])
ss_int = int(keys["dh_shared_secret"], 16)

# 全 enc_key (post_appboot)
ENC_POST = [bytes.fromhex(e["key"]) for e in keys["aes_key_history"] if e["phase"] == "post_appboot"]
ENC_UNIQUE = list(dict.fromkeys(k.hex() for k in ENC_POST))
# 全 hmac_key (post_appboot)
HMAC_POST = [bytes.fromhex(e["key"]) for e in keys["hmac_key_history"] if e["phase"] == "post_appboot"]
HMAC_UNIQUE = list(dict.fromkeys(k.hex() for k in HMAC_POST))

print(f"Target enc_keys  ({len(ENC_UNIQUE)}): {ENC_UNIQUE}")
print(f"Target hmac_keys ({len(HMAC_UNIQUE)}): {HMAC_UNIQUE}")
print(f"DH shared_secret (1023-bit): {DH_SHARED.hex()[:32]}...")
print()

# DH shared_secret のバリエーション
INPUT_VARIANTS: list[tuple[str, bytes]] = [
    ("raw", DH_SHARED),
    ("pad128", ss_int.to_bytes(128, "big")),
    ("sha256", hashlib.sha256(DH_SHARED).digest()),
    ("sha384", hashlib.sha384(DH_SHARED).digest()),
    ("sha512", hashlib.sha512(DH_SHARED).digest()),
    ("rev", DH_SHARED[::-1]),
]

HASH_ALGS: list[tuple[str, hashes.HashAlgorithm]] = [
    ("SHA1", hashes.SHA1()),
    ("SHA256", hashes.SHA256()),
    ("SHA384", hashes.SHA384()),
    ("SHA512", hashes.SHA512()),
]

SALTS: list[tuple[str, bytes | None]] = [
    ("None", None),
    ("empty", b""),
    ("z16", b"\x00" * 16),
    ("z20", b"\x00" * 20),
    ("z32", b"\x00" * 32),
    ("z48", b"\x00" * 48),
    ("z64", b"\x00" * 64),
    ("SHA256empty", hashlib.sha256(b"").digest()),
]

INFOS: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("01", b"\x01"),
    ("MSL", b"MSL"),
    ("enc", b"enc"),
    ("hmac", b"hmac"),
    ("session", b"session"),
    ("Netflix", b"Netflix"),
    ("NFAPPL", b"NFAPPL"),
    ("AES", b"AES"),
    ("HMAC", b"HMAC"),
    ("scheme5", b"scheme5"),
    ("dh1024", b"dh1024"),
    ("appboot", b"appboot"),
    ("fair", b"FAIRPLAY_MGK_APPID"),
    ("key_exp", b"key_expansion"),
    ("NF", b"Netflix MSL"),
    ("WrapEnc", b"WrapEnc"),
    ("WrapMac", b"WrapMac"),
]

LENGTHS = [16, 32, 48, 64]

match_enc_only: list[str] = []
match_full: list[str] = []


def test(label: str, derived: bytes) -> None:
    for enc_hex in ENC_UNIQUE:
        enc = bytes.fromhex(enc_hex)
        if len(derived) >= 16 and derived[:16] == enc:
            for hmac_hex in HMAC_UNIQUE:
                hmac_k = bytes.fromhex(hmac_hex)
                if len(derived) >= 48 and derived[16:48] == hmac_k:
                    msg = f"[FULL MATCH] {label}  enc={enc_hex[:8]} hmac={hmac_hex[:8]}"
                    print(msg)
                    match_full.append(msg)
                    return
                if len(derived) >= 32 and derived[16:48] == hmac_k:
                    msg = f"[FULL MATCH 32] {label}  enc={enc_hex[:8]} hmac={hmac_hex[:8]}"
                    print(msg)
                    match_full.append(msg)
                    return
            msg = f"[ENC_ONLY] {label}  enc={enc_hex[:8]} rest={derived[16:32].hex()}"
            print(msg)
            match_enc_only.append(msg)


print("=" * 70)
print("HKDF 全組み合わせ")
print("=" * 70)

total = len(HASH_ALGS) * len(SALTS) * len(INFOS) * len(INPUT_VARIANTS) * len(LENGTHS)
print(f"Total combinations: {total}")

for inp_name, inp_val in INPUT_VARIANTS:
    for hash_name, hash_alg in HASH_ALGS:
        for salt_name, salt_val in SALTS:
            for info_name, info_val in INFOS:
                for out_len in LENGTHS:
                    try:
                        hkdf = HKDF(
                            algorithm=hash_alg,
                            length=out_len,
                            salt=salt_val,
                            info=info_val,
                        )
                        derived = hkdf.derive(inp_val)
                        label = f"HKDF({inp_name},h={hash_name},s={salt_name},i={info_name},L={out_len})"
                        test(label, derived)
                    except Exception:
                        pass

print()
print("=" * 70)
print("HKDFExpand 全組み合わせ")
print("=" * 70)

for inp_name, inp_val in INPUT_VARIANTS:
    for hash_name, hash_alg in HASH_ALGS:
        for info_name, info_val in INFOS:
            for out_len in LENGTHS:
                try:
                    hkdf_expand = HKDFExpand(
                        algorithm=hash_alg,
                        length=out_len,
                        info=info_val,
                    )
                    derived = hkdf_expand.derive(inp_val)
                    label = f"HKDFExpand({inp_name},h={hash_name},i={info_name},L={out_len})"
                    test(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("HMAC チェーン KDF")
print("=" * 70)

# RFC 5869 HKDF の手動実装 (extract + expand を分けて確認)
def hkdf_extract(salt: bytes | None, ikm: bytes, hash_name: str) -> bytes:
    """HKDF-Extract"""
    hash_fn = hashlib.sha256 if hash_name == "SHA256" else hashlib.sha384 if hash_name == "SHA384" else hashlib.sha512
    hash_len = hash_fn(b"").digest_size
    if salt is None:
        salt = b"\x00" * hash_len
    return hmac_mod.new(salt, ikm, hash_name.lower().replace("sha", "sha")).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str) -> bytes:
    """HKDF-Expand"""
    hash_fn_name = "sha256" if hash_name == "SHA256" else "sha384" if hash_name == "SHA384" else "sha512"
    result = b""
    t = b""
    counter = 1
    while len(result) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hash_fn_name).digest()
        result += t
        counter += 1
    return result[:length]

# HKDF-Extract ステップの PRK を確認
for inp_name, inp_val in INPUT_VARIANTS:
    for hash_name, _ in HASH_ALGS:
        for salt_name, salt_val in SALTS:
            try:
                prk = hkdf_extract(salt_val, inp_val, hash_name)
                # PRK の先頭 16 バイトが enc_key か?
                for enc_hex in ENC_UNIQUE:
                    if prk[:16] == bytes.fromhex(enc_hex):
                        print(f"[PRK ENC MATCH] hkdf_extract({inp_name},s={salt_name},h={hash_name})[:16] == {enc_hex[:8]}")
            except Exception:
                pass

print()
print("=" * 70)
print("結果サマリー")
print("=" * 70)
if match_full:
    print(f"完全一致 ({len(match_full)}件):")
    for m in match_full:
        print(f"  {m}")
elif match_enc_only:
    print(f"enc_key のみ一致 ({len(match_enc_only)}件):")
    for m in match_enc_only[:20]:
        print(f"  {m}")
else:
    print("一致なし")
    print()
    print("【結論】msl_keys.json の dh_shared_secret と session_enc_key は")
    print("  同一のセッションのものではない (タイムスタンプ不整合)")
    print()
    print("  対策: Tweak の実装改善が必要")
    print("  - DH_compute_key → AES_set_encrypt_key の呼び出し順序を記録")
    print("  - または DH 鍵と AES 鍵をアトミックに1セッション分だけ記録")
    print()
    print("  代替案: appboot response の key33.6 の暗号化アルゴリズムを特定")
    print("  - 96 bytes のうち [IV(16)+CT(48)+HMAC(32)] の可能性")
    print("  - 復号鍵は DH shared_secret から何らかの方法で導出")
    print("  - ただし DH と AES 鍵のペアリングが確立されないと試行不可能")
