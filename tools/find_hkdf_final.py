#!/usr/bin/env python3
"""
HKDF パラメータ探索 最終版
ログから正確に特定したペアリング:
  DH_compute_key → shared_secret = 052a8b...
  直後の AES_set_encrypt_key bits=128 key=97b99f4e88e8e73779aa20ac11877c5d
  直後の HMAC key=d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0

また別のペアリング:
  DH_generate_key の後
  AES_set_encrypt_key bits=128 key=0817065e29e6d1c8668473af9e13b3c2
  HMAC key=91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1
  → ただし DH_compute_key より前なのでこれは前回セッションのキャッシュ鍵か?
"""

import hashlib
import hmac as hmac_mod
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# 正確なペアリング (ログから特定)
PAIRS = [
    # (name, shared_secret, enc_key, hmac_key)
    (
        "Pair-A: DH_compute_key → 直後のAES-128/HMAC",
        bytes.fromhex(
            "052a8bfe9f1a1a9becdd67672338191b"
            "d7b5aff7fffe1f4cfbd97a0b14f8d59a"
            "f54697a0bc1cf96ad6f6e84af98ffd1c"
            "ebbc0fb5b04360878710f215f1261129"
            "652808fd11f5164d84a501b40e63ba91"
            "fcdcc932b6dbd61017099673f552db6e"
            "94ff19934bfdef21b9701c4c9d312b78"
            "f2cb8911e446313c2cb0567f7de865b3"
        ),
        bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d"),
        bytes.fromhex("d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0"),
    ),
    # HMAC key として別のペアリング候補
    (
        "Pair-B: DH_compute_key → HMAC直後",
        bytes.fromhex(
            "052a8bfe9f1a1a9becdd67672338191b"
            "d7b5aff7fffe1f4cfbd97a0b14f8d59a"
            "f54697a0bc1cf96ad6f6e84af98ffd1c"
            "ebbc0fb5b04360878710f215f1261129"
            "652808fd11f5164d84a501b40e63ba91"
            "fcdcc932b6dbd61017099673f552db6e"
            "94ff19934bfdef21b9701c4c9d312b78"
            "f2cb8911e446313c2cb0567f7de865b3"
        ),
        bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d"),
        bytes.fromhex("a4333e99a34eef3663f8e38e217e696949cd3bf57598c5c260fedb8997afa82b"),  # 最初のHMAC
    ),
]

found: list[str] = []


def check(label: str, derived: bytes, target_enc: bytes, target_hmac: bytes) -> bool:
    if len(derived) >= 48 and derived[:16] == target_enc and derived[16:48] == target_hmac:
        msg = f"[FULL MATCH] {label}"
        print(msg)
        found.append(msg)
        return True
    if len(derived) >= 16 and derived[:16] == target_enc:
        msg = f"[ENC_ONLY] {label}  rest={derived[16:32].hex()}"
        print(msg)
        found.append(msg)
    return False


HASH_ALGS = {
    "SHA1": hashes.SHA1(),
    "SHA256": hashes.SHA256(),
    "SHA384": hashes.SHA384(),
    "SHA512": hashes.SHA512(),
}

SALTS: list[tuple[str, bytes | None]] = [
    ("None", None),
    ("empty", b""),
    ("z16", b"\x00" * 16),
    ("z20", b"\x00" * 20),
    ("z32", b"\x00" * 32),
    ("z64", b"\x00" * 64),
]

INFOS: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("00", b"\x00"),
    ("01", b"\x01"),
    ("MSL", b"MSL"),
    ("enc", b"enc"),
    ("hmac", b"hmac"),
    ("session", b"session"),
    ("Netflix", b"Netflix"),
    ("AES", b"AES"),
    ("HMAC", b"HMAC"),
    ("scheme5", b"scheme5"),
    ("key_exp", b"key_expansion"),
    ("NF", b"Netflix MSL"),
    ("sign", b"sign"),
    ("encryption", b"encryption"),
    ("signing", b"signing"),
    ("ENC", b"ENC"),
    ("SIGN", b"SIGN"),
]

LENGTHS = [16, 32, 48, 64, 80, 128]

for pair_name, shared_secret, target_enc, target_hmac in PAIRS:
    print("=" * 70)
    print(f"Pair: {pair_name}")
    print(f"  shared: {shared_secret.hex()[:20]}...")
    print(f"  enc:    {target_enc.hex()}")
    print(f"  hmac:   {target_hmac.hex()}")
    print("=" * 70)

    ss_int = int(shared_secret.hex(), 16)
    INPUT_VARIANTS: list[tuple[str, bytes]] = [
        ("raw", shared_secret),
        ("pad128", ss_int.to_bytes(128, "big")),
        ("sha256", hashlib.sha256(shared_secret).digest()),
        ("sha384", hashlib.sha384(shared_secret).digest()),
        ("sha512", hashlib.sha512(shared_secret).digest()),
        ("rev", shared_secret[::-1]),
    ]

    print("HKDF 全組み合わせ:")
    for inp_name, inp_val in INPUT_VARIANTS:
        for hash_name, hash_alg in HASH_ALGS.items():
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
                            check(label, derived, target_enc, target_hmac)
                        except Exception:
                            pass

    print("HKDFExpand 全組み合わせ:")
    for inp_name, inp_val in INPUT_VARIANTS:
        for hash_name, hash_alg in HASH_ALGS.items():
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
                        check(label, derived, target_enc, target_hmac)
                    except Exception:
                        pass

    print("直接ハッシュ:")
    for inp_name, inp_val in INPUT_VARIANTS:
        for hash_fn, hash_name in [
            (hashlib.sha256, "SHA256"),
            (hashlib.sha384, "SHA384"),
            (hashlib.sha512, "SHA512"),
        ]:
            h = hash_fn(inp_val).digest()
            dummy = h + b"\x00" * 64
            check(f"hash_{hash_name}({inp_name})", dummy, target_enc, target_hmac)

    print("部分列比較:")
    for offset in range(0, len(shared_secret) - 15):
        if shared_secret[offset : offset + 16] == target_enc:
            print(f"  [MATCH] shared[{offset}:{offset+16}] == enc_key")

    print()

print()
print("=" * 70)
print("追加: ログの HMAC 直後の値からの逆算")
print("=" * 70)

# ログの時系列:
# 19:02:57.669 [HMAC] key=a4333e99a34eef3663f8e38e217e696949cd3bf57598c5c260fedb8997afa82b
# 19:02:57.672 [AES bits=128 key=97b99f4e...
# 19:02:57.674 [HMAC] key=d45443fa...
#
# a4333e... は DH 直後の最初の HMAC 呼び出し
# 97b99f... は AES-128
# d45443... は最終的な hmac_key
#
# 仮説: a4333e... = HKDF の中間 PRK?
# HMAC が HKDF の一部として呼ばれているなら...

HMAC_AFTER_DH = bytes.fromhex("a4333e99a34eef3663f8e38e217e696949cd3bf57598c5c260fedb8997afa82b")
ENC_AFTER_DH = bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d")
HMAC_FINAL = bytes.fromhex("d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0")
DH_SHARED_CORRECT = bytes.fromhex(
    "052a8bfe9f1a1a9becdd67672338191b"
    "d7b5aff7fffe1f4cfbd97a0b14f8d59a"
    "f54697a0bc1cf96ad6f6e84af98ffd1c"
    "ebbc0fb5b04360878710f215f1261129"
    "652808fd11f5164d84a501b40e63ba91"
    "fcdcc932b6dbd61017099673f552db6e"
    "94ff19934bfdef21b9701c4c9d312b78"
    "f2cb8911e446313c2cb0567f7de865b3"
)

print(f"HMAC after DH: {HMAC_AFTER_DH.hex()}")
print(f"ENC after DH:  {ENC_AFTER_DH.hex()}")
print(f"HMAC final:    {HMAC_FINAL.hex()}")
print()

# Tweak の HMAC フックは key_len=32 のとき記録
# HKDF の内部では HMAC-SHA256(key=salt, ikm) = PRK となる
# PRK = HMAC-SHA256(salt, IKM)
# この HMAC 呼び出しが a4333e... = PRK?

# verify: HMAC-SHA256(salt=?, DH_SHARED) = a4333e...
# salt が zeros_32 の場合:
for salt_val, salt_name in [(b"\x00" * 32, "z32"), (None, "None"), (b"", "empty")]:
    actual_salt = salt_val if salt_val is not None else b"\x00" * 32  # HKDF-Extract のデフォルト
    prk = hmac_mod.new(actual_salt, DH_SHARED_CORRECT, hashlib.sha256).digest()
    print(f"HMAC-SHA256(salt={salt_name}, DH_SHARED) = {prk.hex()}")
    if prk == HMAC_AFTER_DH:
        print(f"  [MATCH] PRK == HMAC_AFTER_DH with salt={salt_name}")

print()
# HMAC_AFTER_DH が PRK なら、expand で enc_key を導出
prk_candidate = HMAC_AFTER_DH
for info_name, info_val in [("empty", b""), ("01", b"\x01"), ("enc", b"enc")]:
    for out_len in [16, 32, 48]:
        try:
            hkdf_expand = HKDFExpand(
                algorithm=hashes.SHA256(),
                length=out_len,
                info=info_val,
            )
            derived = hkdf_expand.derive(prk_candidate)
            if derived[:16] == ENC_AFTER_DH:
                print(f"[PRK→ENC MATCH] HKDFExpand(prk=HMAC_AFTER_DH, info={info_name}, L={out_len})")
        except Exception:
            pass

print()
print("=" * 70)
print("結果サマリー")
print("=" * 70)
if found:
    print(f"一致 ({len(found)}件):")
    for f in found:
        print(f"  {f}")
else:
    print("一致なし")
    print()
    print("仮説: HKDF 以外の鍵導出を使用している可能性")
    print("  または: NFWebCrypto 内部で独自の鍵導出実装を使用")
    print()
    print("  次のアプローチ:")
    print("  1. NFWebCrypto の HKDF 関数を直接フック")
    print("  2. AES_set_encrypt_key の直前の call stack を調べる")
    print("  3. key33.6 (96B) の構造 [IV(16)+CT(48)+HMAC(32)] を仮定して")
    print("     appboot レスポンスから enc_key を復号する")
