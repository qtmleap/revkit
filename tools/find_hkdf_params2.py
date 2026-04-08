#!/usr/bin/env python3
"""
Netflix iOS MSL HKDF パラメータ探索 Part 2
- aes_key_history の全エントリを対象に試行
- pre_appboot の hmac_key も対象に追加
- 追加の info / salt パターンを試す
"""

import hashlib
import hmac as hmac_mod
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

DH_SHARED_SECRET = bytes.fromhex(
    "76d784d86009dcc43eb5fdbe6bd53fdc6c4e3774a1c73e12468190735b11df7"
    "95f18c4917b79dad9ba5a14a4c9951437a4a85a3d2ab1099072f517389fd8cb"
    "7313092639a5d36bff8f819d034bceb9ed2f1369f2cb67a4667623b96832183"
    "3717a9563c768fd8b4313b08ee9bae7d661146e09d03b6d7989f9705d51ae92"
    "7275"
)

# 全 aes_key_history エントリ (enc_key 候補)
ALL_ENC_KEYS = [
    bytes.fromhex("0817065e29e6d1c8668473af9e13b3c2"),
    bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d"),
    bytes.fromhex("f4b5e0519e8022b2801768cdc88816d6"),
]

# 全 hmac_key_history エントリ (hmac_key 候補)
ALL_HMAC_KEYS = [
    bytes.fromhex("19def2f90d06bc8dfd04a19dbd4588d4e7b8aa6ccacb200f9ae6acc49355917d"),
    bytes.fromhex("e60e376f37d7d962512aea2f29a353c28b0fb95b1e77c43baf7459b21d1df649"),
    bytes.fromhex("58c4e3d1cc2ce7bd73e846a1c3b00a9986aa039302d7bbf1a5508d5f9a49120f"),
    bytes.fromhex("91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1"),
    bytes.fromhex("38b2030dd55e3367290213ca0d16ee079524ccd24fb7221a52145fb6de016fd8"),
    bytes.fromhex("05ffd2d7407a6da255dfd89cde00504d1803ed81a8e5c17ea196c4498d01d825"),
    bytes.fromhex("d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0"),
    bytes.fromhex("b733c6b8bd3c2d02098c6c679daa9b138f9e0d9d76f95d2c85240937d53c66c9"),
]

found: list[str] = []


def check_any(label: str, derived: bytes) -> bool:
    """全 enc_key x hmac_key の組み合わせをチェック"""
    matched = False
    for enc in ALL_ENC_KEYS:
        for hmac_k in ALL_HMAC_KEYS:
            combined_eh = enc + hmac_k
            combined_he = hmac_k + enc
            if len(derived) >= len(combined_eh) and derived[: len(combined_eh)] == combined_eh:
                msg = f"[MATCH enc+hmac] {label}  enc={enc.hex()} hmac={hmac_k.hex()}"
                print(msg)
                found.append(msg)
                matched = True
            if len(derived) >= len(combined_he) and derived[: len(combined_he)] == combined_he:
                msg = f"[MATCH hmac+enc] {label}  hmac={hmac_k.hex()} enc={enc.hex()}"
                print(msg)
                found.append(msg)
                matched = True
            if len(derived) >= 16 and derived[:16] == enc:
                # enc だけ一致
                pass  # ノイズが多すぎるのでここでは出力しない
    return matched


def check_enc_only(label: str, derived: bytes) -> bool:
    for enc in ALL_ENC_KEYS:
        if len(derived) >= 16 and derived[:16] == enc:
            msg = f"[ENC MATCH] {label}  enc={enc.hex()}  full={derived.hex()}"
            print(msg)
            found.append(msg)
            return True
    return False


# ハッシュアルゴリズム
HASH_ALGS = {
    "SHA-1": hashes.SHA1(),
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
}

# info 候補 (拡張版)
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
    ("b'\\x03'", b"\x03"),
    ("b'\\x00\\x01'", b"\x00\x01"),
    ("b'\\x00\\x00\\x00\\x00'", b"\x00\x00\x00\x00"),
    ("b'KEY'", b"KEY"),
    ("b'WRAP'", b"WRAP"),
    ("b'SIGN'", b"SIGN"),
    ("b'ENC'", b"ENC"),
    ("b'wrapping'", b"wrapping"),
    ("b'signing'", b"signing"),
    ("b'Netflix MSL'", b"Netflix MSL"),
    ("b'Netflix MSL enc'", b"Netflix MSL enc"),
    ("b'Netflix MSL hmac'", b"Netflix MSL hmac"),
    ("b'keydata'", b"keydata"),
    ("b'wrapkey'", b"wrapkey"),
    ("b'enckey'", b"enckey"),
    ("b'hmackey'", b"hmackey"),
    ("b'masterkey'", b"masterkey"),
    ("b'sessionkey'", b"sessionkey"),
    ("b'NETFLIX'", b"NETFLIX"),
    ("b'netflix'", b"netflix"),
    ("int32(0)", struct.pack(">I", 0)),
    ("int32(1)", struct.pack(">I", 1)),
    ("int32(2)", struct.pack(">I", 2)),
    ("b'master_secret'", b"master_secret"),
    ("b'key_expansion'", b"key_expansion"),
    ("b'key expansion'", b"key expansion"),
]

# salt 候補 (拡張版)
SALT_CANDIDATES: list[tuple[str, bytes | None]] = [
    ("salt=None", None),
    ("salt=b''", b""),
    ("salt=b'\\x00'*32", b"\x00" * 32),
    ("salt=b'\\x00'*16", b"\x00" * 16),
    ("salt=b'\\x00'*20", b"\x00" * 20),
    ("salt=b'\\x00'*64", b"\x00" * 64),
    ("salt=b'\\x00'*128", b"\x00" * 128),
]

OUTPUT_LENGTHS = [16, 32, 48, 64, 80, 128]

print("=" * 70)
print("1. 全 enc_key/hmac_key 候補に対する HKDF 総当たり")
print("=" * 70)

for hash_name, hash_alg in HASH_ALGS.items():
    for salt_name, salt_val in SALT_CANDIDATES:
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
                    check_any(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("2. HKDFExpand のみ")
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
                check_any(label, derived)
            except Exception:
                pass

print()
print("=" * 70)
print("3. NIST SP800-108 Counter Mode KDF (HMAC-SHA256 ベース)")
print("=" * 70)


def nist_counter_kdf(
    prf_key: bytes,
    label: bytes,
    context: bytes,
    length: int,
    hash_alg: str = "sha256",
) -> bytes:
    """NIST SP800-108 Counter Mode"""
    result = b""
    counter = 1
    while len(result) < length:
        msg = struct.pack(">I", counter) + label + b"\x00" + context + struct.pack(">I", length * 8)
        result += hmac_mod.new(prf_key, msg, hash_alg).digest()
        counter += 1
    return result[:length]


nist_labels: list[tuple[str, bytes]] = [
    ("label=b''", b""),
    ("label=b'enc'", b"enc"),
    ("label=b'hmac'", b"hmac"),
    ("label=b'Netflix'", b"Netflix"),
    ("label=b'MSL'", b"MSL"),
    ("label=b'session'", b"session"),
]

nist_contexts: list[tuple[str, bytes]] = [
    ("ctx=b''", b""),
    ("ctx=b'\\x00'", b"\x00"),
]

for label_name, label_val in nist_labels:
    for ctx_name, ctx_val in nist_contexts:
        try:
            derived = nist_counter_kdf(DH_SHARED_SECRET, label_val, ctx_val, 48)
            lbl = f"NIST-KDF-HMAC-SHA256 {label_name} {ctx_name} len=48"
            check_any(lbl, derived)
        except Exception:
            pass

print()
print("=" * 70)
print("4. TLS PRF (HMAC-SHA256 ベース)")
print("=" * 70)


def tls_prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """TLS 1.2 PRF (P_SHA256)"""
    label_seed = label + seed

    def hmac_sha256(key: bytes, msg: bytes) -> bytes:
        return hmac_mod.new(key, msg, hashlib.sha256).digest()

    def p_hash(key: bytes, seed: bytes, length: int) -> bytes:
        result = b""
        a = seed
        while len(result) < length:
            a = hmac_sha256(key, a)
            result += hmac_sha256(key, a + seed)
        return result[:length]

    return p_hash(secret, label_seed, length)


tls_labels: list[tuple[str, bytes]] = [
    ("b'master secret'", b"master secret"),
    ("b'key expansion'", b"key expansion"),
    ("b'client finished'", b"client finished"),
    ("b''", b""),
    ("b'MSL'", b"MSL"),
    ("b'Netflix'", b"Netflix"),
    ("b'session'", b"session"),
]

tls_seeds: list[tuple[str, bytes]] = [
    ("seed=b''", b""),
    ("seed=b'\\x00'*32", b"\x00" * 32),
]

for lbl_name, lbl_val in tls_labels:
    for seed_name, seed_val in tls_seeds:
        try:
            derived = tls_prf(DH_SHARED_SECRET, lbl_val, seed_val, 48)
            label_str = f"TLS-PRF label={lbl_name} {seed_name} len=48"
            check_any(label_str, derived)
        except Exception:
            pass

print()
print("=" * 70)
print("5. SHA-256/SHA-512 の直接切り出し (全組み合わせ)")
print("=" * 70)

# SHA-256 から直接 enc_key を探す
h256 = hashlib.sha256(DH_SHARED_SECRET).digest()
h384 = hashlib.sha384(DH_SHARED_SECRET).digest()
h512 = hashlib.sha512(DH_SHARED_SECRET).digest()

for name, digest in [("SHA-256", h256), ("SHA-384", h384), ("SHA-512", h512)]:
    print(f"{name}(shared_secret) = {digest.hex()}")
    for enc in ALL_ENC_KEYS:
        for offset in range(len(digest) - 15):
            if digest[offset : offset + 16] == enc:
                print(f"  [ENC MATCH offset={offset}] enc={enc.hex()}")

print()
print("=" * 70)
print("6. Netflix MSL Java 実装の既知パターン試行")
print("=" * 70)

# Netflix MSL Java 実装では JWK_RSA を使うが、
# iOS DH の場合の参考として: DH shared secret を SHA-384 ハッシュして truncate
# enc_key = SHA-384[:16], hmac_key = SHA-384[16:48]
h384_bytes = hashlib.sha384(DH_SHARED_SECRET).digest()
print(f"SHA-384[:16]  = {h384_bytes[:16].hex()}")
print(f"SHA-384[16:48] = {h384_bytes[16:48].hex()}")
for enc in ALL_ENC_KEYS:
    if h384_bytes[:16] == enc:
        print(f"  [SHA-384[:16] ENC MATCH] {enc.hex()}")
    for hmac_k in ALL_HMAC_KEYS:
        if h384_bytes[16:48] == hmac_k:
            print(f"  [SHA-384[16:48] HMAC MATCH] {hmac_k.hex()}")

# HKDF-SHA384 系
print()
print("HKDF-SHA384, out=48:")
hkdf = HKDF(algorithm=hashes.SHA384(), length=48, salt=None, info=b"")
d = hkdf.derive(DH_SHARED_SECRET)
print(f"  derived = {d.hex()}")
check_enc_only("HKDF-SHA384 salt=None info=b'' len=48", d)

print()
print("=" * 70)
print("7. 先頭ゼロ補完バリアント (shared_secret が128バイト→256bitで奇数?)")
print("=" * 70)

# DH shared_secret を big-endian 整数として扱い、
# ゼロ補完して128バイトに揃える
# (すでに128バイトなので問題ないはずだが念のため)
print(f"shared_secret length: {len(DH_SHARED_SECRET)} bytes")

# 先頭に 0x00 を付けた 129 バイト版
ss_padded = b"\x00" + DH_SHARED_SECRET
h256_padded = hashlib.sha256(ss_padded).digest()
h384_padded = hashlib.sha384(ss_padded).digest()
print(f"SHA-256(b'\\x00' + shared_secret) = {h256_padded.hex()}")
print(f"SHA-384(b'\\x00' + shared_secret) = {h384_padded.hex()}")

for enc in ALL_ENC_KEYS:
    if h256_padded[:16] == enc:
        print(f"  [MATCH] SHA-256(padded)[:16] == {enc.hex()}")
    if h384_padded[:16] == enc:
        print(f"  [MATCH] SHA-384(padded)[:16] == {enc.hex()}")

# HKDF with padded shared_secret
for hash_name, hash_alg in HASH_ALGS.items():
    for info_name, info_val in [("b''", b""), ("b'enc'", b"enc"), ("b'session'", b"session")]:
        for salt_val, salt_name in [(None, "None"), (b"", "b''"), (b"\x00" * 32, "zeros32")]:
            try:
                hkdf = HKDF(
                    algorithm=hash_alg,
                    length=48,
                    salt=salt_val,
                    info=info_val,
                )
                derived = hkdf.derive(ss_padded)
                label = f"HKDF(padded_ss) hash={hash_name} salt={salt_name} info={info_name}"
                check_any(label, derived)
            except Exception:
                pass

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
    print()
    print("デバッグ情報: 各ハッシュの先頭16バイト vs ALL_ENC_KEYS")
    for hash_fn, name in [
        (hashlib.sha256, "SHA-256"),
        (hashlib.sha384, "SHA-384"),
        (hashlib.sha512, "SHA-512"),
    ]:
        h = hash_fn(DH_SHARED_SECRET).digest()
        print(f"  {name}[:16] = {h[:16].hex()}")
    print(f"  target enc keys: {[k.hex() for k in ALL_ENC_KEYS]}")
