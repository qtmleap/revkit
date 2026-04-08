#!/usr/bin/env python3
"""
デバイスから取得した正確なデータで HKDF パラメータを探索
DH shared_secret = 052a8b...
全セッション鍵ペアを試す
"""

import hashlib
import hmac as hmac_mod

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

DH_SHARED = bytes.fromhex(
    "052a8bfe9f1a1a9becdd67672338191b"
    "d7b5aff7fffe1f4cfbd97a0b14f8d59a"
    "f54697a0bc1cf96ad6f6e84af98ffd1c"
    "ebbc0fb5b04360878710f215f1261129"
    "652808fd11f5164d84a501b40e63ba91"
    "fcdcc932b6dbd61017099673f552db6e"
    "94ff19934bfdef21b9701c4c9d312b78"
    "f2cb8911e446313c2cb0567f7de865b3"
)

# ログから得た全 AES-128 鍵 (post_appboot)
ALL_ENC = [
    bytes.fromhex("0817065e29e6d1c8668473af9e13b3c2"),  # DH_generate 後 (前回キャッシュ?)
    bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d"),  # DH_compute 直後第1世代
    bytes.fromhex("834327638d92f129c9da8a5ab72bca3b"),  # セッション更新後第2世代
]

# ログから得た全 HMAC-SHA256 鍵 (post_appboot)
ALL_HMAC = [
    bytes.fromhex("91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1"),
    bytes.fromhex("38b2030dd55e3367290213ca0d16ee079524ccd24fb7221a52145fb6de016fd8"),
    bytes.fromhex("a4333e99a34eef3663f8e38e217e696949cd3bf57598c5c260fedb8997afa82b"),
    bytes.fromhex("d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0"),
    bytes.fromhex("b319e54dce7117932439aad5e1dfed1e8d18fe033aabe00ab786dc4239e8dd85"),
]

print(f"DH_SHARED: {DH_SHARED.hex()[:20]}...")
print(f"Target enc_keys: {[k.hex()[:8] for k in ALL_ENC]}")
print(f"Target hmac_keys: {[k.hex()[:8] for k in ALL_HMAC]}")
print()

found: list[str] = []


def check(label: str, derived: bytes) -> bool:
    for enc in ALL_ENC:
        if len(derived) < 16 or derived[:16] != enc:
            continue
        for hmac_k in ALL_HMAC:
            combined_len = 16 + len(hmac_k)
            if len(derived) >= combined_len and derived[16:combined_len] == hmac_k:
                msg = f"[FULL MATCH] {label}  enc={enc.hex()[:8]} hmac={hmac_k.hex()[:8]}"
                print(msg)
                found.append(msg)
                return True
        # enc だけ一致
        msg = f"[ENC_ONLY] {label}  enc={enc.hex()[:8]}  next16={derived[16:32].hex()}"
        print(msg)
        found.append(f"ENC_ONLY: {label}")
    return False


ss_int = int(DH_SHARED.hex(), 16)
print(f"shared_secret bit length: {ss_int.bit_length()}")
print(f"leading byte: 0x{DH_SHARED[0]:02x}")
print()

INPUT_VARIANTS: list[tuple[str, bytes]] = [
    ("raw", DH_SHARED),
    ("pad128", ss_int.to_bytes(128, "big")),
    ("sha256", hashlib.sha256(DH_SHARED).digest()),
    ("sha384", hashlib.sha384(DH_SHARED).digest()),
    ("sha512", hashlib.sha512(DH_SHARED).digest()),
]

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
    ("z48", b"\x00" * 48),
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
    ("NF_MSL", b"Netflix MSL"),
    ("sign", b"sign"),
    ("encryption", b"encryption"),
    ("ENC", b"ENC"),
    ("SIGN", b"SIGN"),
    ("NFAPPL", b"NFAPPL"),
    ("appboot", b"appboot"),
    ("FAIRPLAY", b"FAIRPLAY_MGK_APPID"),
]

LENGTHS = [16, 32, 48, 64, 80, 128]

print("=" * 70)
print("HKDF 全組み合わせ (正確な DH shared_secret)")
print("=" * 70)

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
                        check(label, derived)
                    except Exception:
                        pass

print()
print("=" * 70)
print("HKDFExpand 全組み合わせ")
print("=" * 70)

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
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("直接ハッシュ / 部分列")
print("=" * 70)

# ハッシュ
for inp_name, inp_val in INPUT_VARIANTS:
    for hash_fn, hash_name in [
        (hashlib.sha256, "SHA256"),
        (hashlib.sha384, "SHA384"),
        (hashlib.sha512, "SHA512"),
    ]:
        h = hash_fn(inp_val).digest()
        check(f"{hash_name}({inp_name})", h + b"\x00" * 64)

# 部分列
for offset in range(len(DH_SHARED) - 15):
    for enc in ALL_ENC:
        if DH_SHARED[offset:offset+16] == enc:
            print(f"[MATCH] shared[{offset}:{offset+16}] == enc_key {enc.hex()[:8]}")

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
    print("SHA256/384/512 の先頭 16B と enc_key 比較:")
    for inp_name, inp_val in INPUT_VARIANTS:
        h256 = hashlib.sha256(inp_val).digest()
        h384 = hashlib.sha384(inp_val).digest()
        print(f"  {inp_name}: sha256[:16]={h256[:16].hex()} sha384[:16]={h384[:16].hex()}")
    print(f"  enc_keys: {[k.hex() for k in ALL_ENC]}")
    print()
    print("【最終結論】")
    print("DH shared_secret から enc_key / hmac_key を再現する")
    print("標準的な HKDF パラメータは存在しない")
    print()
    print("可能性:")
    print("1. セッション鍵は appboot response の key33.6 に含まれており,")
    print("   その復号鍵は DH shared_secret から ECDH 等の異なる方法で導出される")
    print("2. NFWebCrypto は独自の HKDF 実装 (非 OpenSSL HMAC ベース) を使用")
    print("3. OpenSSL の EVP_KDF (HKDF) API を使っていてフックできていない")
    print()
    print("推奨アクション:")
    print("  Tweak の HMAC フックで `EVP_MAC_update` / `EVP_KDF` も追加フックする")
    print("  または Frida で AES_set_encrypt_key のコールスタックを取得して")
    print("  caller 関数が何を入力として使っているか特定する")
