#!/usr/bin/env python3
"""
appboot response の key33.6 (96 bytes) から enc_key を逆算
19時台のセッションの key33.6 を AES-CBC で復号して enc_key を得るための wrap_key を特定する

ログから判明した値:
  DH pub_key (new session): 9349f3...
  DH shared_secret: 052a8b...
  enc_key (target): 97b99f4e...
  hmac_key (target): d45443fa...

19時台のキャプチャがないため、07時台のどのレスポンスが対応するか不明
→ 全 key33.6 を全候補鍵で試す

また、DH pub_key から req を特定する試み:
  req.key33.6 (464 bytes) に DH pub_key が含まれているはず
  ただし RSA-4096 暗号化されているので見えない
  → req の client nonce (16 bytes) から server nonce 付きで hash して wrap_key を導出?
"""

import gzip
import hashlib
import hmac as hmac_mod
from pathlib import Path

import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

RAWS_DIR = Path("/home/vscode/app/raws/ios/20260408/raw")

# 19時セッションの情報
DH_PRIV_NEW = bytes.fromhex(
    "4c61046cb05493fcea0b316122849fe0"
    "21cac93bc3858c8c6b43a1fc8329b9be"
    "4ac7d73da8253e491c1b0c8cabf1f614"
    "1144b8cd448821636ceec04105d88b2e"
    "d6a2180994ee41a7be1a7eb0c4f8b866"
    "bc2796e08dd9d2c4b393727e915fa680"
    "dfef7b8115f2a7b3416418048c0a9c9b"
    "4c0ccc1a7a79d38e3cdd6e9f0539020f"
)
DH_PUB_NEW = bytes.fromhex(
    "9349f329e100d6fb1a9eb2e81666af56"
    "32c408bb395f56191d1a125a0d1675b1"
    "a83d623f00dd7e06b4dd296083fd29ee"
    "c44bb7805f6bb0b7ff90e6417eb63ece"
    "b05840dd9e5f1d5991a59997ca866ef2"
    "b6d767418fe147656d4a32b7c2e24b95"
    "1952c423291b14a00d245915460585d5"
    "f93f98ef8755873e9792ea0534be15e5"
)
DH_SHARED_NEW = bytes.fromhex(
    "052a8bfe9f1a1a9becdd67672338191b"
    "d7b5aff7fffe1f4cfbd97a0b14f8d59a"
    "f54697a0bc1cf96ad6f6e84af98ffd1c"
    "ebbc0fb5b04360878710f215f1261129"
    "652808fd11f5164d84a501b40e63ba91"
    "fcdcc932b6dbd61017099673f552db6e"
    "94ff19934bfdef21b9701c4c9d312b78"
    "f2cb8911e446313c2cb0567f7de865b3"
)
TARGET_ENC = bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d")
TARGET_HMAC = bytes.fromhex("d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0")

# ログで記録された全ての 32-byte HMAC 鍵 (DH後)
LOGGED_HMAC_KEYS_AFTER_DH = [
    "a4333e99a34eef3663f8e38e217e696949cd3bf57598c5c260fedb8997afa82b",
    "d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0",
    "b319e54dce7117932439aad5e1dfed1e8d18fe033aabe00ab786dc4239e8dd85",
]

print(f"DH pub new: {DH_PUB_NEW.hex()[:20]}...")
print(f"DH shared new: {DH_SHARED_NEW.hex()[:20]}...")
print(f"Target enc_key: {TARGET_ENC.hex()}")
print(f"Target hmac_key: {TARGET_HMAC.hex()}")
print()

# 07時台の appboot req から DH pub_key が 9349f3... に一致するものを探す
# (RSA 暗号化されているため直接は見えないが、同一 DH グループなら p と g が一致するはず)

# 全 req の key33 sub-key を確認
print("=" * 70)
print("07時台の appboot req から DH 鍵の手がかりを探す")
print("=" * 70)

def try_decode_cbor(data: bytes) -> dict | None:
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except Exception:
            return None
    try:
        return cbor2.loads(data)
    except Exception:
        return None


def aes_cbc_decrypt_try(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(ct) + dec.finalize()
    except Exception:
        return None


def pkcs7_unpad(data: bytes) -> bytes | None:
    if not data:
        return None
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return data[:-pad_len]


# 全 wrap_key 候補 (128-bit AES 用)
sha256_new = hashlib.sha256(DH_SHARED_NEW).digest()
sha384_new = hashlib.sha384(DH_SHARED_NEW).digest()
sha512_new = hashlib.sha512(DH_SHARED_NEW).digest()

WRAP_KEY_CANDIDATES_16: list[tuple[str, bytes]] = [
    ("sha256[:16]", sha256_new[:16]),
    ("sha256[16:32]", sha256_new[16:32]),
    ("sha384[:16]", sha384_new[:16]),
    ("sha384[16:32]", sha384_new[16:32]),
    ("sha384[32:48]", sha384_new[32:48]),
    ("sha512[:16]", sha512_new[:16]),
    ("sha512[16:32]", sha512_new[16:32]),
    ("sha512[32:48]", sha512_new[32:48]),
    ("sha512[48:64]", sha512_new[48:64]),
    ("shared[:16]", DH_SHARED_NEW[:16]),
    ("shared[16:32]", DH_SHARED_NEW[16:32]),
]

# HKDF 候補
HASH_ALGS = {
    "SHA256": hashes.SHA256(),
    "SHA384": hashes.SHA384(),
}
for hash_name, hash_alg in HASH_ALGS.items():
    for salt in [None, b"", b"\x00" * 32]:
        for info in [b"", b"wrap", b"enc", b"session", b"MSL"]:
            try:
                hkdf = HKDF(algorithm=hash_alg, length=16, salt=salt, info=info)
                k = hkdf.derive(DH_SHARED_NEW)
                label = f"HKDF({hash_name},s={repr(salt)[:10]},i={repr(info)})"
                WRAP_KEY_CANDIDATES_16.append((label, k))
            except Exception:
                pass

# logged HMAC keys の先頭 16B も候補として追加
for hex_key in LOGGED_HMAC_KEYS_AFTER_DH:
    kb = bytes.fromhex(hex_key)
    WRAP_KEY_CANDIDATES_16.append((f"logged_hmac_{hex_key[:8]}[:16]", kb[:16]))
    WRAP_KEY_CANDIDATES_16.append((f"logged_hmac_{hex_key[:8]}[16:32]", kb[16:32]))

print(f"Total wrap_key candidates: {len(WRAP_KEY_CANDIDATES_16)}")
print()

# 全 appboot レスポンスの key33.6 で試す
matches_found = []

for res_file in sorted(RAWS_DIR.glob("res_*appboot*.bin")):
    raw = res_file.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    try:
        obj = try_decode_cbor(raw)
        if obj is None:
            continue
        k33 = obj.get(33)
        if isinstance(k33, bytes):
            inner = cbor2.loads(k33)
        elif isinstance(k33, dict):
            inner = k33
        else:
            continue
        k6 = inner.get(6)
        if not isinstance(k6, bytes) or len(k6) != 96:
            continue

        # 仮説 C: IV(16) + CT(48) + HMAC(32)
        iv = k6[:16]
        ct_48 = k6[16:64]

        for wrap_name, wrap_key in WRAP_KEY_CANDIDATES_16:
            pt = aes_cbc_decrypt_try(wrap_key, iv, ct_48)
            if pt is None:
                continue
            pt_unpad = pkcs7_unpad(pt)
            if pt_unpad is None:
                continue
            if len(pt_unpad) >= 16 and pt_unpad[:16] == TARGET_ENC:
                msg = f"[MATCH] {res_file.name}: wrap_key={wrap_name} pt={pt_unpad.hex()}"
                print(msg)
                matches_found.append(msg)

        # 仮説 B: CT(64) + HMAC(32), IV=zeros or IV=first block
        ct_64 = k6[:64]
        for iv_candidate, iv_name in [(b"\x00" * 16, "zeros"), (k6[:16], "k6[:16]")]:
            for wrap_name, wrap_key in WRAP_KEY_CANDIDATES_16:
                pt = aes_cbc_decrypt_try(wrap_key, iv_candidate, ct_64)
                if pt is None:
                    continue
                pt_unpad = pkcs7_unpad(pt)
                if pt_unpad is None:
                    continue
                if len(pt_unpad) >= 16 and pt_unpad[:16] == TARGET_ENC:
                    msg = f"[MATCH-B] {res_file.name}: iv={iv_name} wrap_key={wrap_name}"
                    print(msg)
                    matches_found.append(msg)

    except Exception:
        pass

print()
print("=" * 70)
print("結果")
print("=" * 70)
if matches_found:
    for m in matches_found:
        print(f"  {m}")
else:
    print("一致なし")
    print()
    print("【最終仮説】")
    print("NFWebCrypto は DH shared_secret から MSL セッション鍵を")
    print("HKDF 以外の方法 (独自実装または OpenSSL 独自 API) で導出している")
    print()
    print("可能性1: PKCS#3 DH Agreed Value として共有秘密を使い,")
    print("         その後 AES Key Wrap (RFC 3394) で appboot レスポンスから")
    print("         セッション鍵を取り出す")
    print()
    print("可能性2: ECDH (楕円曲線) が DH の代わりに使われていて,")
    print("         shared_secret の計算方法が異なる")
    print()
    print("可能性3: Netflix MSL の scheme 5 固有の DH 鍵導出関数が")
    print("         OpenSSL の HMAC を使わない内部実装を持つ")
    print()
    print("→ NFWebCrypto の HKDF エクスポートシンボルを直接フックする")
    print("  または Frida で AES_set_encrypt_key のコールスタックを取得する")
    print("  ことで、鍵導出の入力パラメータを特定できる可能性がある")
