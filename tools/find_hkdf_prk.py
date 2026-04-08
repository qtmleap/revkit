#!/usr/bin/env python3
"""
HMAC後の値を PRK として使う仮説の検証
ログ:
  DH_compute_key → shared=052a8b...
  HMAC key=a4333e... (DH の直後、key_len=32)  ← この HMAC の出力が PRK?
  AES-256 key=2f227e...
  AES-256 key=2f227e...
  AES-128 key=97b99f4e...  ← target enc_key
  HMAC key=d45443fa...     ← target hmac_key

仮説:
  1. PRK = HMAC-SHA256(salt=a4333e..., IKM=052a8b...)
  2. 出力 derive → enc_key=97b99f4e...
"""

import hashlib
import hmac as hmac_mod
import struct

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

HMAC_KEY_AFTER_DH = bytes.fromhex("a4333e99a34eef3663f8e38e217e696949cd3bf57598c5c260fedb8997afa82b")
AES_256_AFTER = bytes.fromhex("2f227e15497488f3476f4468b4d8cd00986a094f6e613051b79d6ad2d4d8cdc8")
TARGET_ENC = bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d")
TARGET_HMAC = bytes.fromhex("d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0")

print(f"DH_SHARED: {DH_SHARED.hex()[:20]}...")
print(f"HMAC_KEY_AFTER_DH: {HMAC_KEY_AFTER_DH.hex()}")
print(f"AES_256_AFTER: {AES_256_AFTER.hex()}")
print(f"TARGET_ENC: {TARGET_ENC.hex()}")
print(f"TARGET_HMAC: {TARGET_HMAC.hex()}")
print()

found: list[str] = []


def check(label: str, derived: bytes) -> bool:
    if len(derived) >= 16 and derived[:16] == TARGET_ENC:
        if len(derived) >= 48 and derived[16:48] == TARGET_HMAC:
            msg = f"[FULL MATCH] {label}"
            print(msg)
            found.append(msg)
            return True
        msg = f"[ENC_ONLY] {label}  rest={derived[16:32].hex()}"
        print(msg)
        found.append(msg)
    return False


print("=" * 70)
print("1. a4333e... を鍵として HMAC → PRK → ENC")
print("=" * 70)

# a4333e... を使って HKDF
for info_name, info_val in [("empty", b""), ("01", b"\x01"), ("enc", b"enc"), ("session", b"session")]:
    for out_len in [16, 32, 48, 64]:
        try:
            # a4333e... を PRK として HKDFExpand
            hkdf_expand = HKDFExpand(
                algorithm=hashes.SHA256(),
                length=out_len,
                info=info_val,
            )
            derived = hkdf_expand.derive(HMAC_KEY_AFTER_DH)
            check(f"HKDFExpand(PRK=a4333e,i={info_name},L={out_len})", derived)
        except Exception as e:
            pass

print()
print("=" * 70)
print("2. AES-256 key=2f227e... が DH derived key? その後 AES-ECB で enc_key を導出?")
print("=" * 70)

# AES-256(key=2f227e..., data=?) = 97b99f4e...
# data が何かを総当たりしてみる
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()

def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()

# 2f227e... (256-bit key) でデータを AES-ECB 暗号化して enc_key を得るか?
# ECB は 16 bytes ブロック → 出力[:16] が enc_key?
for data_candidate, data_name in [
    (b"\x00" * 16, "zeros_16"),
    (b"\x01" * 16, "ones_16"),
    (DH_SHARED[:16], "shared[:16]"),
    (DH_SHARED[16:32], "shared[16:32]"),
    (HMAC_KEY_AFTER_DH[:16], "hmac_after[:16]"),
    (TARGET_HMAC[:16], "target_hmac[:16]"),  # reverse: from enc to check
]:
    result = aes_ecb_encrypt(AES_256_AFTER, data_candidate)
    if result[:16] == TARGET_ENC:
        print(f"[MATCH] AES-256-ECB(key=2f227e, data={data_name})[:16] == TARGET_ENC")

# AES-256 で TARGET_ENC を復号して何かを得る?
dec_result = aes_ecb_decrypt(AES_256_AFTER, TARGET_ENC + b"\x00" * 16)
print(f"AES-256-ECB decrypt(2f227e, 97b99f4e...||zeros): {dec_result.hex()}")

print()
print("=" * 70)
print("3. a4333e... が appboot レスポンスから得た wrapping key?")
print("=" * 70)

# 仮説: appboot response の key33.6 (96 bytes) を a4333e... で AES-CBC 復号
import gzip
import cbor2
from pathlib import Path

RAWS_DIR = Path("/home/vscode/app/raws/ios/20260408/raw")

for res_file in sorted(RAWS_DIR.glob("res_*appboot*.bin"))[:10]:
    raw = res_file.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    try:
        obj = cbor2.loads(raw)
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

        iv = k6[:16]
        ct_48 = k6[16:64]
        hmac_part = k6[64:96]

        # a4333e... を AES-128 として使う (32 bytes → AES-256?)
        for wrap_key, wrap_name in [
            (HMAC_KEY_AFTER_DH[:16], "a4333e[:16]"),
            (HMAC_KEY_AFTER_DH[16:32], "a4333e[16:32]"),
            (AES_256_AFTER[:16], "2f227e[:16]"),
            (AES_256_AFTER[16:32], "2f227e[16:32]"),
        ]:
            try:
                cipher = Cipher(algorithms.AES(wrap_key), modes.CBC(iv), backend=default_backend())
                dec = cipher.decryptor()
                pt = dec.update(ct_48) + dec.finalize()
                pad_len = pt[-1]
                if 1 <= pad_len <= 16 and pt[-pad_len:] == bytes([pad_len]) * pad_len:
                    pt_unpad = pt[:-pad_len]
                    if pt_unpad[:16] == TARGET_ENC:
                        print(f"[MATCH] {res_file.name} AES-CBC-128({wrap_name})")
                        print(f"  pt={pt_unpad.hex()}")
            except Exception:
                pass

        # AES-256 で試す
        for wrap_key_256, wrap_name in [
            (HMAC_KEY_AFTER_DH, "a4333e (32B)"),
            (AES_256_AFTER[:32], "2f227e[:32]"),
        ]:
            try:
                cipher = Cipher(algorithms.AES(wrap_key_256), modes.CBC(iv), backend=default_backend())
                dec = cipher.decryptor()
                pt = dec.update(ct_48) + dec.finalize()
                pad_len = pt[-1]
                if 1 <= pad_len <= 16 and pt[-pad_len:] == bytes([pad_len]) * pad_len:
                    pt_unpad = pt[:-pad_len]
                    if pt_unpad[:16] == TARGET_ENC:
                        print(f"[MATCH-256] {res_file.name} AES-CBC-256({wrap_name})")
                        print(f"  pt={pt_unpad.hex()}")
            except Exception:
                pass

    except Exception:
        pass

print()
print("=" * 70)
print("4. SHA-384(DH_SHARED)[:16] で AES-CBC 復号")
print("=" * 70)

sha384_dh = hashlib.sha384(DH_SHARED).digest()
print(f"SHA384(DH_SHARED) = {sha384_dh.hex()}")

for res_file in sorted(RAWS_DIR.glob("res_*appboot*.bin"))[:10]:
    raw = res_file.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    try:
        obj = cbor2.loads(raw)
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

        for wrap_key, wrap_name in [
            (sha384_dh[:16], "sha384[:16]"),
            (sha384_dh[16:32], "sha384[16:32]"),
            (sha384_dh[32:48], "sha384[32:48]"),
        ]:
            iv = k6[:16]
            ct_48 = k6[16:64]
            try:
                cipher = Cipher(algorithms.AES(wrap_key), modes.CBC(iv), backend=default_backend())
                dec = cipher.decryptor()
                pt = dec.update(ct_48) + dec.finalize()
                pad_len = pt[-1]
                if 1 <= pad_len <= 16 and pt[-pad_len:] == bytes([pad_len]) * pad_len:
                    pt_unpad = pt[:-pad_len]
                    if pt_unpad[:16] == TARGET_ENC:
                        print(f"[MATCH] {res_file.name} AES-CBC({wrap_name})")
                        print(f"  pt={pt_unpad.hex()}")
            except Exception:
                pass
    except Exception:
        pass

print()
print("=" * 70)
print("5. 別のペアリングを試す: 0817 enc と 0817 直後の HMAC")
print("=" * 70)

# ログ 19:02:56.898 の状況:
# DH_generate_key で新しい鍵ペアを生成
# その後 (pre-COMPUTE) にも AES-128 key=0817... が出ている
# これは前回セッションのキャッシュ鍵が再利用されたものか?
# または DH_generate_key 後に何かが起きたのか?

# 19:02:56.886 DH_generate_key
# 19:02:56.898 AES-128 key=0817...
# 19:02:56.900 HMAC key=91f752...
# 19:02:56.901 HMAC key=38b203...
# 19:02:56.903 AES-256 (TFIT chain)
# ...
# 19:02:57.666 DH_compute_key → shared_secret=052a8b...
# 19:02:57.672 AES-128 key=97b99f4e...

# 0817 が DH_generate_key の後に出るのはなぜ?
# → DH キーペアを生成した後、前のセッションの cached key で MSL 送信?
# → そうなら 0817 は前回セッションの enc_key でこれ自体は HKDF 導出済み

# 別の可能性: DH_generate_key 後に server へ appboot リクエストを送信する前に
# 前回の master_token を検証するため 0817 を使う?

print("0817... は DH_generate_key 後, DH_compute_key 前の鍵 = 前回セッションのキャッシュ")
print("97b99f4e... は DH_compute_key 後の最初の新しいセッション鍵")
print()
print("正しいペアリング確認済み:")
print(f"  DH_shared_secret = 052a8b...")
print(f"  enc_key (DH直後) = 97b99f4e...")
print(f"  hmac_key (enc直後) = d45443fa...")
print()
print("しかし HKDF でこれらが再現できない")
print("→ NFWebCrypto は OpenSSL の HKDF 関数を使っているはずだが,")
print("  そのパラメータが標準的でない可能性")

print()
print("=" * 70)
print("6. OpenSSL EVP_HKDF を使った可能性 (内部でも HMAC が呼ばれる)")
print("=" * 70)

# OpenSSL の HKDF_extract: HMAC(salt, IKM)
# DH 後の最初の HMAC key=a4333e... は:
# a4333e... = salt として使われた?  または IKM?
# もし HKDF(IKM=DH_SHARED, salt=a4333e...) なら:
prk_test = hmac_mod.new(HMAC_KEY_AFTER_DH, DH_SHARED, hashlib.sha256).digest()
print(f"HMAC-SHA256(key=a4333e, msg=DH_SHARED) = PRK? {prk_test.hex()}")
# これを PRK として expand
for info_name, info_val in [("empty", b""), ("01", b"\x01"), ("enc", b"enc")]:
    for L in [16, 48]:
        try:
            hkdf_expand = HKDFExpand(
                algorithm=hashes.SHA256(),
                length=L,
                info=info_val,
            )
            derived = hkdf_expand.derive(prk_test)
            check(f"HKDFExpand(HMAC-SHA256(a4333e,DH_SHARED),i={info_name},L={L})", derived)
        except Exception:
            pass

# 逆: HMAC-SHA256(key=DH_SHARED, msg=a4333e...) = PRK?
prk_test2 = hmac_mod.new(DH_SHARED, HMAC_KEY_AFTER_DH, hashlib.sha256).digest()
print(f"HMAC-SHA256(key=DH_SHARED, msg=a4333e) = PRK? {prk_test2.hex()}")
for info_name, info_val in [("empty", b""), ("01", b"\x01"), ("enc", b"enc")]:
    for L in [16, 48]:
        try:
            hkdf_expand = HKDFExpand(
                algorithm=hashes.SHA256(),
                length=L,
                info=info_val,
            )
            derived = hkdf_expand.derive(prk_test2)
            check(f"HKDFExpand(HMAC-SHA256(DH_SHARED,a4333e),i={info_name},L={L})", derived)
        except Exception:
            pass

print()
print("=" * 70)
print("結果サマリー")
print("=" * 70)
if found:
    for f in found:
        print(f"  {f}")
else:
    print("一致なし")
    print()
    print("【重要な観察】")
    print("HMAC フックは HKDF-Extract の内部 HMAC も捕捉するはず。")
    print(f"DH 後最初の HMAC key: a4333e99... ({len(HMAC_KEY_AFTER_DH)} bytes)")
    print("しかし、これが HKDF-Extract の salt として機能していない")
    print()
    print("次のアプローチ: NFWebCrypto の HKDF エクスポート関数を直接フックして")
    print("入出力を確認する必要がある")
