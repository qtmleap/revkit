#!/usr/bin/env python3
"""
正しいペアリングデータを使った HKDF パラメータ探索
ログから特定した正確なデータ:
  DH shared_secret (実際): 052a8bfe9f1a1a9b...
  enc_key: 0817065e29e6d1c8668473af9e13b3c2
  hmac_key: 91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1
"""

import hashlib
import hmac as hmac_mod
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# ログから判明した正確なペアリング
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

TARGET_ENC = bytes.fromhex("0817065e29e6d1c8668473af9e13b3c2")
TARGET_HMAC = bytes.fromhex(
    "91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1"
)

print(f"Correct shared_secret: {DH_SHARED_CORRECT.hex()[:32]}...")
print(f"Target enc_key:        {TARGET_ENC.hex()}")
print(f"Target hmac_key:       {TARGET_HMAC.hex()}")
print(f"shared_secret length:  {len(DH_SHARED_CORRECT)} bytes")
print(f"shared_secret bit len: {int(DH_SHARED_CORRECT.hex(), 16).bit_length()}")
print()

# ともに `msl_keys.json` から読んだ dh_pub_key と別物であることを確認
# msl_keys.json の dh_shared_secret: 76d784d86009dcc4...
# 実際の shared_secret: 052a8bfe9f1a1a9b...

found: list[str] = []


def check(label: str, derived: bytes) -> bool:
    if len(derived) >= 48 and derived[:16] == TARGET_ENC and derived[16:48] == TARGET_HMAC:
        msg = f"[FULL MATCH] {label}"
        print(msg)
        found.append(msg)
        return True
    if len(derived) >= 16 and derived[:16] == TARGET_ENC:
        msg = f"[ENC_ONLY] {label}  rest={derived[16:32].hex()}"
        print(msg)
        found.append(msg)
        return False
    return False


ss_int = int(DH_SHARED_CORRECT.hex(), 16)
INPUT_VARIANTS: list[tuple[str, bytes]] = [
    ("raw", DH_SHARED_CORRECT),
    ("pad128", ss_int.to_bytes(128, "big")),
    ("sha256", hashlib.sha256(DH_SHARED_CORRECT).digest()),
    ("sha384", hashlib.sha384(DH_SHARED_CORRECT).digest()),
    ("sha512", hashlib.sha512(DH_SHARED_CORRECT).digest()),
    ("rev", DH_SHARED_CORRECT[::-1]),
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
    ("SHA256empty", hashlib.sha256(b"").digest()),
]

INFOS: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("01", b"\x01"),
    ("00", b"\x00"),
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
    ("sign", b"sign"),
    ("encryption", b"encryption"),
    ("signing", b"signing"),
    ("SIGN", b"SIGN"),
    ("ENC", b"ENC"),
    ("session_key", b"session_key"),
    ("masterkey", b"masterkey"),
    ("0000", b"\x00\x00\x00\x00"),
    ("0001", b"\x00\x00\x00\x01"),
    ("0002", b"\x00\x00\x00\x02"),
]

LENGTHS = [16, 32, 48, 64, 80, 128]

print("=" * 70)
print("1. HKDF 全組み合わせ (正しいペアリング使用)")
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
print("2. HKDFExpand のみ")
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
print("3. 直接ハッシュ")
print("=" * 70)

for inp_name, inp_val in INPUT_VARIANTS:
    for hash_fn, hash_name in [
        (hashlib.sha256, "SHA256"),
        (hashlib.sha384, "SHA384"),
        (hashlib.sha512, "SHA512"),
        (hashlib.sha1, "SHA1"),
    ]:
        h = hash_fn(inp_val).digest()
        check(f"hash_{hash_name}({inp_name})", h + b"\x00" * 64)

print()
print("=" * 70)
print("4. 部分列比較")
print("=" * 70)

for offset in range(0, len(DH_SHARED_CORRECT) - 15):
    candidate = DH_SHARED_CORRECT[offset : offset + 16]
    if candidate == TARGET_ENC:
        print(f"[MATCH] shared_correct[{offset}:{offset+16}] == enc_key")

print()
print("=" * 70)
print("5. HMAC ベース KDF")
print("=" * 70)

hmac_inputs_for_kdf: list[tuple[str, bytes]] = [
    ("key=shared,msg=b''", (DH_SHARED_CORRECT, b"")),
    ("key=shared,msg=b'\\x01'", (DH_SHARED_CORRECT, b"\x01")),
    ("key=SHA256,msg=b''", (hashlib.sha256(DH_SHARED_CORRECT).digest(), b"")),
    ("key=z32,msg=shared", (b"\x00" * 32, DH_SHARED_CORRECT)),
    ("key=z20,msg=shared", (b"\x00" * 20, DH_SHARED_CORRECT)),
]

for label, (key_val, msg_val) in hmac_inputs_for_kdf:
    for hash_fn, hash_name in [
        (hashlib.sha256, "sha256"),
        (hashlib.sha384, "sha384"),
        (hashlib.sha512, "sha512"),
        (hashlib.sha1, "sha1"),
    ]:
        h = hmac_mod.new(key_val, msg_val, hash_fn).digest()
        check(f"HMAC-{hash_name.upper()} {label}", h + b"\x00" * 64)

print()
print("=" * 70)
print("6. appboot レスポンス key33.6 の復号 (正しい shared_secret で)")
print("=" * 70)

import gzip
import cbor2
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

RAWS_DIR = Path("/home/vscode/app/raws/ios/20260408/raw")


def aes_cbc_decrypt_nopad(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
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


# appboot req/res ペアを解析してセッション鍵を取り出す
# DH generate_key が 19:02:56.886 に呼ばれた = req の直前
# そのセッションの req ファイルを探す (19:02 台)

# 19:02 台のファイルを探す → res_4_appboot_2026-04-08T07-52-22-999Z.bin は違う
# ログは 2026-04-08 19:02 なので、別のキャプチャセッション
# 19時台のキャプチャファイルがあるか確認

all_res = list(RAWS_DIR.glob("res_*appboot*.bin"))
print(f"appboot res files: {len(all_res)}")

# SHA256(shared_correct) の先頭 16 bytes で全 key33.6 を AES-CBC 復号してみる
sha256_correct = hashlib.sha256(DH_SHARED_CORRECT).digest()
sha384_correct = hashlib.sha384(DH_SHARED_CORRECT).digest()

print(f"SHA256(correct_shared)[:16] = {sha256_correct[:16].hex()}")
print(f"SHA384(correct_shared)[:16] = {sha384_correct[:16].hex()}")
print()

for res_file in sorted(all_res)[:5]:
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

        for wrap_name, wrap_key in [
            ("SHA256[:16]", sha256_correct[:16]),
            ("SHA256[16:32]", sha256_correct[16:32]),
            ("SHA384[:16]", sha384_correct[:16]),
            ("SHA384[16:32]", sha384_correct[16:32]),
            ("shared[:16]", DH_SHARED_CORRECT[:16]),
        ]:
            pt = aes_cbc_decrypt_nopad(wrap_key, iv, ct_48)
            if pt:
                pt_unpad = pkcs7_unpad(pt)
                if pt_unpad and len(pt_unpad) >= 16:
                    if pt_unpad[:16] == TARGET_ENC:
                        print(f"[MATCH] {res_file.name} AES-CBC {wrap_name}")
                        print(f"  pt={pt_unpad.hex()}")
    except Exception:
        pass

print()
print("=" * 70)
print("7. shared_secret の leading zero 問題の確認")
print("=" * 70)

# 実際の shared_secret: 052a8b...
# 先頭が 05 (= leading byte が小さい)
# OpenSSL DH_compute_key は leading zeros を省略する場合がある
# 128 bytes を返したということは leading zeros なし
print(f"Leading byte: 0x{DH_SHARED_CORRECT[0]:02x}")
print(f"Length: {len(DH_SHARED_CORRECT)} bytes (1024-bit DH, max 128 bytes)")

# 先頭に 0x00 を付けて 129 bytes にしてみる
shared_with_zero = b"\x00" + DH_SHARED_CORRECT
for hash_name, hash_alg in HASH_ALGS.items():
    for salt_val, salt_name in [(None, "None"), (b"", "empty"), (b"\x00" * 32, "z32")]:
        for info_val, info_name in [(b"", "empty"), (b"\x01", "01")]:
            try:
                hkdf = HKDF(
                    algorithm=hash_alg,
                    length=48,
                    salt=salt_val,
                    info=info_val,
                )
                derived = hkdf.derive(shared_with_zero)
                check(f"HKDF(0x00+shared,h={hash_name},s={salt_name},i={info_name})", derived)
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
    print("デバッグ: 各入力バリアントのハッシュ先頭 16B")
    for inp_name, inp_val in INPUT_VARIANTS:
        h256 = hashlib.sha256(inp_val).digest()
        h384 = hashlib.sha384(inp_val).digest()
        print(f"  {inp_name}: SHA256[:16]={h256[:16].hex()} SHA384[:16]={h384[:16].hex()}")
    print(f"  target enc_key:        {TARGET_ENC.hex()}")
    print(f"  target hmac_key[:16]:  {TARGET_HMAC[:16].hex()}")
