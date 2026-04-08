#!/usr/bin/env python3
"""
HKDF パラメータ探索 Part 3
- aes_key_history[0] と hmac_key_history[3] (post_appboot 最初のペア) をターゲットに
- より広い組み合わせを試す
- shared_secret のバイト列変換パターンも試す
"""

import hashlib
import hmac as hmac_mod
import json
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

with open("/home/vscode/app/raws/msl_keys.json") as f:
    keys = json.load(f)

DH_SHARED = bytes.fromhex(keys["dh_shared_secret"])

# ターゲットペアの候補
# aes_key_history の post_appboot エントリとの対応を全組み合わせで試す
ENC_KEYS = [
    bytes.fromhex(e["key"])
    for e in keys["aes_key_history"]
    if e["phase"] == "post_appboot"
]
HMAC_KEYS_POST = [
    bytes.fromhex(e["key"])
    for e in keys["hmac_key_history"]
    if e["phase"] == "post_appboot"
]

ENC_UNIQUE = list(dict.fromkeys(k.hex() for k in ENC_KEYS))
HMAC_UNIQUE = list(dict.fromkeys(k.hex() for k in HMAC_KEYS_POST))

print("post_appboot enc_keys:", ENC_UNIQUE)
print("post_appboot hmac_keys:", HMAC_UNIQUE)
print()

found: list[str] = []


def check(label: str, derived: bytes) -> bool:
    for enc_hex in ENC_UNIQUE:
        enc = bytes.fromhex(enc_hex)
        for hmac_hex in HMAC_UNIQUE:
            hmac_k = bytes.fromhex(hmac_hex)
            # enc + hmac_k の組み合わせが derived に含まれるか
            combined = enc + hmac_k
            if len(derived) >= len(combined) and derived[: len(combined)] == combined:
                msg = f"[ENC+HMAC MATCH] {label}  enc={enc_hex[:8]} hmac={hmac_hex[:8]}"
                print(msg)
                found.append(msg)
                return True
            combined_rev = hmac_k + enc
            if len(derived) >= len(combined_rev) and derived[: len(combined_rev)] == combined_rev:
                msg = f"[HMAC+ENC MATCH] {label}  hmac={hmac_hex[:8]} enc={enc_hex[:8]}"
                print(msg)
                found.append(msg)
                return True
        if len(derived) >= 16 and derived[:16] == enc:
            msg = f"[ENC_ONLY] {label}  enc={enc_hex[:8]}  rest={derived[16:32].hex()}"
            print(msg)
            found.append(msg)
    return False


# DH shared secret のバリエーション
ss_int = int(keys["dh_shared_secret"], 16)
INPUT_VARIANTS: list[tuple[str, bytes]] = [
    ("shared_raw", DH_SHARED),
    ("shared_padded_128", ss_int.to_bytes(128, "big")),
    ("shared_padded_256", ss_int.to_bytes(256, "big")),  # over-padded
    ("SHA256(shared)", hashlib.sha256(DH_SHARED).digest()),
    ("SHA384(shared)", hashlib.sha384(DH_SHARED).digest()),
    ("SHA512(shared)", hashlib.sha512(DH_SHARED).digest()),
    # CBOR エンコードされた shared_secret?
    # bstr として: 0x5818 (58=bstr, 18=24=0) + ...
    # shared_secret の上位バイトが最初?下位が最初?
    ("shared_reversed", DH_SHARED[::-1]),
    # 末尾 n バイトを使う
    ("shared_last_32", DH_SHARED[-32:]),
    ("shared_last_64", DH_SHARED[-64:]),
]

# ハッシュアルゴリズム
HASH_ALGS = {
    "SHA-1": hashes.SHA1(),
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
}

# salt 候補 (拡張版)
SALT_CANDIDATES: list[tuple[str, bytes | None]] = [
    ("salt=None", None),
    ("salt=b''", b""),
    ("salt=zeros_16", b"\x00" * 16),
    ("salt=zeros_20", b"\x00" * 20),
    ("salt=zeros_32", b"\x00" * 32),
    ("salt=zeros_64", b"\x00" * 64),
    ("salt=zeros_128", b"\x00" * 128),
    # SHA-256(b"") をソルトとして使う (RFC 5869 デフォルト)
    ("salt=SHA256(b'')", hashlib.sha256(b"").digest()),
]

# info 候補 (大幅拡張)
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
    ("b'\\x04'", b"\x04"),
    ("b'\\x05'", b"\x05"),
    ("b'\\x00\\x00\\x00\\x00'", b"\x00\x00\x00\x00"),
    ("b'\\x00\\x00\\x00\\x01'", b"\x00\x00\x00\x01"),
    ("b'\\x00\\x00\\x00\\x02'", b"\x00\x00\x00\x02"),
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
    ("b'master_secret'", b"master_secret"),
    ("b'key_expansion'", b"key_expansion"),
    ("b'key expansion'", b"key expansion"),
    ("b'client'", b"client"),
    ("b'server'", b"server"),
    ("b'MSL enc'", b"MSL enc"),
    ("b'MSL hmac'", b"MSL hmac"),
    ("b'MSL encryption'", b"MSL encryption"),
    ("b'MSL signing'", b"MSL signing"),
    ("b'AES/CBC/PKCS5Padding'", b"AES/CBC/PKCS5Padding"),
    ("b'HmacSHA256'", b"HmacSHA256"),
    ("b'HMACSHA256'", b"HMACSHA256"),
    # Scheme 5 関連?
    ("b'scheme5'", b"scheme5"),
    ("b'SCHEME5'", b"SCHEME5"),
    ("b'5'", b"5"),
    ("b'scheme=5'", b"scheme=5"),
    # DH 1024 グループ関連
    ("b'dh1024'", b"dh1024"),
    ("b'DH1024'", b"DH1024"),
    # NFWebCrypto 関連
    ("b'NFWebCrypto'", b"NFWebCrypto"),
    ("b'appboot'", b"appboot"),
    ("b'APPBOOT'", b"APPBOOT"),
    ("b'fairplay'", b"fairplay"),
    ("b'FAIRPLAY'", b"FAIRPLAY"),
    ("b'FairPlay'", b"FairPlay"),
]

OUTPUT_LENGTHS = [16, 32, 48, 64, 80, 128]

print("=" * 70)
print("1. 全入力バリアント × HKDF パラメータ組み合わせ")
print("=" * 70)

for hash_name, hash_alg in HASH_ALGS.items():
    for salt_name, salt_val in SALT_CANDIDATES:
        for info_name, info_val in INFO_CANDIDATES:
            for input_name, input_val in INPUT_VARIANTS:
                for out_len in OUTPUT_LENGTHS:
                    try:
                        hkdf = HKDF(
                            algorithm=hash_alg,
                            length=out_len,
                            salt=salt_val,
                            info=info_val,
                        )
                        derived = hkdf.derive(input_val)
                        label = f"HKDF({input_name}) hash={hash_name} {salt_name} info={info_name} len={out_len}"
                        check(label, derived)
                    except Exception:
                        pass

print()
print("=" * 70)
print("2. HKDFExpand バリアント")
print("=" * 70)

for hash_name, hash_alg in HASH_ALGS.items():
    for info_name, info_val in INFO_CANDIDATES:
        for input_name, input_val in INPUT_VARIANTS:
            for out_len in OUTPUT_LENGTHS:
                try:
                    hkdf_expand = HKDFExpand(
                        algorithm=hash_alg,
                        length=out_len,
                        info=info_val,
                    )
                    derived = hkdf_expand.derive(input_val)
                    label = f"HKDFExpand({input_name}) hash={hash_name} info={info_name} len={out_len}"
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("3. ハッシュ連鎖 (key derivation via successive hashing)")
print("=" * 70)

# pattern: h1 = SHA-256(shared), enc_key = h1[:16], hmac_key = SHA-256(h1)
h256 = hashlib.sha256(DH_SHARED).digest()
h_of_h256 = hashlib.sha256(h256).digest()
h384 = hashlib.sha384(DH_SHARED).digest()

for enc_hex in ENC_UNIQUE:
    enc = bytes.fromhex(enc_hex)
    if h256[:16] == enc:
        print(f"[MATCH] SHA256(shared)[:16] == enc={enc_hex[:8]}")
    if h384[:16] == enc:
        print(f"[MATCH] SHA384(shared)[:16] == enc={enc_hex[:8]}")

# AES key wrapping 系: shared_secret を使って対称鍵をアンラップ
print()
print("=" * 70)
print("4. 直接比較: shared_secret の部分列")
print("=" * 70)

for offset in range(0, 128 - 15, 1):
    candidate = DH_SHARED[offset : offset + 16]
    for enc_hex in ENC_UNIQUE:
        if bytes.fromhex(enc_hex) == candidate:
            print(f"[MATCH] shared[{offset}:{offset+16}] == enc={enc_hex[:8]}")

print()
print("=" * 70)
print("5. PKCS#1 OAEP (RSA 暗号化された鍵バンドル?)")
print("=" * 70)

# 別の考え方: key33.6 (464 bytes) は RSA-4096 で暗号化されていて
# 復号するとセッション鍵が出てくる。
# しかし RSA-4096 の秘密鍵はサーバーにしかない。
# Tweak で取得した shared_secret と session_enc_key の間に
# どんな変換があるか直接調べるには DH shared_secret から
# session_enc_key への写像を特定する。

# もし変換が f(shared) = enc_key なら、
# SHA-256(shared) = 0x64eef7c98f563401...
# enc_key = 0817... or 97b9... or f4b5...
# どれも一致しない。

# 考えられる可能性:
# 1. Tweak がキャプチャした DH_compute_key の出力がこのセッションのものでない
# 2. DH shared_secret に追加の処理が施されている
# 3. shared_secret は全く別の用途で使われていて、enc_key は server から受信したもの

# key33.6 (レスポンス 96 bytes) の構造をより詳しく分析
print()
print("=" * 70)
print("6. 全 appboot レスポンスの key33.6 の統計")
print("=" * 70)

import gzip
import cbor2
from pathlib import Path

RAWS_DIR = Path("/home/vscode/app/raws/ios/20260408/raw")

# 全 appboot レスポンスから key33.6 を収集
all_res_96: list[bytes] = []
for res_file in sorted(RAWS_DIR.glob("res_*appboot*.bin")):
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
        if isinstance(k6, bytes) and len(k6) == 96:
            all_res_96.append(k6)
    except Exception:
        pass

print(f"Total 96-byte key33.6 values: {len(all_res_96)}")
print()

# バイト位置ごとの分散を見る (固定部分と可変部分を特定)
if all_res_96:
    # 各バイト位置でユニーク値の数を数える (高=ランダム, 低=固定)
    print("Byte position uniqueness (low=fixed, high=random):")
    for i in range(0, 96, 16):
        unique_counts = [len(set(b[j] for b in all_res_96)) for j in range(i, min(i+16, 96))]
        avg = sum(unique_counts) / len(unique_counts)
        print(f"  bytes {i:2d}-{i+15:2d}: avg_unique={avg:.1f}  (min={min(unique_counts)} max={max(unique_counts)})")
    # 先頭 16 bytes のユニーク性
    first_16 = [b[:16] for b in all_res_96]
    unique_first_16 = set(b.hex() for b in first_16)
    print(f"  全96B のユニーク数: {len(set(b.hex() for b in all_res_96))}")
    print(f"  先頭16B のユニーク数: {len(unique_first_16)}")

print()
print("=" * 70)
print("結果サマリー")
print("=" * 70)
if found:
    print(f"一致 ({len(found)}件):")
    for f in found:
        print(f"  - {f}")
else:
    print("一致なし")
    print()
    print("仮説: msl_keys.json の dh_shared_secret と session_enc_key は別のセッションのもの")
    print("  → Tweak の実装で g_keys は最後に更新された値を保持するため、")
    print("    複数の DH 鍵交換が行われた場合に対応が崩れる可能性がある")
    print()
    print(f"msl_keys.json の dh_shared_secret = {keys['dh_shared_secret'][:32]}...")
    print(f"  session_enc_key                  = {keys['session_enc_key']}")
    print(f"  SHA256(shared)[:16]              = {hashlib.sha256(DH_SHARED).hexdigest()[:32]}")
    print(f"  → enc_key が SHA256(shared)[:16] と一致しない → 別セッションの可能性大")
