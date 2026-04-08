#!/usr/bin/env python3
"""
DH 共有秘密の整合性確認 + 追加の HKDF パターン探索
"""

import hashlib
import hmac as hmac_mod
import json
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

with open("/home/vscode/app/raws/msl_keys.json") as f:
    keys = json.load(f)

DH_PRIV = int(keys["dh_priv_key"], 16)
DH_PUB = int(keys["dh_pub_key"], 16)
DH_SHARED = bytes.fromhex(keys["dh_shared_secret"])
DH_P = int(keys["dh_p"], 16)
DH_G = int(keys["dh_g"], 16)

print(f"DH p  = {hex(DH_P)[:20]}... ({DH_P.bit_length()} bits)")
print(f"DH g  = {DH_G}")
print(f"priv  = {keys['dh_priv_key'][:20]}...")
print(f"pub   = {keys['dh_pub_key'][:20]}...")
print(f"shared= {keys['dh_shared_secret'][:20]}...")
print()

# DH 公開鍵の検証: g^priv mod p == pub?
computed_pub = pow(DH_G, DH_PRIV, DH_P)
computed_pub_hex = hex(computed_pub)[2:].zfill(256)  # 128 bytes = 256 hex chars
print(f"computed pub = {computed_pub_hex[:20]}...")
print(f"stored   pub = {keys['dh_pub_key'][:20]}...")
print(f"DH pub key MATCH: {computed_pub_hex == keys['dh_pub_key']}")
print()

# DH shared secret の検証: dh_pub^priv mod p == shared?
# (この場合、dh_pub はサーバーの公開鍵であるべきだが、
#  msl_keys.json にはサーバーの公開鍵が記録されていない)
# 代わりに: server_pub^priv mod p == shared を逆算して server_pub を求める
# これは困難なので、代わりに shared_secret の整合性を別の方法で確認

# dh_pub (クライアント公開鍵) を使って検算
# もし shared_secret = dh_pub^priv mod p なら...
computed_ss_from_client_pub = pow(DH_PUB, DH_PRIV, DH_P)
computed_ss_hex = hex(computed_ss_from_client_pub)[2:].zfill(256)
print(f"client_pub^priv mod p = {computed_ss_hex[:20]}...")
print(f"dh_shared_secret      = {keys['dh_shared_secret'][:20]}...")
print()

# OpenSSL DH_compute_key の出力形式
# DH_compute_key は big-endian bytes, leading zeros なし
# shared secret が 1024-bit の場合: 最大 128 bytes (leading zeros は省略)
shared_int = int(keys["dh_shared_secret"], 16)
print(f"shared_secret as int = {shared_int}")
print(f"shared_secret bit length = {shared_int.bit_length()}")
print()

# shared_secret を 128 bytes (1024-bit) に zero-pad
shared_padded = shared_int.to_bytes(128, "big")
print(f"shared_secret (128B padded) = {shared_padded.hex()[:20]}...")
print(f"same as original: {shared_padded == DH_SHARED}")
print()

# --- 全 enc_key/hmac_key 候補 ---
ALL_ENC_KEYS = [bytes.fromhex(e["key"]) for e in keys["aes_key_history"]]
ALL_HMAC_KEYS = [bytes.fromhex(e["key"]) for e in keys["hmac_key_history"]]
ALL_ENC_UNIQUE = list(dict.fromkeys(k.hex() for k in ALL_ENC_KEYS))
ALL_HMAC_UNIQUE = list(dict.fromkeys(k.hex() for k in ALL_HMAC_KEYS))
print(f"Unique enc_keys  ({len(ALL_ENC_UNIQUE)}): {ALL_ENC_UNIQUE}")
print(f"Unique hmac_keys ({len(ALL_HMAC_UNIQUE)}): {ALL_HMAC_UNIQUE}")
print()

found = []

def check_any_48(label: str, derived: bytes) -> bool:
    for enc_hex in ALL_ENC_UNIQUE:
        enc = bytes.fromhex(enc_hex)
        for hmac_hex in ALL_HMAC_UNIQUE:
            hmac_k = bytes.fromhex(hmac_hex)
            if len(derived) >= 48:
                combined_eh = enc + hmac_k
                combined_he = hmac_k[:16] + enc
                if derived[:48] == combined_eh:
                    msg = f"[ENC+HMAC MATCH] {label}  enc={enc_hex[:8]} hmac={hmac_hex[:8]}"
                    print(msg)
                    found.append(msg)
                    return True
            if len(derived) >= 16 and derived[:16] == enc:
                msg = f"[ENC_ONLY] {label}  enc={enc_hex[:8]}  rest={derived[16:32].hex()}"
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

INPUT_VARIANTS: list[tuple[str, bytes]] = [
    ("shared_raw", DH_SHARED),
    ("shared_padded_128", shared_padded),
    ("shared_int_be", shared_int.to_bytes(128, "big")),
]

# nonce: key_response_data の sub-key 9 = サーバー nonce
# (msl_cbor_key_exchange_analysis.md より)
# appboot レスポンス: サーバー nonce = e73104a8f4a9ed430d90a330d7978432
# クライアント nonce: a97e47477522ab39e39b322bdf818031
SERVER_NONCE = bytes.fromhex("e73104a8f4a9ed430d90a330d7978432")
CLIENT_NONCE = bytes.fromhex("a97e47477522ab39e39b322bdf818031")

print("=" * 70)
print("1. nonce をソルトまたは info に使った HKDF")
print("=" * 70)

extra_salts: list[tuple[str, bytes | None]] = [
    ("salt=None", None),
    ("salt=b''", b""),
    ("salt=server_nonce", SERVER_NONCE),
    ("salt=client_nonce", CLIENT_NONCE),
    ("salt=server+client_nonce", SERVER_NONCE + CLIENT_NONCE),
    ("salt=client+server_nonce", CLIENT_NONCE + SERVER_NONCE),
    ("salt=zeros_16", b"\x00" * 16),
    ("salt=zeros_32", b"\x00" * 32),
]

extra_infos: list[tuple[str, bytes]] = [
    ("info=b''", b""),
    ("info=server_nonce", SERVER_NONCE),
    ("info=client_nonce", CLIENT_NONCE),
    ("info=s+c_nonce", SERVER_NONCE + CLIENT_NONCE),
    ("info=c+s_nonce", CLIENT_NONCE + SERVER_NONCE),
    ("info=b'enc'", b"enc"),
    ("info=b'hmac'", b"hmac"),
    ("info=b'session'", b"session"),
    ("info=b'Netflix'", b"Netflix"),
    ("info=b'MSL'", b"MSL"),
    ("info=ESN_bytes", b"NFAPPL-02-IPHONE9=1"),
]

OUTPUT_LENGTHS = [16, 32, 48, 64, 80, 128]

for hash_name, hash_alg in HASH_ALGS.items():
    for salt_name, salt_val in extra_salts:
        for info_name, info_val in extra_infos:
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
                        label = f"HKDF({input_name}) hash={hash_name} {salt_name} {info_name} len={out_len}"
                        check_any_48(label, derived)
                    except Exception:
                        pass

print()
print("=" * 70)
print("2. HKDFExpand with nonce as info")
print("=" * 70)

for hash_name, hash_alg in HASH_ALGS.items():
    for info_name, info_val in extra_infos:
        for input_name, input_val in INPUT_VARIANTS:
            for out_len in OUTPUT_LENGTHS:
                try:
                    hkdf_expand = HKDFExpand(
                        algorithm=hash_alg,
                        length=out_len,
                        info=info_val,
                    )
                    derived = hkdf_expand.derive(input_val)
                    label = f"HKDFExpand({input_name}) hash={hash_name} {info_name} len={out_len}"
                    check_any_48(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("3. HMAC-SHA256 ベース KDF with nonces")
print("=" * 70)

hmac_keys_for_kdf: list[tuple[str, bytes]] = [
    ("key=shared", DH_SHARED),
    ("key=SHA256(shared)", hashlib.sha256(DH_SHARED).digest()),
    ("key=server_nonce", SERVER_NONCE),
    ("key=client_nonce", CLIENT_NONCE),
    ("key=zeros_32", b"\x00" * 32),
]

hmac_msgs: list[tuple[str, bytes]] = [
    ("msg=b''", b""),
    ("msg=server_nonce", SERVER_NONCE),
    ("msg=client_nonce", CLIENT_NONCE),
    ("msg=s+c_nonce", SERVER_NONCE + CLIENT_NONCE),
    ("msg=shared", DH_SHARED),
    ("msg=b'\\x00'", b"\x00"),
    ("msg=b'\\x01'", b"\x01"),
]

for key_name, key_val in hmac_keys_for_kdf:
    for msg_name, msg_val in hmac_msgs:
        h = hmac_mod.new(key_val, msg_val, hashlib.sha256).digest()
        label = f"HMAC-SHA256 {key_name} {msg_name}"
        check_any_48(label, h + b"\x00" * 16)

print()
print("=" * 70)
print("4. ハッシュ (nonce concatenation 込み)")
print("=" * 70)

hash_inputs: list[tuple[str, bytes]] = [
    ("SHA256(shared)", hashlib.sha256(DH_SHARED).digest()),
    ("SHA384(shared)", hashlib.sha384(DH_SHARED).digest()),
    ("SHA512(shared)", hashlib.sha512(DH_SHARED).digest()),
    ("SHA256(shared+server_nonce)", hashlib.sha256(DH_SHARED + SERVER_NONCE).digest()),
    ("SHA256(shared+client_nonce)", hashlib.sha256(DH_SHARED + CLIENT_NONCE).digest()),
    ("SHA256(server_nonce+shared)", hashlib.sha256(SERVER_NONCE + DH_SHARED).digest()),
    ("SHA256(client_nonce+shared)", hashlib.sha256(CLIENT_NONCE + DH_SHARED).digest()),
    ("SHA384(shared+s_nonce)", hashlib.sha384(DH_SHARED + SERVER_NONCE).digest()),
    ("SHA384(shared+c_nonce)", hashlib.sha384(DH_SHARED + CLIENT_NONCE).digest()),
    ("SHA512(shared+s_nonce)", hashlib.sha512(DH_SHARED + SERVER_NONCE).digest()),
]

for name, digest in hash_inputs:
    for offset in range(0, max(1, len(digest) - 47), 1):
        candidate = digest[offset : offset + 48]
        if len(candidate) >= 16:
            check_any_48(f"{name}[{offset}:]", candidate)

print()
print("=" * 70)
print("5. appboot response key 33.6 (96 bytes) の AES-CBC 復号試行")
print("=" * 70)

# docs/spec/msl_cbor_key_exchange_analysis.md より:
# レスポンス key 33.6 = 96 bytes:
# CT(64B) = bb73317f907f7a5a3f924bece878d6a6 8db3b8f354d2207a224a323297523f58 2d72dfb28ea593b584d096c861561be8 b7d72ef4dc404e076943130aa0303200
# HMAC(32B) = af5d720284876f9b1c076aacc2ad7fc8 6b5a242b0cf9beb28b2a87ad00f3db38
# または:
# IV(16B) + CT(48B) + HMAC(32B)

RESPONSE_96 = bytes.fromhex(
    "bb73317f907f7a5a3f924bece878d6a6"
    "8db3b8f354d2207a224a323297523f58"
    "2d72dfb28ea593b584d096c861561be8"
    "b7d72ef4dc404e076943130aa0303200"
    "af5d720284876f9b1c076aacc2ad7fc8"
    "6b5a242b0cf9beb28b2a87ad00f3db38"
)

print(f"response_96 = {RESPONSE_96.hex()}")
print()

# AES-CBC 復号: IV = 先頭 16B, CT = 次の 48B (または 64B)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(ct) + dec.finalize()
    except Exception:
        return None

# 仮説 A: CT(64B) を AES-CBC 復号して enc_key + hmac_key を得る
# 復号鍵: DH shared secret から直接導出した何かか?
# まず SHA-256(shared_secret) を鍵にして試す

print("5.1 CT=96[0:64], IV は何か? 復号鍵候補で試行")
CT_64 = RESPONSE_96[:64]
CT_48 = RESPONSE_96[16:64]  # IV(16) + CT(48) の場合
IV_16 = RESPONSE_96[:16]

# SHA-256(shared_secret)[:16] を AES 鍵として使う
sha256_ss = hashlib.sha256(DH_SHARED).digest()

aes_keys_to_try: list[tuple[str, bytes]] = [
    ("SHA256(shared)[:16]", sha256_ss[:16]),
    ("SHA256(shared)[16:32]", sha256_ss[16:32]),
    ("SHA384(shared)[:16]", hashlib.sha384(DH_SHARED).digest()[:16]),
    ("SHA384(shared)[16:32]", hashlib.sha384(DH_SHARED).digest()[16:32]),
    ("SHA512(shared)[:16]", hashlib.sha512(DH_SHARED).digest()[:16]),
    ("shared[:16]", DH_SHARED[:16]),
    ("shared[16:32]", DH_SHARED[16:32]),
    ("server_nonce", SERVER_NONCE),
    ("client_nonce", CLIENT_NONCE),
    ("zeros_16", b"\x00" * 16),
]

ivs_to_try: list[tuple[str, bytes]] = [
    ("IV=response[:16]", RESPONSE_96[:16]),
    ("IV=zeros", b"\x00" * 16),
    ("IV=server_nonce", SERVER_NONCE),
    ("IV=client_nonce", CLIENT_NONCE),
    ("IV=SHA256(shared)[:16]", sha256_ss[:16]),
]

for key_name, aes_key in aes_keys_to_try:
    for iv_name, iv_val in ivs_to_try:
        # CT = 64 bytes (仮説 A)
        pt = aes_cbc_decrypt(aes_key, iv_val, CT_64)
        if pt:
            # PKCS7 アンパッド
            pad_len = pt[-1]
            if 1 <= pad_len <= 16 and pt[-pad_len:] == bytes([pad_len]) * pad_len:
                pt_unpad = pt[:-pad_len]
                if len(pt_unpad) == 48:
                    enc_candidate = pt_unpad[:16]
                    hmac_candidate = pt_unpad[16:]
                    for enc_hex in ALL_ENC_UNIQUE:
                        if bytes.fromhex(enc_hex) == enc_candidate:
                            print(f"[DECRYPT MATCH enc] AES-CBC key={key_name} {iv_name}")
                            print(f"  enc={enc_candidate.hex()} hmac={hmac_candidate.hex()}")
                            found.append(f"DECRYPT enc_match: {key_name} {iv_name}")
                    for hmac_hex in ALL_HMAC_UNIQUE:
                        if bytes.fromhex(hmac_hex) == hmac_candidate:
                            print(f"[DECRYPT MATCH hmac] AES-CBC key={key_name} {iv_name}")
                            found.append(f"DECRYPT hmac_match: {key_name} {iv_name}")

        # CT = 48 bytes (仮説 B: IV=response[:16])
        pt2 = aes_cbc_decrypt(aes_key, iv_val, CT_48)
        if pt2:
            pad_len = pt2[-1]
            if 1 <= pad_len <= 16 and pt2[-pad_len:] == bytes([pad_len]) * pad_len:
                pt_unpad = pt2[:-pad_len]
                for enc_hex in ALL_ENC_UNIQUE:
                    if len(pt_unpad) >= 16 and bytes.fromhex(enc_hex) == pt_unpad[:16]:
                        print(f"[DECRYPT2 MATCH enc] AES-CBC(48B CT) key={key_name} {iv_name}")
                        print(f"  pt={pt_unpad.hex()}")
                        found.append(f"DECRYPT2 enc_match: {key_name} {iv_name}")

print()
print("=" * 70)
print("6. appboot response の実際のファイルを探して解析")
print("=" * 70)

import os, glob
appboot_files = glob.glob("/home/vscode/app/raws/ios/*/raw/*appboot*")
print(f"appboot files found: {appboot_files}")

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
    print("デバッグ: SHA256(shared_secret) = ", hashlib.sha256(DH_SHARED).hexdigest())
    print("デバッグ: 全 enc_key unique =", ALL_ENC_UNIQUE)
    print()
    print("NOTE: dh_shared_secret と session_enc_key が別セッションの可能性が高い")
    print("  msl_keys.json timestamp: 2026-04-08T19:01:29")
    print("  キャプチャファイル: 07:xx ~ 08:xx 台")
    print("  → 別のセッションの鍵が記録されている可能性")
