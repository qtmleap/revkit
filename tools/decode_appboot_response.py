#!/usr/bin/env python3
"""
appboot レスポンスの CBOR を解析して key 33.6 を取り出し、
DH shared_secret を使ってセッション鍵の復号を試みる

msl_keys.json の DH 鍵ペアとサーバーレスポンスのペアリングも調べる
"""

import gzip
import hashlib
import json
import struct
from pathlib import Path

import cbor2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

RAWS_DIR = Path("/home/vscode/app/raws/ios/20260408/raw")
KEYS_FILE = Path("/home/vscode/app/raws/msl_keys.json")

with open(KEYS_FILE) as f:
    keys = json.load(f)

DH_SHARED = bytes.fromhex(keys["dh_shared_secret"])
DH_PUB = int(keys["dh_pub_key"], 16)
DH_P = int(keys["dh_p"], 16)
DH_G = int(keys["dh_g"], 16)
DH_PRIV = int(keys["dh_priv_key"], 16)

ALL_ENC_UNIQUE = list(dict.fromkeys(e["key"] for e in keys["aes_key_history"]))
ALL_HMAC_UNIQUE = list(dict.fromkeys(e["key"] for e in keys["hmac_key_history"]))

print(f"DH pub key: {keys['dh_pub_key'][:20]}...")
print(f"DH shared:  {keys['dh_shared_secret'][:20]}...")
print()


def try_decode_cbor(data: bytes) -> dict | None:
    """CBOR デコード試行 (gzip 展開も試みる)"""
    # gzip 展開
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except Exception:
            pass

    try:
        return cbor2.loads(data)
    except Exception:
        return None


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


# appboot レスポンスファイルをすべて処理
appboot_res_files = sorted(RAWS_DIR.glob("res_*appboot*.bin"))
print(f"appboot response files: {len(appboot_res_files)}")
print()

# key 33.6 の値を収集してユニークなものを調べる
key_33_6_values: dict[str, str] = {}  # hex -> filename

for res_file in appboot_res_files:
    raw = res_file.read_bytes()
    obj = try_decode_cbor(raw)
    if obj is None:
        continue

    # key 33 を探す
    key33 = obj.get(33)
    if key33 is None:
        continue

    # key 33.6 (key_response_data) を取り出す
    inner = None
    try:
        if isinstance(key33, bytes):
            inner = cbor2.loads(key33)
        elif isinstance(key33, dict):
            inner = key33
    except Exception:
        continue

    if inner is None:
        continue

    key33_6 = inner.get(6)
    if key33_6 is None:
        continue

    if isinstance(key33_6, bytes):
        hex_val = key33_6.hex()
        key_33_6_values[hex_val] = res_file.name

print(f"Unique key 33.6 values: {len(key_33_6_values)}")
for hex_val, fname in list(key_33_6_values.items())[:5]:
    print(f"  {fname}: {hex_val[:32]}... ({len(bytes.fromhex(hex_val))} bytes)")
print()

# key 33.6 の各値を解析
print("=" * 70)
print("key 33.6 の解析")
print("=" * 70)

# DH shared_secret から鍵候補を生成
sha256_ss = hashlib.sha256(DH_SHARED).digest()
sha384_ss = hashlib.sha384(DH_SHARED).digest()
sha512_ss = hashlib.sha512(DH_SHARED).digest()

# HKDF 候補
HASH_ALGS = {
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
}

hkdf_candidates: dict[str, bytes] = {}
for hash_name, hash_alg in HASH_ALGS.items():
    for salt in [None, b"", b"\x00" * 32]:
        for info in [b"", b"enc", b"session", b"MSL", b"Netflix"]:
            try:
                hkdf = HKDF(
                    algorithm=hash_alg,
                    length=16,
                    salt=salt,
                    info=info,
                )
                k = hkdf.derive(DH_SHARED)
                label = f"HKDF({hash_name},salt={salt!r}[:4],info={info!r})"
                hkdf_candidates[label] = k
            except Exception:
                pass

wrap_key_candidates: list[tuple[str, bytes]] = [
    ("SHA256(shared)[:16]", sha256_ss[:16]),
    ("SHA256(shared)[16:32]", sha256_ss[16:32]),
    ("SHA384(shared)[:16]", sha384_ss[:16]),
    ("SHA384(shared)[16:32]", sha384_ss[16:32]),
    ("SHA512(shared)[:16]", sha512_ss[:16]),
    ("SHA512(shared)[16:32]", sha512_ss[16:32]),
    ("shared[:16]", DH_SHARED[:16]),
    ("shared[16:32]", DH_SHARED[16:32]),
    ("zeros_16", b"\x00" * 16),
    *[(label, k) for label, k in hkdf_candidates.items()],
]

for hex_val, fname in key_33_6_values.items():
    data = bytes.fromhex(hex_val)
    print(f"\nFile: {fname} ({len(data)} bytes)")
    print(f"Data: {data.hex()}")

    if len(data) == 96:
        print("→ 96 bytes: 試行 [IV(16)+CT(64)+HMAC(16)] or [CT(64)+HMAC(32)]")

        # 仮説 A: IV(16) + CT(64) + HMAC(16) - ただし HMAC は 32 bytes が標準
        # 仮説 B: CT(64) + HMAC(32)
        # 仮説 C: IV(16) + CT(48) + HMAC(32)

        # 仮説 C: IV(16) + CT(48) + HMAC(32)
        iv = data[:16]
        ct_48 = data[16:64]
        hmac_32 = data[64:96]
        # ct_64 = data[0:64]
        # hmac_alt = data[64:96]

        for wrap_name, wrap_key in wrap_key_candidates:
            pt = aes_cbc_decrypt_nopad(wrap_key, iv, ct_48)
            if pt:
                pt_unpad = pkcs7_unpad(pt)
                if pt_unpad and len(pt_unpad) == 32:
                    enc_candidate = pt_unpad[:16]
                    hmac_candidate = pt_unpad[16:32]
                    for enc_hex in ALL_ENC_UNIQUE:
                        if bytes.fromhex(enc_hex) == enc_candidate:
                            print(f"  [MATCH enc] wrap_key={wrap_name}")
                            print(f"  enc={enc_candidate.hex()} hmac={hmac_candidate.hex()}")
                    for h_hex in ALL_HMAC_UNIQUE:
                        if bytes.fromhex(h_hex)[:16] == hmac_candidate:
                            print(f"  [MATCH hmac[:16]] wrap_key={wrap_name}")

                if pt_unpad and len(pt_unpad) == 48:
                    enc_candidate = pt_unpad[:16]
                    hmac_candidate = pt_unpad[16:48]
                    for enc_hex in ALL_ENC_UNIQUE:
                        if bytes.fromhex(enc_hex) == enc_candidate:
                            print(f"  [MATCH enc(48)] wrap_key={wrap_name}")
                            print(f"  enc={enc_candidate.hex()} hmac={hmac_candidate.hex()}")

        # 仮説 B: CT(64) + HMAC(32)
        ct_64 = data[:64]
        for wrap_name, wrap_key in wrap_key_candidates:
            for iv_candidate, iv_name in [
                (b"\x00" * 16, "zeros_16"),
                (data[:16], "data[:16]"),
            ]:
                pt = aes_cbc_decrypt_nopad(wrap_key, iv_candidate, ct_64)
                if pt:
                    pt_unpad = pkcs7_unpad(pt)
                    if pt_unpad and 32 <= len(pt_unpad) <= 48:
                        for enc_hex in ALL_ENC_UNIQUE:
                            if len(pt_unpad) >= 16 and bytes.fromhex(enc_hex) == pt_unpad[:16]:
                                print(f"  [MATCH enc B] wrap_key={wrap_name} iv={iv_name}")
                                print(f"  pt={pt_unpad.hex()}")

print()
print("=" * 70)
print("appboot req の client DH pub_key と msl_keys.json の dh_pub_key 比較")
print("=" * 70)

stored_pub = keys["dh_pub_key"]
print(f"msl_keys dh_pub_key: {stored_pub[:20]}...")

appboot_req_files = sorted(RAWS_DIR.glob("req_*appboot*.bin"))
for req_file in appboot_req_files[:5]:
    raw = req_file.read_bytes()
    obj = try_decode_cbor(raw)
    if obj is None:
        continue

    key33 = obj.get(33)
    if key33 is None:
        continue

    inner = None
    try:
        if isinstance(key33, bytes):
            inner = cbor2.loads(key33)
        elif isinstance(key33, dict):
            inner = key33
    except Exception:
        continue

    if inner is None:
        continue

    key33_6 = inner.get(6)
    print(f"\n{req_file.name}: key33.6 = {key33_6.hex()[:20] if isinstance(key33_6, bytes) else key33_6}... ({len(key33_6) if isinstance(key33_6, bytes) else '?'} bytes)")

    # key 33.8 = identity (ESN)
    key33_8 = inner.get(8)
    print(f"  key33.8 (ESN) = {key33_8}")

    # key 33.9 = client nonce
    key33_9 = inner.get(9)
    if isinstance(key33_9, bytes):
        print(f"  key33.9 (nonce) = {key33_9.hex()}")

print()
print("=" * 70)
print("appboot res の key 33.6 を取り出して DH 由来の鍵でデコード試行 (req とペア)")
print("=" * 70)

# req_4/res_4 のペア (最初の appboot)
for num in ["4", "33", "89", "98"]:
    req_file = RAWS_DIR / f"req_{num}_appboot_2026-04-08T07-52-22-999Z.bin"
    res_file = RAWS_DIR / f"res_{num}_appboot_2026-04-08T07-52-22-999Z.bin"

    if not req_file.exists():
        # ファイル名が異なる可能性があるので glob で探す
        req_files = list(RAWS_DIR.glob(f"req_{num}_appboot*.bin"))
        res_files = list(RAWS_DIR.glob(f"res_{num}_appboot*.bin"))
        if req_files:
            req_file = req_files[0]
        if res_files:
            res_file = res_files[0]

    if not req_file.exists() or not res_file.exists():
        continue

    print(f"\nPair: {req_file.name} / {res_file.name}")

    # req から client nonce と ESN を取得
    req_raw = req_file.read_bytes()
    req_obj = try_decode_cbor(req_raw)
    if req_obj is None:
        print("  req: CBOR decode failed")
        continue

    req_inner = None
    k33 = req_obj.get(33)
    if isinstance(k33, bytes):
        try:
            req_inner = cbor2.loads(k33)
        except Exception:
            pass
    elif isinstance(k33, dict):
        req_inner = k33

    if req_inner:
        client_nonce = req_inner.get(9)
        esn = req_inner.get(8)
        req_6 = req_inner.get(6)
        if isinstance(client_nonce, bytes):
            print(f"  client nonce: {client_nonce.hex()}")
        print(f"  ESN: {esn}")
        if isinstance(req_6, bytes):
            print(f"  req key33.6: {req_6.hex()[:32]}... ({len(req_6)} bytes)")

    # res から server nonce と key33.6 を取得
    res_raw = res_file.read_bytes()
    if res_raw[:2] == b"\x1f\x8b":
        res_raw = gzip.decompress(res_raw)
    res_obj = try_decode_cbor(res_raw)
    if res_obj is None:
        print("  res: CBOR decode failed")
        continue

    res_inner = None
    k33 = res_obj.get(33)
    if isinstance(k33, bytes):
        try:
            res_inner = cbor2.loads(k33)
        except Exception:
            pass
    elif isinstance(k33, dict):
        res_inner = k33

    if res_inner:
        server_nonce = res_inner.get(9)
        scheme = res_inner.get(8)
        res_6 = res_inner.get(6)
        if isinstance(server_nonce, bytes):
            print(f"  server nonce: {server_nonce.hex()}")
        print(f"  scheme: {scheme}")
        if isinstance(res_6, bytes):
            print(f"  res key33.6: {res_6.hex()} ({len(res_6)} bytes)")

            # msl_keys.json の DH shared secret + nonces で復号試行
            if isinstance(client_nonce, bytes) and isinstance(server_nonce, bytes):
                for hash_name, hash_alg in {"SHA-256": hashes.SHA256(), "SHA-384": hashes.SHA384(), "SHA-512": hashes.SHA512()}.items():
                    for salt in [None, b"", client_nonce, server_nonce, client_nonce + server_nonce]:
                        for info in [b"", b"enc", b"wrap", b"session", client_nonce, server_nonce]:
                            try:
                                hkdf = HKDF(
                                    algorithm=hash_alg,
                                    length=16,
                                    salt=salt,
                                    info=info,
                                )
                                wrap_k = hkdf.derive(DH_SHARED)
                                iv = res_6[:16]
                                ct = res_6[16:64]
                                pt = aes_cbc_decrypt_nopad(wrap_k, iv, ct)
                                if pt:
                                    pt_unpad = pkcs7_unpad(pt)
                                    if pt_unpad:
                                        for enc_hex in ALL_ENC_UNIQUE:
                                            if bytes.fromhex(enc_hex) == pt_unpad[:16]:
                                                salt_repr = repr(salt)[:10]
                                                info_repr = repr(info)
                                                print(f"  [MATCH] HKDF(hash={hash_name},salt={salt_repr},info={info_repr}) wrap_key={wrap_k.hex()}")
                                                print(f"  pt={pt_unpad.hex()}")
                            except Exception:
                                pass
