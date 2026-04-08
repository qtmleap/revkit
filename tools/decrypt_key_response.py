#!/usr/bin/env python3
"""
Phase 2 初期セッション鍵の復号試行ツール

key 33.6 (96 bytes) の暗号文を候補鍵で復号し、
平文が既知のセッション鍵 (enc_key_0, sign_key_0) を含むか検証する。

構造仮説:
  仮説 A: [CT:64B][HMAC:32B]     — IV なし (zeros または別フィールド)
  仮説 B: [IV:16B][CT:48B][HMAC:32B]  — 最有力 (MSL 標準構造)
  仮説 C: [IV:16B][CT:64B][HMAC:16B]  — HMAC が 16B に短縮

テストベクター:
  DH shared_secret = 052a8bfe... (128 bytes)
  PSK              = 027617984f6227539a630b897c017d69
  nonce (hardcode) = 809f82a7addf548d3ea9dd067ff9bb91
  server nonce     = e73104a8f4a9ed430d90a330d7978432
  client nonce     = a97e47477522ab39e39b322bdf818031

既知セッション鍵 (ターゲット):
  enc_key_0  = 0817065e29e6d1c8668473af9e13b3c2  (DH 直後最初の AES 鍵)
  enc_key_1  = 97b99f4e88e8e73779aa20ac11877c5d  (Phase 3 KDF 出力)
  sign_key_0 = 91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1
  sign_key_1 = d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import struct
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ===================================================================
# テストベクター
# ===================================================================

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

# バイナリ埋め込み固定値 (NFWebCrypto.framework @ 0x1ac8f5)
PSK = bytes.fromhex("027617984f6227539a630b897c017d69")
NONCE_HARD = bytes.fromhex("809f82a7addf548d3ea9dd067ff9bb91")

# セッション固有 nonce
SERVER_NONCE = bytes.fromhex("e73104a8f4a9ed430d90a330d7978432")
CLIENT_NONCE = bytes.fromhex("a97e47477522ab39e39b322bdf818031")

# 既知セッション鍵 (全ターゲット)
ENC_KEY_0 = bytes.fromhex("0817065e29e6d1c8668473af9e13b3c2")
ENC_KEY_1 = bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d")

KNOWN_ENC_KEYS: list[bytes] = [
    ENC_KEY_0,
    ENC_KEY_1,
    bytes.fromhex("f4b5e0519e8022b2801768cdc88816d6"),  # enc_key_2
    bytes.fromhex("834327638d92f129c9da8a5ab72bca3b"),
]

KNOWN_HMAC_KEYS: list[bytes] = [
    bytes.fromhex(
        "91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1"
    ),  # sign_key_0
    bytes.fromhex("38b2030dd55e3367290213ca0d16ee079524ccd24fb7221a52145fb6de016fd8"),
    bytes.fromhex("05ffd2d7407a6da255dfd89cde00504d1803ed81a8e5c17ea196c4498d01d825"),
    bytes.fromhex(
        "d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0"
    ),  # sign_key_1
    bytes.fromhex("b733c6b8bd3c2d02098c6c679daa9b138f9e0d9d76f95d2c85240937d53c66c9"),
    bytes.fromhex("a4333e99a34eef3663f8e38e217e696949cd3bf57598c5c260fedb8997afa82b"),
    bytes.fromhex("b319e54dce7117932439aad5e1dfed1e8d18fe033aabe00ab786dc4239e8dd85"),
]

# appboot レスポンス key 33.6 (96 bytes)
KEY336_HEX = (
    "bb73317f907f7a5a3f924bece878d6a6"
    "8db3b8f354d2207a224a323297523f58"
    "2d72dfb28ea593b584d096c861561be8"
    "b7d72ef4dc404e076943130aa0303200"
    "af5d720284876f9b1c076aacc2ad7fc8"
    "6b5a242b0cf9beb28b2a87ad00f3db38"
)
KEY336 = bytes.fromhex(KEY336_HEX)

print(f"key 33.6 ({len(KEY336)} bytes):")
print(f"  IV  (bytes  0-15): {KEY336[:16].hex()}")
print(f"  CT  (bytes 16-63): {KEY336[16:64].hex()}")
print(f"  HMAC(bytes 64-95): {KEY336[64:96].hex()}")
print()

# ===================================================================
# ユーティリティ
# ===================================================================

found: list[str] = []


def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
    """AES-128-CBC 復号。失敗時は None を返す。"""
    if len(key) not in (16, 24, 32):
        return None
    if len(iv) != 16:
        return None
    if len(ct) % 16 != 0:
        return None
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(ct) + dec.finalize()
    except Exception:
        return None


def pkcs7_unpad(data: bytes) -> bytes | None:
    """PKCS7 アンパディング。不正なパディングは None を返す。"""
    if not data:
        return None
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return data[:-pad_len]


def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac_mod.new(key, msg, hashlib.sha256).digest()


def verify_hmac(hmac_key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """HMAC-SHA256(hmac_key, data) == expected_hmac"""
    computed = hmac256(hmac_key, data)
    return computed == expected_hmac


def check_plaintext(label: str, pt: bytes) -> bool:
    """平文が既知のセッション鍵 (enc_key または sign_key) を含むか検査"""
    matched = False
    for enc_key in KNOWN_ENC_KEYS:
        if len(pt) >= 16 and pt[:16] == enc_key:
            hmac_part = pt[16:]
            hmac_matched = any(
                hmac_part == sk or hmac_part[:32] == sk for sk in KNOWN_HMAC_KEYS
            )
            if hmac_matched:
                msg = (
                    f"[FULL MATCH] {label}  enc={enc_key.hex()[:8]}... hmac_match=True"
                )
                print(msg)
                found.append(msg)
            else:
                msg = f"[ENC_ONLY] {label}  enc={enc_key.hex()[:8]}...  rest={hmac_part[:16].hex()}"
                print(msg)
                found.append(msg)
            matched = True
    return matched


# ===================================================================
# 候補ラッピング鍵の生成
# ===================================================================

ss_int = int(DH_SHARED.hex(), 16)

sha256_ss = hashlib.sha256(DH_SHARED).digest()
sha384_ss = hashlib.sha384(DH_SHARED).digest()
sha512_ss = hashlib.sha512(DH_SHARED).digest()

WRAP_KEY_CANDIDATES: list[tuple[str, bytes]] = [
    # --- ハッシュ切り出し ---
    ("sha256(DH)[:16]", sha256_ss[:16]),
    ("sha256(DH)[16:32]", sha256_ss[16:32]),
    ("sha384(DH)[:16]", sha384_ss[:16]),
    ("sha384(DH)[16:32]", sha384_ss[16:32]),
    ("sha384(DH)[32:48]", sha384_ss[32:48]),
    ("sha512(DH)[:16]", sha512_ss[:16]),
    ("sha512(DH)[16:32]", sha512_ss[16:32]),
    ("sha512(DH)[32:48]", sha512_ss[32:48]),
    ("sha512(DH)[48:64]", sha512_ss[48:64]),
    # --- DH 直接切り出し ---
    ("DH[:16]", DH_SHARED[:16]),
    ("DH[16:32]", DH_SHARED[16:32]),
    ("DH[-16:]", DH_SHARED[-16:]),
    # --- PSK / nonce 由来 ---
    ("PSK", PSK),
    ("NONCE_HARD", NONCE_HARD),
    ("SERVER_NONCE", SERVER_NONCE),
    ("CLIENT_NONCE", CLIENT_NONCE),
    # --- 既知セッション鍵 (Phase 4 では enc_key_1 が wrap_key として使われた) ---
    ("enc_key_0", ENC_KEY_0),
    ("enc_key_1", ENC_KEY_1),
    # --- HMAC チェーン由来 ---
    ("HMAC(PSK,DH)[:16]", hmac256(PSK, DH_SHARED)[:16]),
    ("HMAC(DH,PSK)[:16]", hmac256(DH_SHARED, PSK)[:16]),
    ("HMAC(PSK,DH)[16:32]", hmac256(PSK, DH_SHARED)[16:32]),
    ("HMAC(NONCE,DH)[:16]", hmac256(NONCE_HARD, DH_SHARED)[:16]),
    ("HMAC(SERVER_NONCE,DH)[:16]", hmac256(SERVER_NONCE, DH_SHARED)[:16]),
    # --- 2 段 HMAC ---
    (
        "HMAC(HMAC(PSK,DH),NONCE)[:16]",
        hmac256(hmac256(PSK, DH_SHARED), NONCE_HARD)[:16],
    ),
    (
        "HMAC(HMAC(PSK,DH),SRV_NONCE)[:16]",
        hmac256(hmac256(PSK, DH_SHARED), SERVER_NONCE)[:16],
    ),
    (
        "HMAC(HMAC(DH,PSK),NONCE)[:16]",
        hmac256(hmac256(DH_SHARED, PSK), NONCE_HARD)[:16],
    ),
    # --- HKDF 由来 (サーバー nonce を salt/info に) ---
]

# HKDF 候補を動的生成
for hash_alg, hash_name in [
    (hashes.SHA256(), "SHA256"),
    (hashes.SHA384(), "SHA384"),
]:
    for salt_val, salt_name in [
        (None, "None"),
        (SERVER_NONCE, "SRV_NONCE"),
        (CLIENT_NONCE, "CLI_NONCE"),
        (PSK, "PSK"),
    ]:
        for info_val, info_name in [
            (b"", "empty"),
            (SERVER_NONCE, "SRV_NONCE"),
            (PSK, "PSK"),
            (b"wrap", "wrap"),
            (b"session", "session"),
        ]:
            try:
                hkdf = HKDF(
                    algorithm=hash_alg,
                    length=16,
                    salt=salt_val,
                    info=info_val,
                )
                k = hkdf.derive(DH_SHARED)
                label = f"HKDF({hash_name},s={salt_name},i={info_name})"
                WRAP_KEY_CANDIDATES.append((label, k))
            except Exception:
                pass

print(f"Total wrap_key candidates: {len(WRAP_KEY_CANDIDATES)}")
print()

# ===================================================================
# HMAC 署名鍵の候補
# ===================================================================

SIGN_KEY_CANDIDATES: list[tuple[str, bytes]] = [
    ("PSK", PSK),
    ("NONCE_HARD", NONCE_HARD),
    ("SERVER_NONCE", SERVER_NONCE),
    ("DH_SHARED", DH_SHARED),
    ("sha256(DH)", sha256_ss),
    ("sha384(DH)", sha384_ss),
    ("enc_key_0", ENC_KEY_0),
    ("enc_key_1", ENC_KEY_1),
    ("HMAC(PSK,DH)", hmac256(PSK, DH_SHARED)),
    ("HMAC(DH,PSK)", hmac256(DH_SHARED, PSK)),
    ("HMAC(PSK,DH+NONCE)", hmac256(PSK, DH_SHARED + NONCE_HARD)),
]
# 全 known HMAC keys も候補として追加
for i, sk in enumerate(KNOWN_HMAC_KEYS):
    SIGN_KEY_CANDIDATES.append((f"known_hmac_{i}_{sk.hex()[:8]}", sk))

# ===================================================================
# Section 1: 仮説 B — [IV:16B][CT:48B][HMAC:32B]
# ===================================================================

print("=" * 70)
print("仮説 B: [IV:16B][CT:48B][HMAC:32B]")
print("  IV   = key336[0:16]")
print("  CT   = key336[16:64]")
print("  HMAC = key336[64:96]")
print("=" * 70)

IV_B = KEY336[:16]
CT_B = KEY336[16:64]
HMAC_B = KEY336[64:96]

print(f"  IV:   {IV_B.hex()}")
print(f"  CT:   {CT_B.hex()}")
print(f"  HMAC: {HMAC_B.hex()}")
print()

for wrap_name, wrap_key in WRAP_KEY_CANDIDATES:
    pt = aes_cbc_decrypt(wrap_key, IV_B, CT_B)
    if pt is None:
        continue
    pt_unpad = pkcs7_unpad(pt)
    if pt_unpad is None:
        continue
    label = f"HypB(wrap={wrap_name})"
    check_plaintext(label, pt_unpad)

    # HMAC 検証: 候補 sign_key で HMAC(IV||CT) を計算して HMAC_B と比較
    if any(pt_unpad[:16] == enc for enc in KNOWN_ENC_KEYS):
        for sign_name, sign_key in SIGN_KEY_CANDIDATES:
            if verify_hmac(sign_key, IV_B + CT_B, HMAC_B):
                msg = f"[HMAC_VERIFIED] HypB wrap={wrap_name} sign={sign_name}"
                print(msg)
                found.append(msg)

# ===================================================================
# Section 2: 仮説 A — [CT:64B][HMAC:32B] (IV=zeros)
# ===================================================================

print()
print("=" * 70)
print("仮説 A: [CT:64B][HMAC:32B] — IV=zeros_16")
print("  CT   = key336[0:64]")
print("  HMAC = key336[64:96]")
print("=" * 70)

CT_A = KEY336[:64]
HMAC_A = KEY336[64:96]

for wrap_name, wrap_key in WRAP_KEY_CANDIDATES:
    pt = aes_cbc_decrypt(wrap_key, b"\x00" * 16, CT_A)
    if pt is None:
        continue
    pt_unpad = pkcs7_unpad(pt)
    if pt_unpad is None:
        continue
    label = f"HypA(wrap={wrap_name})"
    check_plaintext(label, pt_unpad)

# ===================================================================
# Section 3: 仮説 A2 — [CT:64B][HMAC:32B] (IV=CT[:16])
# ===================================================================

print()
print("=" * 70)
print("仮説 A2: [CT:64B][HMAC:32B] — IV=CT[:16] (先頭 16B を IV として再利用)")
print("=" * 70)

for wrap_name, wrap_key in WRAP_KEY_CANDIDATES:
    pt = aes_cbc_decrypt(wrap_key, CT_A[:16], CT_A[16:])
    if pt is None:
        continue
    pt_unpad = pkcs7_unpad(pt)
    if pt_unpad is None:
        continue
    label = f"HypA2(wrap={wrap_name})"
    check_plaintext(label, pt_unpad)

# ===================================================================
# Section 4: 仮説 C — [IV:16B][CT:64B][HMAC:16B]
#   key 33.6 が 96 bytes では収まらないため、代わりに CT を 48B として残り 16B が HMAC[:16]
# ===================================================================

print()
print("=" * 70)
print("仮説 C: [IV:16B][CT:48B][HMAC:32B] — wrap_key に enc_key_1 を使用")
print("  (Phase 4 では enc_key_1 が wrap_key として使われた)")
print("=" * 70)

# Phase 4 で確認済み: enc_key_1 が AES-CBC 復号鍵として機能
# 同じパターンが Phase 2 にも当てはまるか確認
for iv_val, iv_name in [
    (IV_B, "key336[:16]"),
    (b"\x00" * 16, "zeros"),
    (SERVER_NONCE, "SERVER_NONCE"),
    (CLIENT_NONCE, "CLIENT_NONCE"),
]:
    pt = aes_cbc_decrypt(ENC_KEY_1, iv_val, CT_B)
    if pt is None:
        continue
    pt_unpad = pkcs7_unpad(pt)
    if pt_unpad is None:
        continue
    label = f"HypC(wrap=enc_key_1,iv={iv_name})"
    check_plaintext(label, pt_unpad)
    print(f"  enc_key_1 wrap: iv={iv_name} pt(raw)={pt.hex()}")

# ===================================================================
# Section 5: 全 appboot レスポンスファイルへの適用
# ===================================================================

print()
print("=" * 70)
print("全 appboot レスポンスファイルへの適用")
print("=" * 70)

import gzip

try:
    import cbor2

    RAWS_DIR = Path("/home/vscode/app/raws/ios/20260408/raw")
    res_files = sorted(RAWS_DIR.glob("res_*appboot*.bin"))
    print(f"Found {len(res_files)} appboot response files")

    unique_key336: dict[str, str] = {}  # hex -> filename

    for res_file in res_files:
        raw = res_file.read_bytes()
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                continue
        try:
            obj = cbor2.loads(raw)
        except Exception:
            continue

        k33 = obj.get(33)
        if k33 is None:
            continue
        try:
            if isinstance(k33, bytes):
                inner = cbor2.loads(k33)
            elif isinstance(k33, dict):
                inner = k33
            else:
                continue
        except Exception:
            continue

        k6 = inner.get(6)
        if not isinstance(k6, bytes) or len(k6) != 96:
            continue

        hex_val = k6.hex()
        if hex_val not in unique_key336:
            unique_key336[hex_val] = res_file.name

    print(f"Unique key 33.6 values (96B): {len(unique_key336)}")

    for hex_val, fname in unique_key336.items():
        blob = bytes.fromhex(hex_val)
        iv = blob[:16]
        ct48 = blob[16:64]
        hmac32 = blob[64:96]

        print(f"\n  File: {fname}")
        print(f"  IV:   {iv.hex()}")
        print(f"  CT:   {ct48.hex()}")

        for wrap_name, wrap_key in WRAP_KEY_CANDIDATES:
            pt = aes_cbc_decrypt(wrap_key, iv, ct48)
            if pt is None:
                continue
            pt_unpad = pkcs7_unpad(pt)
            if pt_unpad is None:
                continue
            label = f"File[{fname}] HypB(wrap={wrap_name})"
            check_plaintext(label, pt_unpad)

except ImportError:
    print("[skip] cbor2 not available")

# ===================================================================
# Section 6: HMAC 署名の検証 (独立)
# ===================================================================

print()
print("=" * 70)
print("HMAC 署名の検証 — どの鍵で HMAC(IV||CT) == key336[64:96] になるか")
print("=" * 70)

for sign_name, sign_key in SIGN_KEY_CANDIDATES:
    # 仮説 B: HMAC over IV||CT
    if verify_hmac(sign_key, IV_B + CT_B, HMAC_B):
        msg = f"[HMAC_MATCH HypB IV||CT] sign={sign_name}"
        print(msg)
        found.append(msg)
    # HMAC over CT only
    if verify_hmac(sign_key, CT_B, HMAC_B):
        msg = f"[HMAC_MATCH CT_only] sign={sign_name}"
        print(msg)
        found.append(msg)
    # HMAC over CT_A (full 64B)
    if verify_hmac(sign_key, CT_A, HMAC_A):
        msg = f"[HMAC_MATCH HypA CT64] sign={sign_name}"
        print(msg)
        found.append(msg)
    # HMAC over entire 96 bytes
    if len(KEY336) >= 64 + 32:
        if verify_hmac(sign_key, KEY336[:64], KEY336[64:96]):
            msg = f"[HMAC_MATCH full96[:64]] sign={sign_name}"
            print(msg)
            found.append(msg)

# ===================================================================
# Section 7: 平文構造の仮説追加 — enc_key || sign_key ではなく別の構造
# ===================================================================

print()
print("=" * 70)
print("平文構造の代替仮説テスト")
print("  平文が enc_key(16B) + sign_key(32B) ではなく別の構造の可能性")
print("=" * 70)

for wrap_name, wrap_key in WRAP_KEY_CANDIDATES:
    # 仮説 B の復号
    pt_b = aes_cbc_decrypt(wrap_key, IV_B, CT_B)
    if pt_b is None:
        continue

    # パディングなしで直接確認
    if len(pt_b) == 48:
        # enc_key はどこかにある?
        for offset in range(0, 33):
            for enc in KNOWN_ENC_KEYS:
                if pt_b[offset : offset + 16] == enc:
                    msg = (
                        f"[ENC_AT_OFFSET_{offset}] wrap={wrap_name} enc={enc.hex()[:8]}"
                    )
                    print(msg)
                    found.append(msg)

# ===================================================================
# 結果サマリー
# ===================================================================

print()
print("=" * 70)
print("結果サマリー")
print("=" * 70)
if found:
    print(f"一致 ({len(found)} 件):")
    for item in found:
        print(f"  {item}")
else:
    print("一致なし")
    print()
    print("考察:")
    print()
    print("  1. enc_key_0 (0817065e) と enc_key_1 (97b99f4e) のいずれも")
    print("     key 33.6 の復号で得られなかった。")
    print()
    print("  2. 可能性 A: DH 共有秘密とセッション鍵のペアリングが誤っている")
    print("     (別セッションのデータが混在している)")
    print()
    print("  3. 可能性 B: wrap_key が DH 共有秘密から標準 KDF では導出されない")
    print("     NFWebCrypto 内部の TFIT ホワイトボックス変換が関与")
    print()
    print("  4. 可能性 C: key 33.6 の構造が [IV:16][CT:48][HMAC:32] ではなく")
    print("     全く異なる (例: プロトコル独自の AES Key Wrap)")
    print()
    print("推奨アクション:")
    print("  - Frida で AES_set_decrypt_key の直前の caller を特定する")
    print(
        "  - AES_set_decrypt_key に渡される鍵と key 33.6 の IV/CT を同時キャプチャする"
    )
    print("  - キャプチャした wrap_key を此処の WRAP_KEY_CANDIDATES に追加する")
