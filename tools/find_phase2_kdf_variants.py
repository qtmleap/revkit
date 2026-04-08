#!/usr/bin/env python3
"""
Phase 2 KDF 仮説テスト: 非 HKDF 鍵導出アルゴリズムの網羅的試行

テスト対象:
  - NIST SP 800-56C 単一ステップ KDF (SHA-256/SHA-384/SHA-1)
  - ANSI X9.63 KDF
  - 生ハッシュ (SHA-256/SHA-1/SHA-384) の直接切り出し
  - MSL spec 風 HMAC-SHA384("MASTER_SECRET" || PSK || nonce, shared_secret)
  - 連結 KDF (Concatenation KDF)
  - TLS 1.2 PRF (P_SHA256)
  - NIST SP 800-108 Counter/Feedback/Pipeline モード
  - IEEE 1363 KDF1/KDF2

テストベクター:
  DH shared_secret = 052a8bfe... (128 bytes)
  Target enc_key   = 97b99f4e88e8e73779aa20ac11877c5d
  Target hmac_key  = d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0
  PSK              = 027617984f6227539a630b897c017d69
  nonce (hardcode) = 809f82a7addf548d3ea9dd067ff9bb91
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import struct

# === テストベクター ===

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

TARGET_ENC = bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d")
TARGET_HMAC = bytes.fromhex(
    "d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0"
)

PSK = bytes.fromhex("027617984f6227539a630b897c017d69")
NONCE_HARD = bytes.fromhex("809f82a7addf548d3ea9dd067ff9bb91")
SERVER_NONCE = bytes.fromhex("e73104a8f4a9ed430d90a330d7978432")
CLIENT_NONCE = bytes.fromhex("a97e47477522ab39e39b322bdf818031")

ss_int = int(DH_SHARED.hex(), 16)

found: list[str] = []


def check(label: str, derived: bytes) -> bool:
    """enc_key と hmac_key の一致を確認"""
    matched = False
    if len(derived) >= 16 and derived[:16] == TARGET_ENC:
        if len(derived) >= 48 and derived[16:48] == TARGET_HMAC:
            msg = f"[FULL MATCH] {label}"
            print(msg)
            found.append(msg)
            return True
        msg = f"[ENC_ONLY] {label}  rest={derived[16:32].hex()}"
        print(msg)
        found.append(msg)
        matched = True
    if len(derived) >= 32 and derived[:32] == TARGET_HMAC:
        msg = f"[HMAC_ONLY(offset=0)] {label}"
        print(msg)
        found.append(msg)
        matched = True
    # hmac_key が後半に来る場合 (enc_key + hmac_key の順)
    if len(derived) >= 48 and derived[16:48] == TARGET_HMAC:
        msg = f"[HMAC_ONLY(offset=16)] {label}  enc_candidate={derived[:16].hex()}"
        print(msg)
        found.append(msg)
        matched = True
    return matched


# ===================================================================
# 1. NIST SP 800-56C 単一ステップ KDF (ハッシュベース)
#    Z = DH_shared_secret
#    K(i) = Hash(counter || Z || OtherInfo)
#    counter: 4 バイト big-endian から 0x00000001 開始
# ===================================================================

print("=" * 70)
print("1. NIST SP 800-56C 単一ステップ KDF (ハッシュベース)")
print("=" * 70)


def nist_ss_kdf_hash(
    z: bytes,
    other_info: bytes,
    length: int,
    hash_fn,
) -> bytes:
    """NIST SP 800-56C Rev 2 Sec 4: Single-Step KDF (hash-based)"""
    result = b""
    counter = 1
    while len(result) < length:
        msg = struct.pack(">I", counter) + z + other_info
        result += hash_fn(msg).digest()
        counter += 1
    return result[:length]


HASH_VARIANTS: list[tuple[str, object]] = [
    ("SHA1", hashlib.sha1),
    ("SHA256", hashlib.sha256),
    ("SHA384", hashlib.sha384),
    ("SHA512", hashlib.sha512),
]

OTHER_INFO_VARIANTS: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("PSK", PSK),
    ("NONCE_HARD", NONCE_HARD),
    ("SERVER_NONCE", SERVER_NONCE),
    ("PSK+NONCE_HARD", PSK + NONCE_HARD),
    ("PSK+SERVER_NONCE", PSK + SERVER_NONCE),
    ("PSK+CLIENT_NONCE", PSK + CLIENT_NONCE),
    ("NONCE_HARD+PSK", NONCE_HARD + PSK),
    ("SERVER_NONCE+PSK", SERVER_NONCE + PSK),
    ("SERVER_NONCE+CLIENT_NONCE", SERVER_NONCE + CLIENT_NONCE),
    ("CLIENT_NONCE+SERVER_NONCE", CLIENT_NONCE + SERVER_NONCE),
    ("Netflix", b"Netflix"),
    ("Netflix MSL", b"Netflix MSL"),
    ("MSL", b"MSL"),
    ("appboot", b"appboot"),
    ("scheme5", b"scheme5"),
    ("session", b"session"),
    ("PSK+NONCE_HARD+SERVER_NONCE", PSK + NONCE_HARD + SERVER_NONCE),
]

DH_INPUT_VARIANTS: list[tuple[str, bytes]] = [
    ("raw", DH_SHARED),
    ("pad128", ss_int.to_bytes(128, "big")),
    ("sha256", hashlib.sha256(DH_SHARED).digest()),
    ("sha384", hashlib.sha384(DH_SHARED).digest()),
    ("00+raw", b"\x00" + DH_SHARED),
]

for hash_name, hash_fn in HASH_VARIANTS:
    for oi_name, oi_val in OTHER_INFO_VARIANTS:
        for dh_name, dh_val in DH_INPUT_VARIANTS:
            for out_len in [48, 64, 16, 32]:
                try:
                    derived = nist_ss_kdf_hash(dh_val, oi_val, out_len, hash_fn)
                    label = f"NIST_SS_KDF_hash({hash_name},oi={oi_name},dh={dh_name},L={out_len})"
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("2. NIST SP 800-56C 単一ステップ KDF (HMAC ベース)")
print("   K(i) = HMAC(salt, counter || Z || OtherInfo)")
print("=" * 70)


def nist_ss_kdf_hmac(
    z: bytes,
    other_info: bytes,
    length: int,
    salt: bytes,
    hash_name: str = "sha256",
) -> bytes:
    """NIST SP 800-56C Rev 2 Sec 4: Single-Step KDF (HMAC-based)"""
    result = b""
    counter = 1
    while len(result) < length:
        msg = struct.pack(">I", counter) + z + other_info
        result += hmac_mod.new(salt, msg, hash_name).digest()
        counter += 1
    return result[:length]


SALT_VARIANTS: list[tuple[str, bytes]] = [
    ("PSK", PSK),
    ("NONCE_HARD", NONCE_HARD),
    ("SERVER_NONCE", SERVER_NONCE),
    ("zeros16", b"\x00" * 16),
    ("zeros32", b"\x00" * 32),
    ("PSK+NONCE_HARD", PSK + NONCE_HARD),
    ("SHA256(PSK)", hashlib.sha256(PSK).digest()),
]

for hash_name, _ in HASH_VARIANTS:
    hash_str = hash_name.lower()
    for salt_name, salt_val in SALT_VARIANTS:
        for oi_name, oi_val in OTHER_INFO_VARIANTS[:10]:
            for dh_name, dh_val in DH_INPUT_VARIANTS:
                for out_len in [48, 64]:
                    try:
                        derived = nist_ss_kdf_hmac(
                            dh_val, oi_val, out_len, salt_val, hash_str
                        )
                        label = f"NIST_SS_KDF_hmac({hash_name},salt={salt_name},oi={oi_name},dh={dh_name},L={out_len})"
                        check(label, derived)
                    except Exception:
                        pass

print()
print("=" * 70)
print("3. ANSI X9.63 KDF")
print("   Hash(Z || Counter || SharedInfo)")
print("   Counter: 0x00000001 開始")
print("=" * 70)


def ansi_x963_kdf(
    z: bytes,
    shared_info: bytes,
    length: int,
    hash_fn,
) -> bytes:
    """ANSI X9.63 KDF"""
    result = b""
    counter = 1
    while len(result) < length:
        msg = z + struct.pack(">I", counter) + shared_info
        result += hash_fn(msg).digest()
        counter += 1
    return result[:length]


for hash_name, hash_fn in HASH_VARIANTS:
    for si_name, si_val in OTHER_INFO_VARIANTS:
        for dh_name, dh_val in DH_INPUT_VARIANTS:
            for out_len in [48, 64]:
                try:
                    derived = ansi_x963_kdf(dh_val, si_val, out_len, hash_fn)
                    label = (
                        f"ANSI_X963({hash_name},si={si_name},dh={dh_name},L={out_len})"
                    )
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("4. 生ハッシュ直接切り出し (全組み合わせ)")
print("   Hash(Z) または Hash(Z || extra) の各部分を enc/hmac_key として使用")
print("=" * 70)

# ハッシュ入力バリアント
hash_input_variants: list[tuple[str, bytes]] = [
    ("DH", DH_SHARED),
    ("00+DH", b"\x00" + DH_SHARED),
    ("DH+PSK", DH_SHARED + PSK),
    ("PSK+DH", PSK + DH_SHARED),
    ("DH+NONCE_HARD", DH_SHARED + NONCE_HARD),
    ("DH+SERVER_NONCE", DH_SHARED + SERVER_NONCE),
    ("DH+PSK+NONCE_HARD", DH_SHARED + PSK + NONCE_HARD),
    ("DH+PSK+SERVER_NONCE", DH_SHARED + PSK + SERVER_NONCE),
    ("DH+SERVER_NONCE+CLIENT_NONCE", DH_SHARED + SERVER_NONCE + CLIENT_NONCE),
]

for hash_name, hash_fn in HASH_VARIANTS:
    for inp_name, inp_val in hash_input_variants:
        digest = hash_fn(inp_val).digest()
        # 各オフセットから 48 bytes を試す
        for offset in range(0, len(digest) - 15):
            candidate = digest[offset : offset + 48]
            if len(candidate) >= 16:
                label = f"Hash_{hash_name}({inp_name})[{offset}:]"
                check(label, candidate + b"\x00" * 16)

print()
print("=" * 70)
print("5. MSL spec 風 HMAC-SHA384")
print('   HMAC-SHA384("MASTER_SECRET" || PSK || nonce, DH_shared)')
print("   MSL DH 鍵交換の参照: HMAC を使った shared_secret からの鍵導出")
print("=" * 70)

ms_labels: list[tuple[str, bytes]] = [
    ("MASTER_SECRET", b"MASTER_SECRET"),
    ("master secret", b"master secret"),
    ("master_secret", b"master_secret"),
    ("key material", b"key material"),
    ("key_material", b"key_material"),
    ("MSL", b"MSL"),
    ("Netflix MSL key", b"Netflix MSL key"),
    ("Netflix MSL enc key", b"Netflix MSL enc key"),
    ("session keys", b"session keys"),
    ("AES/CBC/PKCS5Padding", b"AES/CBC/PKCS5Padding"),
    ("HmacSHA256", b"HmacSHA256"),
    ("empty", b""),
]

for hash_name, hash_fn in HASH_VARIANTS:
    hash_str = hash_name.lower()
    for lbl_name, lbl_val in ms_labels:
        for nonce_name, nonce_val in [
            ("NONCE_HARD", NONCE_HARD),
            ("SERVER_NONCE", SERVER_NONCE),
            ("PSK+NONCE_HARD", PSK + NONCE_HARD),
        ]:
            for dh_name, dh_val in DH_INPUT_VARIANTS[:3]:
                try:
                    # HMAC(key=label||PSK||nonce, msg=DH)
                    key_material = lbl_val + PSK + nonce_val
                    if key_material:
                        h = hmac_mod.new(key_material, dh_val, hash_str).digest()
                        check(
                            f"MSL_hmac({hash_name},lbl={lbl_name},nonce={nonce_name},dh={dh_name})",
                            h + b"\x00" * 32,
                        )

                    # HMAC(key=DH, msg=label||PSK||nonce)
                    h2 = hmac_mod.new(
                        dh_val, lbl_val + PSK + nonce_val, hash_str
                    ).digest()
                    check(
                        f"MSL_hmac_inv({hash_name},lbl={lbl_name},nonce={nonce_name},dh={dh_name})",
                        h2 + b"\x00" * 32,
                    )

                    # HMAC(key=PSK, msg=label||DH||nonce)
                    h3 = hmac_mod.new(
                        PSK, lbl_val + dh_val + nonce_val, hash_str
                    ).digest()
                    check(
                        f"MSL_hmac_psk({hash_name},lbl={lbl_name},nonce={nonce_name},dh={dh_name})",
                        h3 + b"\x00" * 32,
                    )
                except Exception:
                    pass

print()
print("=" * 70)
print("6. TLS 1.2 PRF (P_SHA256)")
print("   secret = DH_shared, label+seed = 'master secret' || nonce")
print("=" * 70)


def p_hash(secret: bytes, seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """TLS P_hash: HMAC(secret, A(i) || seed)"""
    result = b""
    a = seed  # A(0) = seed
    while len(result) < length:
        a = hmac_mod.new(secret, a, hash_name).digest()  # A(i+1) = HMAC(secret, A(i))
        result += hmac_mod.new(secret, a + seed, hash_name).digest()
    return result[:length]


def tls_prf(
    secret: bytes, label: bytes, seed: bytes, length: int, hash_name: str = "sha256"
) -> bytes:
    return p_hash(secret, label + seed, length, hash_name)


tls_labels_list: list[tuple[str, bytes]] = [
    ("master secret", b"master secret"),
    ("key expansion", b"key expansion"),
    ("client finished", b"client finished"),
    ("Netflix MSL", b"Netflix MSL"),
    ("MSL", b"MSL"),
    ("session", b"session"),
    ("empty", b""),
]

tls_seeds_list: list[tuple[str, bytes]] = [
    ("NONCE_HARD", NONCE_HARD),
    ("SERVER_NONCE", SERVER_NONCE),
    ("PSK", PSK),
    ("PSK+NONCE_HARD", PSK + NONCE_HARD),
    ("PSK+SERVER_NONCE", PSK + SERVER_NONCE),
    ("SERVER+CLIENT", SERVER_NONCE + CLIENT_NONCE),
    ("zeros32", b"\x00" * 32),
    ("empty", b""),
]

for hash_name, _ in [("sha256", None), ("sha384", None), ("sha512", None)]:
    for lbl_name, lbl_val in tls_labels_list:
        for seed_name, seed_val in tls_seeds_list:
            for dh_name, dh_val in DH_INPUT_VARIANTS[:3]:
                try:
                    derived = tls_prf(dh_val, lbl_val, seed_val, 48, hash_name)
                    label = f"TLS_PRF({hash_name},lbl={lbl_name},seed={seed_name},dh={dh_name})"
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("7. NIST SP 800-108 Counter モード KDF (HMAC-SHA256)")
print("   PRF(key, counter || label || 0x00 || context || L)")
print("=" * 70)


def nist_counter_kdf(
    prf_key: bytes,
    label: bytes,
    context: bytes,
    length: int,
    hash_name: str = "sha256",
) -> bytes:
    """NIST SP 800-108 Counter Mode KDF"""
    result = b""
    counter = 1
    L = length * 8  # bit length
    while len(result) < length:
        msg = (
            struct.pack(">I", counter)
            + label
            + b"\x00"
            + context
            + struct.pack(">I", L)
        )
        result += hmac_mod.new(prf_key, msg, hash_name).digest()
        counter += 1
    return result[:length]


counter_keys: list[tuple[str, bytes]] = [
    ("DH", DH_SHARED),
    ("SHA256(DH)", hashlib.sha256(DH_SHARED).digest()),
    ("PSK", PSK),
    ("NONCE_HARD", NONCE_HARD),
]

counter_labels: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("enc", b"enc"),
    ("hmac", b"hmac"),
    ("MSL", b"MSL"),
    ("Netflix", b"Netflix"),
    ("session", b"session"),
]

counter_contexts: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("PSK", PSK),
    ("NONCE_HARD", NONCE_HARD),
    ("SERVER_NONCE", SERVER_NONCE),
    ("PSK+NONCE", PSK + NONCE_HARD),
]

for key_name, key_val in counter_keys:
    for lbl_name, lbl_val in counter_labels:
        for ctx_name, ctx_val in counter_contexts:
            for hash_name in ["sha256", "sha384"]:
                try:
                    derived = nist_counter_kdf(key_val, lbl_val, ctx_val, 48, hash_name)
                    label = f"NIST_Counter({hash_name},key={key_name},lbl={lbl_name},ctx={ctx_name})"
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("8. NIST SP 800-108 Feedback モード KDF (HMAC-SHA256)")
print("   K(i) = PRF(key, K(i-1) || counter || label || 0x00 || context)")
print("=" * 70)


def nist_feedback_kdf(
    prf_key: bytes,
    label: bytes,
    context: bytes,
    length: int,
    iv: bytes = b"",
    hash_name: str = "sha256",
) -> bytes:
    """NIST SP 800-108 Feedback Mode KDF"""
    result = b""
    k_prev = iv
    counter = 1
    while len(result) < length:
        msg = k_prev + struct.pack(">I", counter) + label + b"\x00" + context
        k_i = hmac_mod.new(prf_key, msg, hash_name).digest()
        result += k_i
        k_prev = k_i
        counter += 1
    return result[:length]


for key_name, key_val in counter_keys:
    for lbl_name, lbl_val in counter_labels[:4]:
        for ctx_name, ctx_val in counter_contexts[:3]:
            for iv_name, iv_val in [
                ("empty", b""),
                ("PSK", PSK),
                ("NONCE_HARD", NONCE_HARD),
            ]:
                try:
                    derived = nist_feedback_kdf(key_val, lbl_val, ctx_val, 48, iv_val)
                    label = f"NIST_Feedback(key={key_name},lbl={lbl_name},ctx={ctx_name},iv={iv_name})"
                    check(label, derived)
                except Exception:
                    pass

print()
print("=" * 70)
print("9. IEEE 1363 KDF1 / KDF2")
print("   KDF1: Hash(Z || counter)  (counter 1 byte)")
print("   KDF2: Hash(Z || counter || otherinfo)")
print("=" * 70)


def kdf1(z: bytes, length: int, hash_fn, other_info: bytes = b"") -> bytes:
    """IEEE 1363 KDF1: Hash(Z || counter) — counter 4 byte big-endian"""
    result = b""
    counter = 0
    while len(result) < length:
        result += hash_fn(z + struct.pack(">I", counter) + other_info).digest()
        counter += 1
    return result[:length]


def kdf2(z: bytes, length: int, hash_fn, other_info: bytes = b"") -> bytes:
    """IEEE 1363 KDF2: Hash(counter || Z || otherinfo) — counter 4 byte big-endian from 1"""
    result = b""
    counter = 1
    while len(result) < length:
        result += hash_fn(struct.pack(">I", counter) + z + other_info).digest()
        counter += 1
    return result[:length]


for hash_name, hash_fn in HASH_VARIANTS:
    for oi_name, oi_val in OTHER_INFO_VARIANTS[:8]:
        for dh_name, dh_val in DH_INPUT_VARIANTS[:3]:
            try:
                d1 = kdf1(dh_val, 48, hash_fn, oi_val)
                check(f"KDF1({hash_name},oi={oi_name},dh={dh_name})", d1)

                d2 = kdf2(dh_val, 48, hash_fn, oi_val)
                check(f"KDF2({hash_name},oi={oi_name},dh={dh_name})", d2)
            except Exception:
                pass

print()
print("=" * 70)
print("10. AES-CBC-MAC / CMAC ベース KDF")
print("    AES-CBC(key=PSK or nonce, msg=DH_shared_padded)")
print("=" * 70)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    def aes_cbc_mac(key: bytes, data: bytes) -> bytes:
        """AES-CBC-MAC: 最終ブロックのみ返す"""
        if len(data) % 16 != 0:
            data = data + b"\x00" * (16 - len(data) % 16)
        iv = b"\x00" * 16
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(data) + enc.finalize()
        return ct[-16:]  # 最終ブロック

    cbc_mac_keys: list[tuple[str, bytes]] = [
        ("PSK", PSK),
        ("NONCE_HARD", NONCE_HARD),
        ("SERVER_NONCE", SERVER_NONCE),
        ("SHA256(DH)[:16]", hashlib.sha256(DH_SHARED).digest()[:16]),
    ]

    for key_name, key_val in cbc_mac_keys:
        for dh_name, dh_val in DH_INPUT_VARIANTS[:3]:
            try:
                mac = aes_cbc_mac(key_val, dh_val)
                check(f"AES_CBC_MAC(key={key_name},dh={dh_name})", mac + b"\x00" * 32)
            except Exception:
                pass
except ImportError:
    print("[skip] cryptography not available")

print()
print("=" * 70)
print("11. OpenSSL EVP_KDF 候補: PBKDF2-HMAC")
print("    (パスワード = DH_shared, salt = PSK or nonce)")
print("=" * 70)

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as crypto_hashes

    PBKDF2_SALTS: list[tuple[str, bytes]] = [
        ("PSK", PSK),
        ("NONCE_HARD", NONCE_HARD),
        ("SERVER_NONCE", SERVER_NONCE),
        ("PSK+NONCE", PSK + NONCE_HARD),
        ("zeros16", b"\x00" * 16),
    ]

    PBKDF2_HASH_ALGS = [
        ("SHA256", crypto_hashes.SHA256()),
        ("SHA384", crypto_hashes.SHA384()),
        ("SHA1", crypto_hashes.SHA1()),
    ]

    for hash_name, hash_alg in PBKDF2_HASH_ALGS:
        for salt_name, salt_val in PBKDF2_SALTS:
            for iterations in [1, 2, 100, 1000]:
                for dh_name, dh_val in DH_INPUT_VARIANTS[:3]:
                    try:
                        pbkdf2 = PBKDF2HMAC(
                            algorithm=hash_alg,
                            length=48,
                            salt=salt_val,
                            iterations=iterations,
                        )
                        derived = pbkdf2.derive(dh_val)
                        label = f"PBKDF2({hash_name},salt={salt_name},iter={iterations},dh={dh_name})"
                        check(label, derived)
                    except Exception:
                        pass
except ImportError:
    print("[skip] PBKDF2 not available")

print()
print("=" * 70)
print("12. 生ハッシュ連鎖 (複数ラウンド)")
print("    H1 = Hash(DH), H2 = Hash(H1), ...")
print("    または H1 = Hash(DH || PSK), H2 = Hash(H1 || nonce)")
print("=" * 70)

for hash_name, hash_fn in HASH_VARIANTS:
    for dh_name, dh_val in DH_INPUT_VARIANTS[:4]:
        try:
            h1 = hash_fn(dh_val).digest()
            h2 = hash_fn(h1).digest()
            h3 = hash_fn(h2).digest()

            check(f"Hash_chain2({hash_name},{dh_name})", h2 + b"\x00" * 16)
            check(f"Hash_chain3({hash_name},{dh_name})", h3 + b"\x00" * 16)
            check(f"Hash_chain2({hash_name},{dh_name})[h1+h2]", h1 + h2)

            # DH || PSK のハッシュ連鎖
            h1b = hash_fn(dh_val + PSK).digest()
            h2b = hash_fn(h1b + NONCE_HARD).digest()
            check(f"Hash_chain_with_psk({hash_name},{dh_name})", h1b + h2b)
            check(f"Hash_chain2_psk_nonce({hash_name},{dh_name})", h2b + b"\x00" * 16)

            # Hash(DH || PSK || SERVER_NONCE)
            h1c = hash_fn(dh_val + PSK + SERVER_NONCE).digest()
            check(f"Hash_dh_psk_snonce({hash_name},{dh_name})", h1c + b"\x00" * 16)
        except Exception:
            pass

print()
print("=" * 70)
print("13. RFC 2104 HMAC を PRF として使った手動 HKDF")
print("    Extract: PRK = HMAC(salt, IKM)  ← 既存ツールと重複するが別の salt 試用")
print("    追加テスト: PSK と nonce を salt に使う")
print("=" * 70)

try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    from cryptography.hazmat.primitives import hashes as crypto_hashes

    new_salts: list[tuple[str, bytes]] = [
        ("PSK", PSK),
        ("NONCE_HARD", NONCE_HARD),
        ("SERVER_NONCE", SERVER_NONCE),
        ("PSK+NONCE_HARD", PSK + NONCE_HARD),
        ("SHA256(PSK)", hashlib.sha256(PSK).digest()),
        ("SHA256(PSK+NONCE_HARD)", hashlib.sha256(PSK + NONCE_HARD).digest()),
    ]

    new_infos: list[tuple[str, bytes]] = [
        ("PSK", PSK),
        ("NONCE_HARD", NONCE_HARD),
        ("SERVER_NONCE", SERVER_NONCE),
        ("PSK+NONCE", PSK + NONCE_HARD),
        ("PSK+SERVER_NONCE", PSK + SERVER_NONCE),
        ("empty", b""),
        ("Netflix", b"Netflix"),
        ("MSL", b"MSL"),
        ("appboot", b"appboot"),
        ("scheme5", b"scheme5"),
    ]

    new_hash_algs = [
        ("SHA256", crypto_hashes.SHA256()),
        ("SHA384", crypto_hashes.SHA384()),
        ("SHA512", crypto_hashes.SHA512()),
    ]

    for hash_name, hash_alg in new_hash_algs:
        for salt_name, salt_val in new_salts:
            for info_name, info_val in new_infos:
                for dh_name, dh_val in DH_INPUT_VARIANTS[:4]:
                    try:
                        hkdf = HKDF(
                            algorithm=hash_alg,
                            length=48,
                            salt=salt_val,
                            info=info_val,
                        )
                        derived = hkdf.derive(dh_val)
                        label = f"HKDF_new(h={hash_name},s={salt_name},i={info_name},dh={dh_name})"
                        check(label, derived)
                    except Exception:
                        pass
except ImportError:
    print("[skip] HKDF not available")

print()
print("=" * 70)
print("14. enc_key_0 (0817065e) を別ターゲットとして同じ KDF バリアントを試す")
print(
    "    enc_key_1 (97b99f4e) は Phase 3 KDF 出力だが enc_key_0 (0817065e) の由来は不明"
)
print("    → enc_key_0 が DH 由来なら同じ KDF で見つかるはず")
print("=" * 70)

# enc_key_0: DH 直後に最初に観測された AES-128 鍵
TARGET_ENC_0 = bytes.fromhex("0817065e29e6d1c8668473af9e13b3c2")

found_enc0: list[str] = []


def check_enc0(label: str, derived: bytes) -> bool:
    if len(derived) >= 16 and derived[:16] == TARGET_ENC_0:
        msg = f"[ENC0_MATCH] {label}  rest={derived[16:32].hex() if len(derived) >= 32 else ''}"
        print(msg)
        found_enc0.append(msg)
        return True
    return False


# NIST SS KDF with enc_key_0 as target
for hash_name, hash_fn in HASH_VARIANTS:
    for oi_name, oi_val in OTHER_INFO_VARIANTS[:8]:
        for dh_name, dh_val in DH_INPUT_VARIANTS:
            for out_len in [16, 32, 48]:
                try:
                    derived = nist_ss_kdf_hash(dh_val, oi_val, out_len, hash_fn)
                    check_enc0(
                        f"NIST_SS({hash_name},oi={oi_name},dh={dh_name})", derived
                    )
                except Exception:
                    pass

# ANSI X9.63 with enc_key_0 as target
for hash_name, hash_fn in HASH_VARIANTS:
    for si_name, si_val in OTHER_INFO_VARIANTS[:8]:
        for dh_name, dh_val in DH_INPUT_VARIANTS:
            try:
                derived = ansi_x963_kdf(dh_val, si_val, 48, hash_fn)
                check_enc0(f"ANSI_X963({hash_name},si={si_name},dh={dh_name})", derived)
            except Exception:
                pass

# Direct hash of DH variants
for hash_name, hash_fn in HASH_VARIANTS:
    for inp_name, inp_val in hash_input_variants:
        digest = hash_fn(inp_val).digest()
        for offset in range(0, len(digest) - 15):
            candidate = digest[offset:]
            check_enc0(f"Hash_{hash_name}({inp_name})[{offset}:]", candidate)

if found_enc0:
    print(f"\nenc_key_0 一致 ({len(found_enc0)} 件):")
    for m in found_enc0:
        print(f"  {m}")
else:
    print("enc_key_0 への一致なし")

print()
print("=" * 70)
print("15. AES Key Wrap (RFC 3394) ベースの復号試行")
print("    Key Wrap: kek で session_keys を wrap したもとに戻す")
print("=" * 70)

try:
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap
    from cryptography.hazmat.backends import default_backend

    # 96 bytes の key33.6 を AES Key Wrap でアンラップ試行
    # [CT(64B)][HMAC(32B)] または [IV(16B)][CT(48B)][HMAC(32B)]
    KEY336 = bytes.fromhex(
        "bb73317f907f7a5a3f924bece878d6a6"
        "8db3b8f354d2207a224a323297523f58"
        "2d72dfb28ea593b584d096c861561be8"
        "b7d72ef4dc404e076943130aa0303200"
        "af5d720284876f9b1c076aacc2ad7fc8"
        "6b5a242b0cf9beb28b2a87ad00f3db38"
    )

    # AES Key Wrap では kek で wrapped_key をアンラップ
    # wrapped_key は元データ + 8 bytes の integrity check
    # key33.6 の CT(64B) を wrapped_key として試す (64B = 48B plain + 8B check → 非標準)
    # key33.6 の CT(40B) を wrapped_key として試す (40B = 32B plain + 8B check)

    kek_candidates: list[tuple[str, bytes]] = [
        ("sha256[:16]", hashlib.sha256(DH_SHARED).digest()[:16]),
        ("sha384[:16]", hashlib.sha384(DH_SHARED).digest()[:16]),
        ("sha256[16:32]", hashlib.sha256(DH_SHARED).digest()[16:32]),
        ("PSK", PSK),
        ("NONCE_HARD", NONCE_HARD),
        ("SERVER_NONCE", SERVER_NONCE),
    ]

    # AES Key Wrap は 8 バイト境界の入力が必要; 64B は OK
    for kek_name, kek_val in kek_candidates:
        for ct_slice, ct_name in [
            (KEY336[:64], "CT[:64]"),
            (KEY336[16:64], "CT[16:64]"),
            (KEY336[:40], "CT[:40]"),
        ]:
            try:
                plain = aes_key_unwrap(kek_val, ct_slice, default_backend())
                if len(plain) >= 16 and plain[:16] == TARGET_ENC:
                    msg = f"[KEYWRAP_MATCH_ENC] kek={kek_name} ct={ct_name}"
                    print(msg)
                    found.append(msg)
                elif len(plain) >= 16 and plain[:16] == TARGET_ENC_0:
                    msg = f"[KEYWRAP_MATCH_ENC0] kek={kek_name} ct={ct_name}"
                    print(msg)
                    found.append(msg)
                else:
                    pass  # no match
            except (InvalidUnwrap, ValueError):
                pass
            except Exception:
                pass

    print("AES Key Wrap 試行完了")
except ImportError:
    print("[skip] aes_key_unwrap not available")

print()
print("=" * 70)
print("結果サマリー")
print("=" * 70)
if found:
    print(f"enc_key_1 一致 ({len(found)} 件):")
    for item in found:
        print(f"  {item}")
else:
    print("一致なし")
    print()
    print("非 HKDF 標準 KDF でも enc_key / hmac_key が再現できない。")
    print()
    print("残りの仮説:")
    print("  A. key 33.6 の構造が [IV:16][CT:48][HMAC:32] で、")
    print("     復号鍵が DH 共有秘密からの KDF ではなく別の経路から来ている")
    print("  B. NFWebCrypto 内部のホワイトボックス鍵導出 (TFIT) が関与")
    print("  C. DH 共有秘密と enc_key_0 のペアリング自体が誤っている")
    print()
    print("推奨: decrypt_key_response.py で key 33.6 の復号を試行し、")
    print("  平文が enc_key_0 + sign_key_0 を含むかを確認する")
