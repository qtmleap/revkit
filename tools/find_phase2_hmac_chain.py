#!/usr/bin/env python3
"""
Phase 2 KDF 仮説テスト: Phase 3 HMAC チェーンパターンを DH 共有秘密に適用

Phase 3 KDF (鍵更新) のパターン:
  enc_temp  = HMAC(PSK, enc_key)
  new_enc   = HMAC(enc_temp, nonce)[:16]
  sign_temp = HMAC(PSK, sign_key)
  new_sign  = HMAC(sign_temp, nonce)

仮説: Phase 2 も同様の HMAC チェーン構造を持ち、DH 共有秘密を入力として
PSK と nonce (バイナリ埋め込み固定値) を使ってセッション鍵を導出する。

テストベクター:
  DH shared_secret = 052a8bfe...  (128 bytes)
  Target enc_key   = 97b99f4e88e8e73779aa20ac11877c5d
  Target hmac_key  = d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0
  PSK              = 027617984f6227539a630b897c017d69
  nonce (hardcode) = 809f82a7addf548d3ea9dd067ff9bb91
  server nonce     = e73104a8f4a9ed430d90a330d7978432
  client nonce     = a97e47477522ab39e39b322bdf818031
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import struct

# === キャプチャ済みテストベクター ===

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

# バイナリ埋め込み固定値 (NFWebCrypto.framework @ 0x1ac8f5)
PSK = bytes.fromhex("027617984f6227539a630b897c017d69")
NONCE_HARD = bytes.fromhex("809f82a7addf548d3ea9dd067ff9bb91")

# セッション固有の nonce (appboot レスポンス key 33.9)
SERVER_NONCE = bytes.fromhex("e73104a8f4a9ed430d90a330d7978432")
CLIENT_NONCE = bytes.fromhex("a97e47477522ab39e39b322bdf818031")

# DH private key (Frida ログから取得)
DH_PRIV = bytes.fromhex(
    "4c61046cb05493fcea0b316122849fe0"
    "21cac93bc3858c8c6b43a1fc8329b9be"
    "4ac7d73da8253e491c1b0c8cabf1f614"
    "1144b8cd448821636ceec04105d88b2e"
    "d6a2180994ee41a7be1a7eb0c4f8b866"
    "bc2796e08dd9d2c4b393727e915fa680"
    "dfef7b8115f2a7b3416418048c0a9c9b"
    "4c0ccc1a7a79d38e3cdd6e9f0539020f"
)

# ログで観測された HMAC 鍵 (DH 直後)
HMAC_AFTER_DH = bytes.fromhex(
    "a4333e99a34eef3663f8e38e217e696949cd3bf57598c5c260fedb8997afa82b"
)

found: list[str] = []


def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac_mod.new(key, msg, hashlib.sha256).digest()


def hmac384(key: bytes, msg: bytes) -> bytes:
    return hmac_mod.new(key, msg, hashlib.sha384).digest()


def hmac512(key: bytes, msg: bytes) -> bytes:
    return hmac_mod.new(key, msg, hashlib.sha512).digest()


def check(label: str, derived: bytes) -> bool:
    """enc_key と hmac_key のどちらか、または両方が一致するか確認"""
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
    return matched


# ===================================================================
# Phase 3 パターンをそのまま DH 共有秘密に適用するバリアント
# Phase 3: enc_temp = HMAC(PSK, enc_key), new_enc = HMAC(enc_temp, nonce)[:16]
# 置換: enc_key → DH 共有秘密 (全体または部分)
# ===================================================================

print("=" * 70)
print("1. Phase 3 パターン直接適用 (DH 共有秘密を enc_key の代替として使用)")
print("=" * 70)

# DH 共有秘密の入力バリアント
ss_int = int(DH_SHARED.hex(), 16)
DH_VARIANTS: list[tuple[str, bytes]] = [
    ("raw", DH_SHARED),
    ("pad128", ss_int.to_bytes(128, "big")),
    ("sha256", hashlib.sha256(DH_SHARED).digest()),
    ("sha384", hashlib.sha384(DH_SHARED).digest()),
    ("sha512", hashlib.sha512(DH_SHARED).digest()),
    ("first16", DH_SHARED[:16]),
    ("first32", DH_SHARED[:32]),
    ("last16", DH_SHARED[-16:]),
    ("last32", DH_SHARED[-32:]),
]

# nonce バリアント
NONCE_VARIANTS: list[tuple[str, bytes]] = [
    ("nonce_hard", NONCE_HARD),
    ("server_nonce", SERVER_NONCE),
    ("client_nonce", CLIENT_NONCE),
    ("s+c_nonce", SERVER_NONCE + CLIENT_NONCE),
    ("c+s_nonce", CLIENT_NONCE + SERVER_NONCE),
    ("hard+server", NONCE_HARD + SERVER_NONCE),
    ("server+hard", SERVER_NONCE + NONCE_HARD),
]

# PSK バリアント
PSK_VARIANTS: list[tuple[str, bytes]] = [
    ("PSK", PSK),
    ("SHA256(PSK)", hashlib.sha256(PSK).digest()),
    ("DH_SHARED", DH_SHARED),
    ("DH[:16]", DH_SHARED[:16]),
    ("DH[:32]", DH_SHARED[:32]),
    ("SHA256(DH)", hashlib.sha256(DH_SHARED).digest()),
    ("HMAC_AFTER_DH", HMAC_AFTER_DH),
    ("HMAC_AFTER_DH[:16]", HMAC_AFTER_DH[:16]),
]

for psk_name, psk_val in PSK_VARIANTS:
    for dh_name, dh_val in DH_VARIANTS:
        for nonce_name, nonce_val in NONCE_VARIANTS:
            try:
                # Phase 3 パターン: HMAC(psk, dh_input) → temp, HMAC(temp, nonce) → key
                temp = hmac256(psk_val, dh_val)
                key_full = hmac256(temp, nonce_val)
                label = f"Phase3({psk_name},{dh_name},{nonce_name})"
                check(label, key_full + b"\x00" * 32)  # enc[:16] check
            except Exception:
                pass

print()
print("=" * 70)
print("2. Phase 3 の 2 段チェーン (enc と hmac を別々に導出)")
print("   enc_key = HMAC(HMAC(psk, dh), nonce)[:16]")
print("   hmac_key = HMAC(HMAC(psk, dh2), nonce)")
print("=" * 70)

# DH 入力を分割して enc と hmac を別々に導出するバリアント
DH_SPLIT_PAIRS: list[tuple[str, bytes, str, bytes]] = [
    # (enc_input_name, enc_input, hmac_input_name, hmac_input)
    ("DH_raw", DH_SHARED, "DH_raw", DH_SHARED),
    ("DH_first32", DH_SHARED[:32], "DH_last32", DH_SHARED[-32:]),
    ("DH_raw", DH_SHARED, "SHA256(DH)", hashlib.sha256(DH_SHARED).digest()),
    ("SHA256(DH)", hashlib.sha256(DH_SHARED).digest(), "DH_raw", DH_SHARED),
    ("DH_first16", DH_SHARED[:16], "DH_last32", DH_SHARED[-32:]),
    (
        "SHA256(DH)[:32]",
        hashlib.sha256(DH_SHARED).digest()[:32],
        "SHA256(DH)[32:]",
        hashlib.sha256(DH_SHARED).digest()[32:] + b"\x00" * 32,
    ),
]

for psk_name, psk_val in PSK_VARIANTS:
    for enc_inp_name, enc_inp, hmac_inp_name, hmac_inp in DH_SPLIT_PAIRS:
        for nonce_name, nonce_val in NONCE_VARIANTS:
            try:
                enc_temp = hmac256(psk_val, enc_inp)
                new_enc = hmac256(enc_temp, nonce_val)[:16]

                hmac_temp = hmac256(psk_val, hmac_inp)
                new_hmac = hmac256(hmac_temp, nonce_val)

                label = f"Phase3_split({psk_name},enc={enc_inp_name},hmac={hmac_inp_name},{nonce_name})"
                if new_enc == TARGET_ENC and new_hmac == TARGET_HMAC:
                    msg = f"[FULL MATCH] {label}"
                    print(msg)
                    found.append(msg)
                elif new_enc == TARGET_ENC:
                    msg = f"[ENC_ONLY] {label}  hmac={new_hmac.hex()[:16]}"
                    print(msg)
                    found.append(msg)
                elif new_hmac == TARGET_HMAC:
                    msg = f"[HMAC_ONLY] {label}  enc={new_enc.hex()}"
                    print(msg)
                    found.append(msg)
            except Exception:
                pass

print()
print("=" * 70)
print("3. カウンタ付き HMAC チェーン (NIST 風)")
print("   T(i) = HMAC(PSK, T(i-1) || counter || DH_shared)")
print("=" * 70)

COUNTER_FORMATS: list[tuple[str, bytes]] = [
    ("1", b"\x01"),
    ("2", b"\x02"),
    ("01_be32", struct.pack(">I", 1)),
    ("02_be32", struct.pack(">I", 2)),
]

for psk_name, psk_val in [
    ("PSK", PSK),
    ("SHA256(DH)", hashlib.sha256(DH_SHARED).digest()),
    ("DH[:32]", DH_SHARED[:32]),
]:
    for dh_name, dh_val in DH_VARIANTS[:4]:
        for nonce_name, nonce_val in NONCE_VARIANTS[:4]:
            for cnt_name, cnt_val in COUNTER_FORMATS:
                try:
                    # T(1) = HMAC(PSK, counter || DH)
                    t1 = hmac256(psk_val, cnt_val + dh_val)
                    check(
                        f"CounterKDF_T1(psk={psk_name},dh={dh_name},cnt={cnt_name})",
                        t1 + b"\x00" * 32,
                    )

                    # T(1) = HMAC(PSK, DH || counter)
                    t1b = hmac256(psk_val, dh_val + cnt_val)
                    check(
                        f"CounterKDF_T1b(psk={psk_name},dh={dh_name},cnt={cnt_name})",
                        t1b + b"\x00" * 32,
                    )

                    # Two-step: T1 = HMAC(psk, dh), T2 = HMAC(T1, nonce || counter)
                    t1c = hmac256(psk_val, dh_val)
                    t2c = hmac256(t1c, nonce_val + cnt_val)
                    check(
                        f"TwoStep_nonce_cnt(psk={psk_name},dh={dh_name},nonce={nonce_name},cnt={cnt_name})",
                        t2c + b"\x00" * 32,
                    )

                    # Two-step: T1 = HMAC(psk, dh), T2 = HMAC(T1, counter || nonce)
                    t2d = hmac256(t1c, cnt_val + nonce_val)
                    check(
                        f"TwoStep_cnt_nonce(psk={psk_name},dh={dh_name},nonce={nonce_name},cnt={cnt_name})",
                        t2d + b"\x00" * 32,
                    )
                except Exception:
                    pass

print()
print("=" * 70)
print("4. 3 段チェーン (セッションバインド風)")
print("   session_check = HMAC(PSK, DH_shared)")
print("   session_bind  = HMAC(session_check, nonce)")
print("   enc_key       = HMAC(session_bind, DH_shared)[:16]  など")
print("=" * 70)

for psk_name, psk_val in [
    ("PSK", PSK),
    ("SHA256(DH)", hashlib.sha256(DH_SHARED).digest()),
]:
    for dh_name, dh_val in DH_VARIANTS[:5]:
        for nonce_name, nonce_val in NONCE_VARIANTS[:5]:
            try:
                step1 = hmac256(psk_val, dh_val)
                step2 = hmac256(step1, nonce_val)

                # step2 から enc/hmac を導出
                enc_candidate = step2[:16]
                hmac_candidate = step2

                if enc_candidate == TARGET_ENC:
                    msg = f"[3STEP_ENC_MATCH step2[:16]] psk={psk_name},dh={dh_name},nonce={nonce_name}"
                    print(msg)
                    found.append(msg)

                if hmac_candidate == TARGET_HMAC:
                    msg = f"[3STEP_HMAC_MATCH step2] psk={psk_name},dh={dh_name},nonce={nonce_name}"
                    print(msg)
                    found.append(msg)

                # step3 = HMAC(step2, DH) など
                step3_a = hmac256(step2, dh_val)
                check(
                    f"3step_enc3a(psk={psk_name},dh={dh_name},nonce={nonce_name})",
                    step3_a + b"\x00" * 32,
                )

                step3_b = hmac256(step2, psk_val)
                check(
                    f"3step_enc3b(psk={psk_name},dh={dh_name},nonce={nonce_name})",
                    step3_b + b"\x00" * 32,
                )
            except Exception:
                pass

print()
print("=" * 70)
print("5. DH private key を PSK として使用するバリアント")
print("=" * 70)

for dh_input_name, dh_input in [
    ("DH_SHARED", DH_SHARED),
    ("SHA256(DH_SHARED)", hashlib.sha256(DH_SHARED).digest()),
]:
    for nonce_name, nonce_val in NONCE_VARIANTS[:5]:
        try:
            # priv_key 全体を使う
            temp = hmac256(DH_PRIV, dh_input)
            key_out = hmac256(temp, nonce_val)
            check(
                f"PrivKey_as_PSK({dh_input_name},{nonce_name})", key_out + b"\x00" * 32
            )

            # priv_key[:16] を使う
            temp2 = hmac256(DH_PRIV[:16], dh_input)
            key_out2 = hmac256(temp2, nonce_val)
            check(
                f"PrivKey[:16]_as_PSK({dh_input_name},{nonce_name})",
                key_out2 + b"\x00" * 32,
            )
        except Exception:
            pass

print()
print("=" * 70)
print("6. HMAC_AFTER_DH (ログ観測値 a4333e...) を PSK として使用")
print("   観測: DH 計算直後に key=a4333e... の HMAC が呼ばれた")
print("   仮説: この HMAC が NFWebCrypto 内部 KDF の最初のステップ出力")
print("=" * 70)

# HMAC_AFTER_DH は Frida で DH_compute_key の直後に記録された HMAC の key
# これ自体が PSK または中間鍵の可能性

for dh_name, dh_val in DH_VARIANTS:
    for nonce_name, nonce_val in NONCE_VARIANTS:
        try:
            # HMAC_AFTER_DH が PSK の役割
            temp = hmac256(HMAC_AFTER_DH, dh_val)
            key_out = hmac256(temp, nonce_val)
            check(f"HMAC_AfterDH_asPSK({dh_name},{nonce_name})", key_out + b"\x00" * 32)

            # HMAC_AFTER_DH[:16] が PSK の役割
            temp2 = hmac256(HMAC_AFTER_DH[:16], dh_val)
            key_out2 = hmac256(temp2, nonce_val)
            check(
                f"HMAC_AfterDH[:16]_asPSK({dh_name},{nonce_name})",
                key_out2 + b"\x00" * 32,
            )

            # HMAC_AFTER_DH が DH 入力の役割 (PSK は固定値)
            temp3 = hmac256(PSK, HMAC_AFTER_DH)
            key_out3 = hmac256(temp3, nonce_val)
            check(f"PSK_HMAC_AfterDH_asInput({nonce_name})", key_out3 + b"\x00" * 32)
        except Exception:
            pass

print()
print("=" * 70)
print("7. SHA-384 ベース HMAC チェーン")
print("   MSL Java 参照実装では SHA-384 を使用するため")
print("=" * 70)

for psk_name, psk_val in [
    ("PSK", PSK),
    ("SHA384(DH)", hashlib.sha384(DH_SHARED).digest()),
]:
    for dh_name, dh_val in DH_VARIANTS[:5]:
        for nonce_name, nonce_val in NONCE_VARIANTS[:4]:
            try:
                # SHA-384 ベース 2 段チェーン
                temp = hmac384(psk_val, dh_val)
                key_out = hmac384(temp, nonce_val)
                label = f"HMAC384_chain(psk={psk_name},dh={dh_name},nonce={nonce_name})"
                # enc_key は 16 bytes, hmac_key は 32 bytes
                enc_candidate = key_out[:16]
                if enc_candidate == TARGET_ENC:
                    print(f"[ENC384_MATCH] {label}")
                    found.append(f"ENC384: {label}")
            except Exception:
                pass

print()
print("=" * 70)
print("8. MSL spec HMAC_MASTER_SECRET 風")
print('   HMAC("MASTER_SECRET" || PSK || nonce, DH_shared)')
print("=" * 70)

label_variants: list[tuple[str, bytes]] = [
    ("MASTER_SECRET", b"MASTER_SECRET"),
    ("master_secret", b"master_secret"),
    ("MSL", b"MSL"),
    ("Netflix", b"Netflix"),
    ("Netflix MSL", b"Netflix MSL"),
    ("session", b"session"),
    ("appboot", b"appboot"),
    ("scheme5", b"scheme5"),
    ("b5", b"5"),
    ("empty", b""),
]

for lbl_name, lbl_val in label_variants:
    for nonce_name, nonce_val in NONCE_VARIANTS:
        try:
            # 複合 info: label || PSK || nonce
            info_a = lbl_val + PSK + nonce_val
            h = hmac256(DH_SHARED, info_a)
            check(
                f"HMAC(DH,label+PSK+nonce)[lbl={lbl_name},{nonce_name}]",
                h + b"\x00" * 32,
            )

            # 複合 info: label || nonce || PSK
            info_b = lbl_val + nonce_val + PSK
            h2 = hmac256(DH_SHARED, info_b)
            check(
                f"HMAC(DH,label+nonce+PSK)[lbl={lbl_name},{nonce_name}]",
                h2 + b"\x00" * 32,
            )

            # 複合 info: PSK || label || nonce
            info_c = PSK + lbl_val + nonce_val
            h3 = hmac256(DH_SHARED, info_c)
            check(
                f"HMAC(DH,PSK+label+nonce)[lbl={lbl_name},{nonce_name}]",
                h3 + b"\x00" * 32,
            )

            # key = PSK, msg = label || DH_shared || nonce
            h4 = hmac256(PSK, lbl_val + DH_SHARED + nonce_val)
            check(
                f"HMAC(PSK,label+DH+nonce)[lbl={lbl_name},{nonce_name}]",
                h4 + b"\x00" * 32,
            )

            # key = nonce, msg = label || DH_shared
            h5 = hmac256(nonce_val, lbl_val + DH_SHARED)
            check(
                f"HMAC(nonce,label+DH)[lbl={lbl_name},{nonce_name}]", h5 + b"\x00" * 32
            )
        except Exception:
            pass

print()
print("=" * 70)
print("9. 入出力順序を入れ替えた全バリアント (HMAC(A, B) vs HMAC(B, A))")
print("=" * 70)

all_values: list[tuple[str, bytes]] = [
    ("DH", DH_SHARED),
    ("PSK", PSK),
    ("NONCE_HARD", NONCE_HARD),
    ("SERVER_NONCE", SERVER_NONCE),
    ("CLIENT_NONCE", CLIENT_NONCE),
    ("SHA256(DH)", hashlib.sha256(DH_SHARED).digest()),
    ("SHA384(DH)", hashlib.sha384(DH_SHARED).digest()),
    ("HMAC_AFTER_DH", HMAC_AFTER_DH),
]

for i, (a_name, a_val) in enumerate(all_values):
    for j, (b_name, b_val) in enumerate(all_values):
        if i == j:
            continue
        try:
            # HMAC(A, B) → check if enc_key candidate
            h = hmac256(a_val, b_val)
            if h[:16] == TARGET_ENC or h == TARGET_HMAC:
                check(f"HMAC256({a_name},{b_name})", h + b"\x00" * 32)
        except Exception:
            pass

print()
print("=" * 70)
print("10. pre_appboot HMAC 中間値を PSK 代替として使用")
print("    ログ: DH_compute_key 直前の 3 つの HMAC 出力値 (phase=pre_appboot)")
print("    仮説: これらは NFWebCrypto 内の KDF 中間ステップ出力")
print("=" * 70)

# pre_appboot HMAC keys (hmac_key_history の pre_appboot フェーズ)
PRE_APPBOOT_HMACS: list[tuple[str, bytes]] = [
    (
        "pre_hmac_0",
        bytes.fromhex(
            "19def2f90d06bc8dfd04a19dbd4588d4e7b8aa6ccacb200f9ae6acc49355917d"
        ),
    ),
    (
        "pre_hmac_1",
        bytes.fromhex(
            "e60e376f37d7d962512aea2f29a353c28b0fb95b1e77c43baf7459b21d1df649"
        ),
    ),
    (
        "pre_hmac_2",
        bytes.fromhex(
            "58c4e3d1cc2ce7bd73e846a1c3b00a9986aa039302d7bbf1a5508d5f9a49120f"
        ),
    ),
]

# enc_key_0 (DH 直後に最初に観測された AES-128 鍵)
ENC_KEY_0 = bytes.fromhex("0817065e29e6d1c8668473af9e13b3c2")

# post_appboot で初めて観測された HMAC 鍵 (sign_key_0 候補)
SIGN_KEY_0_CANDIDATES: list[tuple[str, bytes]] = [
    (
        "sign_key_0a",
        bytes.fromhex(
            "91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1"
        ),
    ),
    (
        "sign_key_0b",
        bytes.fromhex(
            "38b2030dd55e3367290213ca0d16ee079524ccd24fb7221a52145fb6de016fd8"
        ),
    ),
    (
        "sign_key_0c",
        bytes.fromhex(
            "05ffd2d7407a6da255dfd89cde00504d1803ed81a8e5c17ea196c4498d01d825"
        ),
    ),
]

for pre_name, pre_val in PRE_APPBOOT_HMACS:
    for dh_name, dh_val in DH_VARIANTS[:5]:
        for nonce_name, nonce_val in NONCE_VARIANTS[:5]:
            try:
                # pre_hmac を PSK として使う Phase 3 スタイルのチェーン
                temp = hmac256(pre_val, dh_val)
                key_out = hmac256(temp, nonce_val)
                check(
                    f"PreHMAC_asPSK({pre_name},{dh_name},{nonce_name})",
                    key_out + b"\x00" * 32,
                )

                # pre_hmac を最終段の入力として使う
                temp2 = hmac256(PSK, pre_val)
                key_out2 = hmac256(temp2, nonce_val)
                check(f"PSK_PreHMAC({pre_name},{nonce_name})", key_out2 + b"\x00" * 32)

                # pre_hmac そのものをチェック (enc または hmac として)
                if pre_val[:16] == TARGET_ENC:
                    msg = f"[PRE_HMAC_IS_ENC_KEY] {pre_name}"
                    print(msg)
                    found.append(msg)
                if pre_val == TARGET_HMAC:
                    msg = f"[PRE_HMAC_IS_HMAC_KEY] {pre_name}"
                    print(msg)
                    found.append(msg)
            except Exception:
                pass

print()
print("=" * 70)
print("11. enc_key_0 (0817065e) を起点とした逆算")
print("    enc_key_0 は DH 計算後最初に観測された AES 鍵")
print("    仮説: key 33.6 は enc_key_0 で復号される")
print("=" * 70)

for nonce_name, nonce_val in NONCE_VARIANTS:
    try:
        # Phase 3 パターン: DH → enc_key_0
        for dh_name, dh_val in DH_VARIANTS:
            temp = hmac256(PSK, dh_val)
            key_out = hmac256(temp, nonce_val)
            if key_out[:16] == ENC_KEY_0:
                msg = f"[ENC_KEY_0 DERIVED] Phase3(PSK,{dh_name},{nonce_name}) → enc_key_0"
                print(msg)
                found.append(msg)
    except Exception:
        pass

print()
print("=" * 70)
print("12. Phase 3 パターンで enc_key_0 / sign_key_0 の整合性確認")
print("    enc_key_1 = Phase3(PSK, enc_key_0, nonce_hard) 確認")
print("=" * 70)

# enc_key_1 = Phase3(PSK, enc_key_0, nonce_hard) であることを確認
enc_temp_check = hmac256(PSK, ENC_KEY_0)
enc_key_1_check = hmac256(enc_temp_check, NONCE_HARD)
print(f"Phase3(PSK, enc_key_0, nonce_hard)[:16] = {enc_key_1_check[:16].hex()}")
print(f"TARGET_ENC (enc_key_1)                  = {TARGET_ENC.hex()}")
print(f"Match: {enc_key_1_check[:16] == TARGET_ENC}")
print()

# sign_key_0 の候補それぞれで Phase 3 を試して sign_key_1 = d45443fa を確認
print("sign_key_0 候補から sign_key_1 への Phase 3 確認:")
for sk0_name, sk0_val in SIGN_KEY_0_CANDIDATES:
    try:
        sign_temp = hmac256(PSK, sk0_val)
        new_sign = hmac256(sign_temp, NONCE_HARD)
        match = new_sign == TARGET_HMAC
        print(f"  {sk0_name}: Phase3 → {new_sign.hex()[:16]}...  match={match}")
        if match:
            msg = f"[SIGN_KEY_0 FOUND] {sk0_name} → Phase3 → TARGET_HMAC"
            print(msg)
            found.append(msg)
    except Exception:
        pass

print()
print("=" * 70)
print("13. enc_key_0 / sign_key_0 を逆算で特定するための HMAC ブルートフォース")
print("    仮説: DH 共有秘密のどこかから enc_key_0 を切り出せる")
print("=" * 70)

# DH 共有秘密の全 16-byte スライスと enc_key_0 を比較
for offset in range(len(DH_SHARED) - 15):
    if DH_SHARED[offset : offset + 16] == ENC_KEY_0:
        msg = f"[DH_SLICE_MATCH] DH_SHARED[{offset}:{offset + 16}] == enc_key_0"
        print(msg)
        found.append(msg)

# enc_key_0 が HMAC(X, Y) の出力になりうるか: 全 DH 変換 × PSK × nonce
for psk_name, psk_val in PSK_VARIANTS:
    for dh_name, dh_val in DH_VARIANTS:
        for nonce_name, nonce_val in NONCE_VARIANTS:
            try:
                # 1 段: HMAC(psk, dh)[:16] == enc_key_0?
                h1 = hmac256(psk_val, dh_val)
                if h1[:16] == ENC_KEY_0:
                    msg = f"[ENC0_1STEP] HMAC({psk_name},{dh_name})[:16] == enc_key_0"
                    print(msg)
                    found.append(msg)
                # 2 段: HMAC(HMAC(psk, dh), nonce)[:16] == enc_key_0?
                h2 = hmac256(h1, nonce_val)
                if h2[:16] == ENC_KEY_0:
                    msg = f"[ENC0_2STEP] HMAC(HMAC({psk_name},{dh_name}),{nonce_name})[:16] == enc_key_0"
                    print(msg)
                    found.append(msg)
            except Exception:
                pass

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
    print(
        "DH 共有秘密への Phase 3 パターン適用では enc_key / hmac_key が再現できない。"
    )
    print()
    print("次のステップ:")
    print("  1. find_phase2_kdf_variants.py で非 HKDF KDF を試す")
    print("  2. decrypt_key_response.py で key 33.6 の構造を検証する")
    print("  3. Frida でコールスタックを取得して KDF 入力を特定する")
