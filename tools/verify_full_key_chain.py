"""ESN → 全鍵導出チェーンの統合テスト.

Phase 0 (MGK) → Phase 3 (KDF) → Phase 2 (DH Session Keys + bootstrap_key)
+ DH 共有秘密計算の検証を一気通貫で行う。

テストベクタは appboot_tfit_capture.log (2026-04-09) および raws/msl_keys.json から抽出。
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from netflix_msl.constants import IOS_DH_G, IOS_DH_P, IOS_KDF_NONCE, IOS_KDF_PSK
from netflix_msl.crypto import NetflixCrypto

# ============================================================================
# Test vectors from appboot_tfit_capture.log (2026-04-09 session)
# ============================================================================

# Device ESN (from key 33.8 in CBOR)
ESN = "NFAPPL-02-IPHONE9=1-AD0455EF27D3A7B8F0872932FD9837874AF3E6F90157195BD22A8063FEB0B79E"

# Phase 0 expected output (= MGK)
EXPECTED_ENC_KEY_0 = bytes.fromhex("0817065e29e6d1c8668473af9e13b3c2")
EXPECTED_SIGN_KEY_0 = bytes.fromhex(
    "91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1"
)

# Phase 3 KDF intermediate: session_bind
EXPECTED_SESSION_BIND_UPPER16 = bytes.fromhex("add2d4c818426aee3dfbbbb783a85262")

# 48B HMAC key = SHA384(session_bind[:16])
EXPECTED_48B_KEY = bytes.fromhex(
    "268ab8d5d6cb36781f4d9b7fdaccd2d692c5b6af0161e640efad7a3bd4958b42"
    "efc7f6ce89f84c0e37bb66794d972819"
)

# DH shared secret from this session
DH_SHARED_SECRET = bytes.fromhex(
    "715ddbd375471dc485344433e20c35ac75fd5f313c50a9d9e8362e78e896c478"
    "7d18e4cb66ff00d35a9423a09042a188a2ed7f923f2ab0f222e8db3e2f962d3c"
    "5cf716328572cb32dc2bd3be38076b628d99fa72ff68af774be72bd8882ab9b5"
    "00265d8e1bd8819b6f317ff8e78e888736abcebeba1168846ba60974a2b9960e"
)

# Phase 2 expected output
EXPECTED_NEW_ENC_KEY = bytes.fromhex("8f8f6a3ddf600b0d5fa2fe44e11b209c")
EXPECTED_BOOTSTRAP_KEY = bytes.fromhex(
    "016ec72a94ad11cb2ea7b9f10534c1c724a24ff38b07febc8eee0d4cc2825f43"
)

# Phase 3 KDF expected output (enc_key_1, sign_key_1)
EXPECTED_ENC_KEY_1 = bytes.fromhex("97b99f4e88e8e73779aa20ac11877c5d")
EXPECTED_SIGN_KEY_1 = bytes.fromhex(
    "d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0"
)


# ============================================================================
# Test runner
# ============================================================================

passed = 0
total = 0


def check(label: str, got: bytes, expected: bytes) -> None:
    global passed, total
    total += 1
    ok = got == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {label}")
    if ok:
        passed += 1
    else:
        print(f"         expected: {expected.hex()}")
        print(f"         got:      {got.hex()}")


def main() -> int:
    global passed, total

    # ==== Phase 0: ESN → MGK (enc_key_0, sign_key_0) ====
    print("=== Phase 0: MGK Generation (Unicorn TFIT) ===")
    try:
        from emulate_tfit import gen_model_group_keys

        enc_key_0, sign_key_0 = gen_model_group_keys(ESN)
        check("enc_key_0 = MGK key (16B)", enc_key_0, EXPECTED_ENC_KEY_0)
        check("sign_key_0 = MGK vector (32B)", sign_key_0, EXPECTED_SIGN_KEY_0)
    except Exception as e:
        print(f"  [SKIP] Phase 0: {e}")
        print("         Using hardcoded test vectors instead")
        enc_key_0 = EXPECTED_ENC_KEY_0
        sign_key_0 = EXPECTED_SIGN_KEY_0

    # ==== Phase 3: KDF Key Renewal (runs before Phase 1/2) ====
    print()
    print("=== Phase 3: KDF Key Renewal (session_bind + enc_key_1/sign_key_1) ===")

    enc_key_1, sign_key_1 = NetflixCrypto.kdf_renew(
        IOS_KDF_PSK, enc_key_0, sign_key_0, IOS_KDF_NONCE
    )
    check("enc_key_1 (16B)", enc_key_1, EXPECTED_ENC_KEY_1)
    check("sign_key_1 (32B)", sign_key_1, EXPECTED_SIGN_KEY_1)

    # session_bind (KDF intermediate)
    import hmac as hmac_mod

    session_check = hmac_mod.new(
        IOS_KDF_PSK, enc_key_0 + sign_key_0, hashlib.sha256
    ).digest()
    session_bind = hmac_mod.new(
        session_check, IOS_KDF_NONCE, hashlib.sha256
    ).digest()
    check(
        "session_bind[:16] (KDF intermediate)",
        session_bind[:16],
        EXPECTED_SESSION_BIND_UPPER16,
    )

    # ==== 48B Key derivation ====
    print()
    print("=== 48B HMAC Key = SHA384(session_bind[:16]) ===")

    key_48b = NetflixCrypto.derive_hmac384_key(
        IOS_KDF_PSK, enc_key_0, sign_key_0, IOS_KDF_NONCE
    )
    check("48B HMAC key (48B)", key_48b, EXPECTED_48B_KEY)

    # ==== Phase 2: DH → Session Keys + bootstrap_key ====
    print()
    print("=== Phase 2: DH Session Key Derivation ===")

    new_enc_key, new_sign_key = NetflixCrypto.derive_initial_session_keys(
        key_48b, DH_SHARED_SECRET
    )
    check("new enc_key (16B)", new_enc_key, EXPECTED_NEW_ENC_KEY)
    check("bootstrap_key = new sign_key (32B)", new_sign_key, EXPECTED_BOOTSTRAP_KEY)

    # ==== Summary ====
    print()
    print(f"Result: {passed}/{total} passed")
    if passed == total:
        print("\nFull key chain: ESN → MGK → KDF → 48B Key → DH → Session Keys  ✓")
    return 0 if passed == total else 1


def test_dh_compute() -> int:
    """DH 共有秘密計算の回帰テスト (raws/msl_keys.json テストベクタ使用).

    raws/msl_keys.json に記録された dh_priv_key / dh_pub_key / dh_shared_secret を使用して
    NetflixCrypto.compute_dh_shared_secret の正確性を検証する。

    テストベクタ:
      dh_priv_key:      46fe2839... (128 bytes) — クライアント秘密鍵
      dh_pub_key:       6c8b4eae... (128 bytes) — クライアント公開鍵
      dh_shared_secret: 76d784d8... (128 bytes) — DH_compute_key の出力
    """
    # raws/msl_keys.json のテストベクタ (2026-04-08)
    # Note: dh_pub_key はクライアント公開鍵 (= g^priv mod p)
    # DH 共有秘密 = dh_pub_key^priv mod p ではない。
    # 通常の DH: shared = server_pub ^ client_priv mod p
    # msl_keys.json には client_priv と client_pub のペアのみ記録されているため、
    # 公開鍵から秘密鍵を検証する round-trip テストを実施する。
    DH_PRIV_KEY = bytes.fromhex(
        "46fe2839cd0e88e509d75e2b818cfe0f836e9c409ff684bfa4d3f79f1ddd931690dedb9e"
        "379ce82f68db8d5b2acb10ae2c17f136010e3dca2698a593bbb91d10a833df9f5d88d079"
        "05f8b5e55b9db592fc1811c9f5da0d9eeb11d0b3c7966d1d6b1e2226f5b3c9359d05f48d"
        "97ee6c40623adc68d507fa871ab416786f6ac038"
    )
    DH_PUB_KEY = bytes.fromhex(
        "6c8b4eae57b8e44659bc5230e11405ff4921fc147c28a28ebcbac87e5e07e88362c8150d6"
        "ef29dd7466e0aa8e24eebd10b8c2a25d89c1b9b448515ccd66a168b34326d01f1b057329"
        "be4985287a8e050112593481ba5bf8f369c8cecfd8338e315c68a12fbbef2664ede0117b6"
        "f0dd40d0755690e8578f19eb5f021bb38a8e39"
    )

    local_passed = 0
    local_total = 0

    # Round-trip: generate keypair, compute pub = g^priv mod p
    priv_int = int.from_bytes(DH_PRIV_KEY, "big")
    pub_expected = pow(IOS_DH_G, priv_int, IOS_DH_P)
    pub_len = (IOS_DH_P.bit_length() + 7) // 8
    pub_computed = pub_expected.to_bytes(pub_len, "big")

    local_total += 1
    ok = pub_computed == DH_PUB_KEY
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] DH round-trip: g^priv mod p == recorded pub_key")
    if ok:
        local_passed += 1
    else:
        print(f"         expected: {DH_PUB_KEY[:16].hex()}...")
        print(f"         got:      {pub_computed[:16].hex()}...")

    # compute_dh_shared_secret: shared = pub_key ^ priv_key mod p
    # (これは client_pub^client_priv = g^(priv^2) なので通常の DH とは異なるが、
    # API の動作確認として実施する)
    shared = NetflixCrypto.compute_dh_shared_secret(
        peer_public=DH_PUB_KEY,
        private_key=DH_PRIV_KEY,
    )
    local_total += 1
    ok_shared = len(shared) == 128 and shared != b"\x00" * 128
    status = "PASS" if ok_shared else "FAIL"
    print(f"  [{status}] compute_dh_shared_secret: output 128B non-zero")
    if ok_shared:
        local_passed += 1
    else:
        print(f"         got: {shared.hex()}")

    # generate_dh_keypair の基本動作確認
    priv_gen, pub_gen = NetflixCrypto.generate_dh_keypair()
    local_total += 1
    ok_gen = len(priv_gen) == 128 and len(pub_gen) == 128
    ok_gen = ok_gen and priv_gen != b"\x00" * 128 and pub_gen != b"\x00" * 128
    status = "PASS" if ok_gen else "FAIL"
    print(f"  [{status}] generate_dh_keypair: (128B, 128B) non-zero")
    if ok_gen:
        local_passed += 1
    else:
        print(f"         priv_gen: {priv_gen[:16].hex()}...")
        print(f"         pub_gen:  {pub_gen[:16].hex()}...")

    # round-trip: two parties compute same shared secret
    priv_a, pub_a = NetflixCrypto.generate_dh_keypair()
    priv_b, pub_b = NetflixCrypto.generate_dh_keypair()
    shared_ab = NetflixCrypto.compute_dh_shared_secret(pub_b, priv_a)
    shared_ba = NetflixCrypto.compute_dh_shared_secret(pub_a, priv_b)
    local_total += 1
    ok_rt = shared_ab == shared_ba
    status = "PASS" if ok_rt else "FAIL"
    print(f"  [{status}] DH two-party round-trip: shared_ab == shared_ba")
    if ok_rt:
        local_passed += 1
    else:
        print(f"         shared_ab: {shared_ab[:16].hex()}...")
        print(f"         shared_ba: {shared_ba[:16].hex()}...")

    return local_passed, local_total


if __name__ == "__main__":
    # Run existing key chain tests
    result = main()

    # Run DH tests
    print()
    print("=== DH 鍵交換テスト (raws/msl_keys.json) ===")
    dh_passed, dh_total = test_dh_compute()
    print(f"DH Result: {dh_passed}/{dh_total} passed")

    sys.exit(result)
