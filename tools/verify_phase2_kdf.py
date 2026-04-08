"""Phase 2 初期セッション鍵導出の回帰テスト.

raws/appboot_kdf_fresh.log から抽出した検証済みテストベクタを使用して
NetflixCrypto.derive_initial_session_keys の正確性を確認する。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from netflix_msl.constants import IOS_KDF_NONCE, IOS_KDF_PSK
from netflix_msl.crypto import NetflixCrypto

# ============================================================================
# テストベクタ (raws/appboot_kdf_fresh.log)
# ============================================================================

TFIT_KEY = bytes.fromhex(
    "268ab8d5d6cb36781f4d9b7fdaccd2d692c5b6af0161e640efad7a3bd4958b42"
    "efc7f6ce89f84c0e37bb66794d972819"
)

DH_SHARED_SECRET = bytes.fromhex(
    "6854f0b80187914f2e110cb07fb25e8c65c5a0f591aaf48dec8701128ceefa4f"
    "3aa623796400a6f97e0b6c271c2e39d39432c3c5a82dd1e1301470ae418678b"
    "1b4df554027f35bc872c27de42edea18a928541dfec8c9388b788876529c87e"
    "ec0bc71936013df12d366008005ef4e9f7905520da5170a6e15ae584415fdd175a"
)

EXPECTED_ENC_KEY = bytes.fromhex("d7835418df48f1d54ab54e210cf40fc6")
EXPECTED_SIGN_KEY = bytes.fromhex(
    "794e627118ad213532399d2ecd0c85f90d6739aca767db24d98ef9360bfd956e"
)


def check(label: str, got: bytes, expected: bytes) -> bool:
    ok = got == expected
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {label}")
    if not ok:
        print(f"         expected: {expected.hex()}")
        print(f"         got:      {got.hex()}")
    return ok


def main() -> int:
    print("=== Phase 2 KDF (TFIT / HMAC-SHA384) ===")

    # 入力長の確認
    assert len(TFIT_KEY) == 48, f"TFIT_KEY must be 48 bytes, got {len(TFIT_KEY)}"
    assert len(DH_SHARED_SECRET) == 128, (
        f"DH_SHARED_SECRET must be 128 bytes, got {len(DH_SHARED_SECRET)}"
    )

    enc_key, sign_key = NetflixCrypto.derive_initial_session_keys(
        TFIT_KEY, DH_SHARED_SECRET
    )

    passed = 0
    total = 0

    total += 1
    if check("enc_key  (16B)", enc_key, EXPECTED_ENC_KEY):
        passed += 1

    total += 1
    if check("sign_key (32B)", sign_key, EXPECTED_SIGN_KEY):
        passed += 1

    print()
    print("=== Phase 3 KDF (kdf_renew) チェーン ===")
    print(f"  PSK:   {IOS_KDF_PSK.hex()}")
    print(f"  Nonce: {IOS_KDF_NONCE.hex()}")

    new_enc_key, new_sign_key = NetflixCrypto.kdf_renew(
        IOS_KDF_PSK, enc_key, sign_key, IOS_KDF_NONCE
    )

    # Phase 3 の出力は固定の期待値がないが、長さと非ゼロ性を確認する
    total += 1
    ok_enc = len(new_enc_key) == 16 and new_enc_key != b"\x00" * 16
    print(f"  [{'PASS' if ok_enc else 'FAIL'}] new_enc_key  length=16, non-zero")
    if ok_enc:
        passed += 1
    print(f"         new_enc_key:  {new_enc_key.hex()}")

    total += 1
    ok_sign = len(new_sign_key) == 32 and new_sign_key != b"\x00" * 32
    print(f"  [{'PASS' if ok_sign else 'FAIL'}] new_sign_key length=32, non-zero")
    if ok_sign:
        passed += 1
    print(f"         new_sign_key: {new_sign_key.hex()}")

    print()
    print(f"Result: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
