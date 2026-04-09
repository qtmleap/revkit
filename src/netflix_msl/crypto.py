"""NetflixCrypto — 暗号化クラス (NetflixCrypto.cpp の再実装)

RSA 鍵生成、AES-CBC 暗号化/復号、HMAC-SHA256 署名を担当。

バイナリ内オフセット:
  +0x20/0x28: encryption_key (AES-128)
  +0x38/0x40: hmac_key (SHA-256)
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from netflix_msl.constants import (
    IOS_DH_G,
    IOS_DH_P,
    IOS_KDF_NONCE,
    IOS_KDF_PSK,
    IOS_KEY336_DEVICE_HEADER,
    RSA_KEYPAIR_ID,
)


@dataclass
class SessionKeys:
    """MSL セッション鍵セット."""

    enc_key: bytes  # AES-128 暗号化鍵 (16 bytes)
    sign_key: bytes  # HMAC-SHA256 署名鍵 (32 bytes)
    bootstrap_key: bytes  # ペイロード全体署名鍵 = Phase 2 sign_key (32 bytes)
    enc_key_1: bytes  # Phase 3 KDF 更新済み暗号化鍵 (16 bytes)
    sign_key_1: bytes  # Phase 3 KDF 更新済み署名鍵 (32 bytes)


class NetflixCrypto:
    """StreamFab の NetflixCrypto クラスに対応."""

    def __init__(self):
        self.encryption_key: bytes | None = None  # AES-128 鍵 (16 bytes)
        self.sign_key: bytes | None = None  # HMAC-SHA256 鍵 (32 bytes)
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.rsa_public_key_b64: str = ""

    # ---- RSA 鍵生成 (get_key_request で使用) ----

    def generate_rsa_keypair(self) -> None:
        """RSA-2048 鍵ペアを生成."""
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        pub_der = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.rsa_public_key_b64 = base64.b64encode(pub_der).decode()

    def get_key_request(self) -> dict:
        """ASYMMETRIC_WRAPPED 鍵交換リクエストデータを生成.

        バイナリ文字列: "ASYMMETRIC_WRAPPED", "JWK_RSA", "rsaKeypairId"
        """
        if not self.rsa_public_key_b64:
            self.generate_rsa_keypair()

        return {
            "scheme": "ASYMMETRIC_WRAPPED",
            "keydata": {
                "publickey": self.rsa_public_key_b64,
                "mechanism": "JWK_RSA",
                "keypairid": RSA_KEYPAIR_ID,
            },
        }

    # ---- RSA 復号 (鍵交換レスポンスの復号) ----

    def rsa_decrypt(self, ciphertext_b64: str) -> bytes:
        """RSA-OAEP でラップされた鍵をアンラップ.

        NetflixCrypto::rsa_decrypt — SHA-1 OAEP (MSL 仕様)。
        """
        ciphertext = base64.b64decode(ciphertext_b64)
        return self.rsa_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

    def _unwrap_jwk_key(self, wrapped_b64: str) -> bytes | None:
        """RSA-OAEP 復号 → JWK JSON パース → Base64url デコードで実際の鍵を取得.

        Netflix の鍵交換レスポンス:
          encryptionkey / hmackey → Base64(RSA-OAEP encrypted JWK JSON)
          RSA decrypt → {"kty":"oct","k":"<base64url-key>","alg":"A128CBC",...}
          actual key  → base64url_decode(jwk["k"])
        """
        if not wrapped_b64:
            return None

        try:
            # RSA-OAEP 復号
            decrypted = self.rsa_decrypt(wrapped_b64)

            # JWK JSON をパース
            import json

            jwk = json.loads(decrypted)
            k_b64url = jwk.get("k", "")
            if not k_b64url:
                return decrypted  # JWK でない場合は生のバイト列を返す

            # Base64url → bytes (パディング追加)
            padding_needed = 4 - len(k_b64url) % 4
            if padding_needed != 4:
                k_b64url += "=" * padding_needed
            return base64.urlsafe_b64decode(k_b64url)

        except (json.JSONDecodeError, ValueError):
            # JWK でない場合 (直接鍵バイト列)
            return self.rsa_decrypt(wrapped_b64) if wrapped_b64 else None

    def parse_key_response(self, key_response_data: dict) -> bool:
        """鍵交換レスポンスを解析し、encryption_key と sign_key を導出.

        バイナリ文字列: "encryptionkey", "hmackey", '"k":"', '"k": "'
        JWK の "k" フィールドから Base64 デコードした値を RSA 復号。
        """
        keydata = key_response_data.get("keydata", {})

        enc_key_wrapped = keydata.get("encryptionkey", "")
        hmac_key_wrapped = keydata.get("hmackey", "")

        # Netflix は encryptionkey/hmackey を Base64 文字列として送信
        # RSA-OAEP 復号すると JWK JSON が得られる: {"kty":"oct","k":"<base64url>","alg":"..."}
        # 実際の鍵は jwk["k"] を Base64url デコードしたもの
        self.encryption_key = self._unwrap_jwk_key(enc_key_wrapped)
        self.sign_key = self._unwrap_jwk_key(hmac_key_wrapped)

        if self.encryption_key:
            print(f"    [Crypto] encryption_key: {len(self.encryption_key) * 8} bit")
        else:
            print("    [Crypto] encryption_key is empty")

        if self.sign_key:
            print(f"    [Crypto] sign_key: {len(self.sign_key) * 8} bit")
        else:
            print("    [Crypto] sign_key is empty")

        return bool(self.encryption_key and self.sign_key)

    # ---- AES-CBC 暗号化 (NetflixCrypto::encrypt → AES::cbc_encrypt) ----

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """AES-128-CBC 暗号化 + PKCS5 パディング.

        Returns: (ciphertext, iv)
        """
        iv = os.urandom(16)
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)

        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        return ciphertext, iv

    # ---- AES-CBC 復号 ----

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """AES-128-CBC 復号 + PKCS5 アンパディング."""
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        pad_len = padded[-1]
        if pad_len > 16 or pad_len == 0:
            return padded
        return padded[:-pad_len]

    # ---- HMAC-SHA256 署名 (NetflixCrypto::sign → hmac::digest → HMAC + EVP_sha256) ----

    def sign(self, data: str) -> str:
        """HMAC-SHA256 で署名し、Base64 エンコードした結果を返す."""
        sig = hmac_mod.new(self.sign_key, data.encode(), hashlib.sha256).digest()
        return base64.b64encode(sig).decode()

    # ---- 鍵の永続化 ----

    def export_keys(self) -> dict:
        """セッション鍵を辞書にエクスポート (save_msl_data 用)."""
        result = {}
        if self.encryption_key:
            result["encryption_key"] = base64.b64encode(self.encryption_key).decode()
        if self.sign_key:
            result["sign_key"] = base64.b64encode(self.sign_key).decode()
        if self.rsa_private_key:
            pem = self.rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            result["rsa_key"] = pem.decode()
        return result

    def import_keys(self, data: dict) -> bool:
        """辞書からセッション鍵をインポート (load_msl_data 用)."""
        enc_b64 = data.get("encryption_key", "")
        sign_b64 = data.get("sign_key", "")
        rsa_pem = data.get("rsa_key", "")

        if enc_b64:
            self.encryption_key = base64.b64decode(enc_b64)
        if sign_b64:
            self.sign_key = base64.b64decode(sign_b64)
        if rsa_pem:
            self.rsa_private_key = serialization.load_pem_private_key(
                rsa_pem.encode(),
                password=None,
            )
            self.rsa_public_key = self.rsa_private_key.public_key()

        return bool(self.encryption_key and self.sign_key)

    # ---- DH 鍵交換 (1024-bit, g=5, Netflix 固有 p) ----

    @staticmethod
    def generate_dh_keypair(
        p: bytes | None = None,
        g: int | None = None,
    ) -> tuple[bytes, bytes]:
        """DH 鍵ペアを生成する.

        Args:
            p: DH 素数 (big-endian bytes)。None の場合は IOS_DH_P 定数を使用。
            g: DH 生成元。None の場合は IOS_DH_G 定数を使用。

        Returns:
            (private_key_bytes, public_key_bytes) — 各 128 bytes (1024-bit)
        """
        p_int = int.from_bytes(p, "big") if p is not None else IOS_DH_P
        g_int = g if g is not None else IOS_DH_G

        params = dh.DHParameterNumbers(p_int, g_int)
        parameters = params.parameters()
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        pn = private_key.private_numbers()
        pub_n = public_key.public_numbers()

        # 1024-bit = 128 bytes に固定長でシリアライズ (big-endian)
        key_len = (p_int.bit_length() + 7) // 8
        priv_bytes = pn.x.to_bytes(key_len, "big")
        pub_bytes = pub_n.y.to_bytes(key_len, "big")
        return priv_bytes, pub_bytes

    @staticmethod
    def compute_dh_shared_secret(
        peer_public: bytes,
        private_key: bytes,
        p: bytes | None = None,
        g: int | None = None,
    ) -> bytes:
        """DH 共有秘密を計算する.

        Args:
            peer_public:  相手の DH 公開鍵 (big-endian bytes, 128 bytes)
            private_key:  自分の DH 秘密鍵 (big-endian bytes, 128 bytes)
            p:            DH 素数 (big-endian bytes)。None の場合は IOS_DH_P 定数を使用。
            g:            DH 生成元。None の場合は IOS_DH_G 定数を使用。

        Returns:
            DH 共有秘密 (big-endian bytes, 128 bytes)
        """
        p_int = int.from_bytes(p, "big") if p is not None else IOS_DH_P
        # g is not needed for DH shared secret computation (peer_pub ^ priv mod p)
        _ = g

        peer_y = int.from_bytes(peer_public, "big")
        priv_x = int.from_bytes(private_key, "big")

        # shared = peer_y ^ priv_x mod p
        shared_int = pow(peer_y, priv_x, p_int)
        key_len = (p_int.bit_length() + 7) // 8
        return shared_int.to_bytes(key_len, "big")

    # ---- 全鍵導出チェーン (Phase 0 MGK → Phase 3 KDF → Phase 2 DH) ----

    @staticmethod
    def derive_full_key_chain(
        enc_key_0: bytes,
        sign_key_0: bytes,
        dh_shared_secret: bytes,
        psk: bytes | None = None,
        nonce: bytes | None = None,
    ) -> "SessionKeys":
        """Phase 3 KDF → Phase 2 DH → SessionKeys の全導出チェーンを実行する.

        実行順序 (msl_key_relationship.md §2):
          Phase 3: kdf_renew(PSK, enc_key_0, sign_key_0, nonce) → enc_key_1, sign_key_1, session_bind
          48B Key: SHA384(session_bind[:16])
          Phase 2: derive_initial_session_keys(48B_KEY, dh_shared_secret)
                   → new_enc_key (enc_key), bootstrap_key (sign_key)

        Args:
            enc_key_0:        Phase 0 MGK 暗号化鍵 (16 bytes)。
                              Frida/Tweak キャプチャまたは TFIT エミュレーションで取得。
            sign_key_0:       Phase 0 MGK 署名鍵 (32 bytes)。
            dh_shared_secret: DH_compute_key() の出力 (128 bytes)。
                              Frida/Tweak キャプチャで取得。
            psk:              Pre-Shared Key (16 bytes)。None の場合は IOS_KDF_PSK を使用。
            nonce:            KDF nonce (16 bytes)。None の場合は IOS_KDF_NONCE を使用。

        Returns:
            SessionKeys: enc_key, sign_key, bootstrap_key, enc_key_1, sign_key_1

        Raises:
            ValueError: 入力長が不正な場合
        """
        if len(enc_key_0) != 16:
            raise ValueError(f"enc_key_0 must be 16 bytes, got {len(enc_key_0)}")
        if len(sign_key_0) != 32:
            raise ValueError(f"sign_key_0 must be 32 bytes, got {len(sign_key_0)}")
        if len(dh_shared_secret) != 128:
            raise ValueError(
                f"dh_shared_secret must be 128 bytes, got {len(dh_shared_secret)}"
            )

        _psk = psk if psk is not None else IOS_KDF_PSK
        _nonce = nonce if nonce is not None else IOS_KDF_NONCE

        # Phase 3: KDF Key Renewal (HMAC-SHA256 chain)
        enc_key_1, sign_key_1 = NetflixCrypto.kdf_renew(
            _psk, enc_key_0, sign_key_0, _nonce
        )

        # 48B Key: SHA384(session_bind[:16])
        key_48b = NetflixCrypto.derive_hmac384_key(_psk, enc_key_0, sign_key_0, _nonce)

        # Phase 2: HMAC-SHA384(48B_KEY, 0x00 || dh_shared_secret)
        enc_key, bootstrap_key = NetflixCrypto.derive_initial_session_keys(
            key_48b, dh_shared_secret
        )

        return SessionKeys(
            enc_key=enc_key,
            sign_key=enc_key_1,  # 初期 MSL 暗号化鍵 = enc_key_1 (Phase 4 で使用)
            bootstrap_key=bootstrap_key,  # ペイロード全体署名鍵 (Phase 5)
            enc_key_1=enc_key_1,
            sign_key_1=sign_key_1,
        )

    # ---- Scheme 5 (DH) KDF: セッション鍵更新 ----

    @staticmethod
    def kdf_renew(
        psk: bytes,
        enc_key: bytes,
        sign_key: bytes,
        nonce: bytes,
    ) -> tuple[bytes, bytes]:
        """Netflix MSL Scheme 5 セッション鍵更新 KDF.

        HMAC-SHA256 チェーンによるカスタム鍵導出。
        標準 HKDF ではなく、NFWebCrypto.framework の
        HMAC_Init_ex/Update/Final を直接使用する独自実装。

        Args:
            psk:      Pre-Shared Key (16 bytes) — DH 共有秘密から導出
            enc_key:  現在の AES-128-CBC 暗号化鍵 (16 bytes)
            sign_key: 現在の HMAC-SHA256 署名鍵 (32 bytes)
            nonce:    サーバー nonce (16 bytes) — key_response_data.9

        Returns:
            (new_enc_key, new_sign_key)
        """
        # Step 1-2: セッションバインド
        session_check = hmac_mod.new(psk, enc_key + sign_key, hashlib.sha256).digest()
        _session_bind = hmac_mod.new(session_check, nonce, hashlib.sha256).digest()

        # Step 3-4: 新しい暗号化鍵
        enc_temp = hmac_mod.new(psk, enc_key, hashlib.sha256).digest()
        new_enc_key = hmac_mod.new(enc_temp, nonce, hashlib.sha256).digest()[:16]

        # Step 5-6: 新しい署名鍵
        sign_temp = hmac_mod.new(psk, sign_key, hashlib.sha256).digest()
        new_sign_key = hmac_mod.new(sign_temp, nonce, hashlib.sha256).digest()

        return new_enc_key, new_sign_key

    # ---- Phase 2: 初期セッション鍵導出 ----

    @staticmethod
    def derive_hmac384_key(
        psk: bytes,
        enc_key_0: bytes,
        sign_key_0: bytes,
        nonce: bytes,
    ) -> bytes:
        """Phase 3 KDF の session_bind から 48B HMAC-SHA384 鍵を導出.

        session_check = HMAC-SHA256(PSK, enc_key_0 || sign_key_0)
        session_bind  = HMAC-SHA256(session_check, nonce)
        48B_key       = SHA384(session_bind[:16])

        Args:
            psk:        Pre-Shared Key (16 bytes)
            enc_key_0:  保存済み暗号化鍵 (16 bytes)
            sign_key_0: 保存済み署名鍵 (32 bytes)
            nonce:      ハードコード nonce (16 bytes)

        Returns:
            48 バイトの HMAC-SHA384 鍵
        """
        session_check = hmac_mod.new(
            psk, enc_key_0 + sign_key_0, hashlib.sha256
        ).digest()
        session_bind = hmac_mod.new(session_check, nonce, hashlib.sha256).digest()
        return hashlib.sha384(session_bind[:16]).digest()

    @staticmethod
    def derive_initial_session_keys(
        tfit_key: bytes,
        dh_shared_secret: bytes,
    ) -> tuple[bytes, bytes]:
        """Phase 2 初期セッション鍵導出.

        HMAC-SHA384(48B_KEY, 0x00 || DH_SHARED_SECRET_128B) → 48 bytes
          enc_key  = output[0:16]   (AES-128 暗号化鍵)
          sign_key = output[16:48]  (HMAC-SHA256 署名鍵)

        48B_KEY は derive_hmac384_key() で導出するか、直接指定する。

        Args:
            tfit_key:         48 バイト HMAC-SHA384 鍵
            dh_shared_secret: DH_compute_key から得た 128 バイト共有秘密

        Returns:
            (enc_key, sign_key) — それぞれ 16 bytes, 32 bytes
        """
        data = b"\x00" + dh_shared_secret
        digest = hmac_mod.new(tfit_key, data, hashlib.sha384).digest()
        enc_key = digest[:16]
        sign_key = digest[16:48]
        return enc_key, sign_key

    # ---- key 33.6 scheme_data 構築 (Scheme 3 / appboot) ----

    @staticmethod
    def build_key336_scheme_data(
        session_region: bytes,
        nonce_7b: bytes,
        s1: bytes,
        s2: bytes,
        s3: bytes,
        k9_xor_nonce: bytes,
    ) -> tuple[bytes, bytes]:
        """iOS appboot の key 33.6 scheme_data (352B) を構築し XOR 暗号化して返す.

        key 33.6 の 352B plaintext は以下の構成を持つ (CBOR truncated stream):

          bytes [0:128]   : 固定デバイスヘッダー (DEVICE_HEADER_128B 定数)
          bytes [128:300] : セッション領域 (172B) — TFIT 暗号化 DH 公開鍵 + セッション状態
          bytes [300:307] : nonce_7b — 7B ランダム nonce (N)
          bytes [307:316] : s1 — 9B セッション固定セパレータ
          bytes [316:323] : N' — nonce 変形 1: N[0]^=0xf4, N[1]^=0x1b, N[2:7] 同一
          bytes [323:332] : s2 — 9B セッション固定セパレータ
          bytes [332:339] : N'' — nonce 変形 2: N[0]^=0xf4, N[1]^=0x1b, N[3]^=0x18,
                                  N[4]^=0x1b, N[2,5,6] 同一
          bytes [339:348] : s3 — 9B セパレータ (byte[5] がリクエスト毎カウンタ)
          bytes [348:352] : tail — N[:4] XOR 0xf31c071f

        XOR 暗号化: ciphertext[i] = plaintext[i] ^ k9_xor_nonce[i % 16]
        (k9_xor_nonce は key 33.9 の 16B XOR nonce)

        引数:
            session_region:  172B セッション領域。Frida キャプチャまたは TFIT エミュレーション
                             で取得した DH 鍵 + セッション状態バイト列。
                             sessions_region = pt[128:300] (XOR 復号後の値)
            nonce_7b:        7B ランダム per-request nonce (N)。毎リクエストで os.urandom(7)。
            s1:              9B セッション固定セパレータ (pt[307:316])
            s2:              9B セッション固定セパレータ (pt[323:332])
            s3:              9B セパレータ (pt[339:348])。byte[5] はリクエスト毎に変化する
                             不透明な CBOR カウンタ値 — セッション初期値を起点に単調増加。
            k9_xor_nonce:    16B per-request XOR nonce (key 33.9)。毎リクエストで生成。

        Returns:
            (scheme_data_enc, k9_xor_nonce)
              scheme_data_enc : 352B XOR 暗号化済み scheme_data (key 33.6 の値)
              k9_xor_nonce    : 入力をそのまま返す (key 33.9 として使用する 16B)

        Raises:
            ValueError: session_region が 172B でない、または nonce が 7B/16B でない場合

        ---
        固定デバイスヘッダー (DEVICE_HEADER_128B):
            165/180 の 352B appboot サンプルで共通の 128B 定数。
            残り 15 サンプルは異なるヘッダーを持つ (デバイス/ビルド依存)。
            標準的な iPhone デバイスではこの定数を使用する。

        セッション領域の取得方法:
            (a) Frida/Tweak キャプチャ: AppbootKeyExtract Tweak で live デバイスから取得
                session_region = captured_pt[128:300]
            (b) TFIT エミュレーション: tools/emulate_tfit.py で NFWebCrypto.framework
                バイナリから WB-AES テーブルを読み込み DH 公開鍵を暗号化

        nonce XOR 変形マスク (実測値):
            n1^n2 = f4 1b 00 00 00 00 00  (165 サンプル全てで一致)
            n1^n3 = f4 1b 00 18 1b 00 00  (165 サンプル全てで一致)
            tail  = N[:4] XOR f3 1c 07 1f  (165 サンプル全てで一致)
        """
        # --- 引数検証 ---
        if len(session_region) != 172:
            raise ValueError(
                f"session_region must be 172 bytes, got {len(session_region)}"
            )
        if len(nonce_7b) != 7:
            raise ValueError(f"nonce_7b must be 7 bytes, got {len(nonce_7b)}")
        if len(s1) != 9 or len(s2) != 9 or len(s3) != 9:
            raise ValueError("s1, s2, s3 must each be 9 bytes")
        if len(k9_xor_nonce) != 16:
            raise ValueError(f"k9_xor_nonce must be 16 bytes, got {len(k9_xor_nonce)}")

        # --- nonce 変形 (CBOR コンテキスト差分マスク) ---
        # n1 = raw nonce N (7B)
        # n2 = N with bytes 0,1 XORed by 0xf4, 0x1b (CBOR int encoding 差分)
        # n3 = N with bytes 0,1 XORed by 0xf4,0x1b and bytes 3,4 XORed by 0x18,0x1b
        _N2_MASK = bytes([0xF4, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00])
        _N3_MASK = bytes([0xF4, 0x1B, 0x00, 0x18, 0x1B, 0x00, 0x00])
        _TAIL_MASK = bytes([0xF3, 0x1C, 0x07, 0x1F])

        n = nonce_7b
        n2 = bytes(a ^ b for a, b in zip(n, _N2_MASK))
        n3 = bytes(a ^ b for a, b in zip(n, _N3_MASK))
        tail = bytes(a ^ b for a, b in zip(n[:4], _TAIL_MASK))

        # --- 平文 352B を組み立て ---
        plaintext = (
            IOS_KEY336_DEVICE_HEADER  # [0:128]   定数ヘッダー
            + session_region  # [128:300] セッション領域
            + n  # [300:307] nonce copy 1
            + s1  # [307:316] separator 1
            + n2  # [316:323] nonce copy 2
            + s2  # [323:332] separator 2
            + n3  # [332:339] nonce copy 3
            + s3  # [339:348] separator 3 (per-req counter)
            + tail  # [348:352] tail
        )
        assert len(plaintext) == 352, f"plaintext length {len(plaintext)} != 352"

        # --- XOR 暗号化 (key 33.9 で平文を XOR) ---
        scheme_data_enc = bytes(plaintext[i] ^ k9_xor_nonce[i % 16] for i in range(352))
        return scheme_data_enc, k9_xor_nonce

    # ---- Scheme 3/5 (DH) 鍵取り込み ----

    def import_session_keys(self, enc_key: bytes, sign_key: bytes) -> None:
        """Frida でキャプチャした鍵素材を直接インポートする (Scheme 3 用).

        enc_key  : AES-128 暗号化鍵 (16 bytes)
        sign_key : HMAC-SHA256 署名鍵 (32 bytes)

        設定後は既存の encrypt / decrypt / sign がそのまま動作する。
        """
        self.encryption_key = enc_key
        self.sign_key = sign_key

    def import_keys_from_file(self, path: str) -> None:
        """鍵素材 JSON を読み込む (Scheme 3 用).

        対応形式:
          Frida: {"enc_key": "<hex>", "sign_key": "<hex>"}
          Tweak: {"session_enc_key": "<hex>", "session_hmac_key": "<hex>", ...}
        """
        import json

        with open(path) as f:
            data = json.load(f)

        enc_hex: str = data.get("enc_key") or data.get("session_enc_key", "")
        sign_hex: str = data.get("sign_key") or data.get("session_hmac_key", "")
        if not enc_hex or not sign_hex:
            raise ValueError(
                "JSON must contain enc_key/sign_key or session_enc_key/session_hmac_key"
            )
        self.import_session_keys(bytes.fromhex(enc_hex), bytes.fromhex(sign_hex))
