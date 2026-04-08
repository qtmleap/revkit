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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from netflix_msl.constants import RSA_KEYPAIR_ID


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
