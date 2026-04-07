"""CborMslDecoder — iOS CBOR MSL メッセージの復号パイプライン

iOS Netflix (Argo) が使用する CBOR 形式の MSL メッセージを解析・復号する。

CBOR トップレベル数値キーマッピング (iOS 確認分):
  32  = header / capabilities
  33  = key_request_data / key_response_data (appboot)
  34  = entity_auth_data
  64  = payload_chunk (暗号化ペイロード、通常 MSL メッセージ)
  16  = message signature (HMAC-SHA256, 32 bytes)

payload_chunk 内部キー:
  6   = ciphertext (AES-128-CBC 暗号化データ)
  7   = iv (初期化ベクタ, 16 bytes)
  8   = keyid ({ESN}_{session_index})
  9   = hmac (HMAC-SHA256, 32 bytes)

JSON 形式 MSL との対応 (00_common.md):
  payload → base64 decode → {"ciphertext", "sha256", "keyid", "iv"}
  復号後 → {"data", "messageid", "compressionalgo", "sequencenumber"}
  data → base64 decode → 圧縮展開 (gzip) → JSON ペイロード本体
"""

from __future__ import annotations

import gzip
import hashlib
import hmac as hmac_mod
import json
from typing import Any

import cbor2

from netflix_msl.crypto import NetflixCrypto

# ---------------------------------------------------------------------------
# CBOR 数値キー定数
# ---------------------------------------------------------------------------

KEY_HEADER = 32
KEY_KEY_EXCHANGE = 33
KEY_ENTITY_AUTH = 34
KEY_PAYLOAD_CHUNK = 64
KEY_MESSAGE_SIG = 16

# payload_chunk 内部キー
PAYLOAD_CIPHERTEXT = 6
PAYLOAD_IV = 7
PAYLOAD_KEYID = 8
PAYLOAD_HMAC = 9

# header / capabilities 内部キー
HEADER_CAPABILITIES = 15
HEADER_RENEWABLE = 16

# entity_auth_data 内部キー
ENTITY_SCHEME = 30
ENTITY_AUTH_DATA = 35

# key_exchange 内部キー
KEYEX_SCHEME = 6
KEYEX_KEYDATA = 7
KEYEX_IDENTITY = 8
KEYEX_NONCE = 9


class DecodeError(Exception):
    """CBOR MSL メッセージのパースまたは復号に失敗した場合."""


class VerificationError(Exception):
    """HMAC 検証に失敗した場合."""


class CborMslDecoder:
    """iOS CBOR MSL メッセージを解析・復号するデコーダー."""

    def __init__(self, crypto: NetflixCrypto) -> None:
        """セッション鍵を保持する crypto インスタンスを受け取る.

        crypto.encryption_key と crypto.sign_key が設定済みであること。
        未設定の場合、復号・署名検証は失敗する。
        """
        self.crypto = crypto

    # ------------------------------------------------------------------
    # パブリック API
    # ------------------------------------------------------------------

    def decode_message(self, data: bytes) -> dict[str, Any]:
        """CBOR バイト列を解析してヘッダーとペイロードを分離する.

        Returns:
            {
                "header": dict | bytes | None,
                "entity_auth_data": dict | bytes | None,
                "key_exchange": bytes | None,
                "payload_chunks": list[dict],  # raw CBOR dict (復号前)
                "signature": bytes | None,
                "raw": dict,  # CBOR デコードした生データ
            }
        """
        try:
            raw = cbor2.loads(data)
        except Exception as e:
            raise DecodeError(f"CBOR デコード失敗: {e}") from e

        if not isinstance(raw, dict):
            raise DecodeError(f"トップレベルが dict でない: {type(raw)}")

        header_raw = raw.get(KEY_HEADER)
        entity_auth_raw = raw.get(KEY_ENTITY_AUTH)
        key_exchange_raw = raw.get(KEY_KEY_EXCHANGE)
        sig_raw = raw.get(KEY_MESSAGE_SIG)
        payload_chunk_raw = raw.get(KEY_PAYLOAD_CHUNK)

        # ヘッダーはバイト列 or dict の場合がある
        header = (
            self._try_decode_cbor(header_raw)
            if isinstance(header_raw, bytes)
            else header_raw
        )

        # entity_auth_data はバイト列 or dict
        entity_auth = (
            self._try_decode_cbor(entity_auth_raw)
            if isinstance(entity_auth_raw, bytes)
            else entity_auth_raw
        )

        # payload_chunk は単一 dict の場合と list の場合がある
        if payload_chunk_raw is None:
            chunks = []
        elif isinstance(payload_chunk_raw, list):
            chunks = payload_chunk_raw
        else:
            chunks = [payload_chunk_raw]

        return {
            "header": header,
            "entity_auth_data": entity_auth,
            "key_exchange": key_exchange_raw,
            "payload_chunks": chunks,
            "signature": sig_raw if isinstance(sig_raw, bytes) else None,
            "raw": raw,
        }

    def decrypt_payload(self, encrypted_payload: bytes | dict) -> bytes:
        """payload_chunk から AES-128-CBC 復号を行う.

        encrypted_payload:
          - bytes: CBOR エンコードされた payload_chunk
          - dict:  decode_message() が返す payload_chunks の要素

        Returns:
            PKCS7 アンパディング済みの平文バイト列
        """
        if not self.crypto.encryption_key:
            raise DecodeError(
                "encryption_key が未設定。先に import_session_keys() を呼ぶ。"
            )

        if isinstance(encrypted_payload, bytes):
            chunk = self._try_decode_cbor(encrypted_payload)
            if not isinstance(chunk, dict):
                raise DecodeError("payload_chunk が dict でない")
        else:
            chunk = encrypted_payload

        ciphertext = chunk.get(PAYLOAD_CIPHERTEXT)
        iv = chunk.get(PAYLOAD_IV)

        if not isinstance(ciphertext, bytes):
            raise DecodeError(f"ciphertext が bytes でない: {type(ciphertext)}")
        if not isinstance(iv, bytes) or len(iv) != 16:
            raise DecodeError(f"iv が 16 bytes でない: {iv!r}")

        return self.crypto.decrypt(ciphertext, iv)

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """HMAC-SHA256 でメッセージ署名を検証する.

        data:      署名対象のバイト列
        signature: 検証する HMAC-SHA256 ダイジェスト (32 bytes)
        """
        if not self.crypto.sign_key:
            raise VerificationError(
                "sign_key が未設定。先に import_session_keys() を呼ぶ。"
            )

        expected = hmac_mod.new(self.crypto.sign_key, data, hashlib.sha256).digest()
        return hmac_mod.compare_digest(expected, signature)

    def process_message(self, raw_data: bytes) -> dict[str, Any]:
        """decode → verify → decrypt の一連処理.

        Returns:
            {
                "header": dict | None,
                "entity_auth_data": dict | None,
                "key_exchange": bytes | None,
                "signature_valid": bool | None,   # sign_key 未設定時は None
                "payloads": list[dict],            # 復号・展開済みペイロード
                "raw_message": dict,              # CBOR 生データ
            }

        signature_valid が False でも payloads に復号結果を含める。
        """
        msg = self.decode_message(raw_data)

        # 署名検証 (sign_key があれば)
        sig_valid: bool | None = None
        sig = msg["signature"]
        if sig is not None and self.crypto.sign_key:
            # 署名対象はトップレベル CBOR から signature フィールドを除いたデータ。
            # 実際の計算方法は未確認のため、CBOR 全体に対して検証を試みる。
            # 検証失敗しても復号は続行する。
            try:
                sig_valid = self.verify_signature(raw_data, sig)
            except VerificationError:
                sig_valid = False

        # ペイロード復号
        payloads: list[dict] = []
        for chunk in msg["payload_chunks"]:
            try:
                plaintext = self.decrypt_payload(chunk)
                parsed = self._parse_plaintext(plaintext)
                payloads.append(parsed)
            except (DecodeError, Exception) as e:
                payloads.append({"_error": str(e), "_raw_chunk": chunk})

        return {
            "header": msg["header"],
            "entity_auth_data": msg["entity_auth_data"],
            "key_exchange": msg["key_exchange"],
            "signature_valid": sig_valid,
            "payloads": payloads,
            "raw_message": msg["raw"],
        }

    # ------------------------------------------------------------------
    # 内部ヘルパー
    # ------------------------------------------------------------------

    @staticmethod
    def _try_decode_cbor(data: bytes) -> Any:
        """bytes を CBOR デコードして返す。失敗時は元の bytes を返す."""
        if not isinstance(data, bytes):
            return data
        try:
            return cbor2.loads(data)
        except Exception:
            return data

    @staticmethod
    def _parse_plaintext(plaintext: bytes) -> dict[str, Any]:
        """復号後の平文を解析する.

        復号後のフォーマット (00_common.md §1.3):
          JSON: {"data": "<base64>", "messageid": int, "compressionalgo": str, "sequencenumber": int}
          data → base64 decode → gzip 展開 (compressionalgo が gzip の場合) → JSON

        CBOR の場合もあるため両方を試みる。
        """
        # JSON を試みる
        try:
            outer = json.loads(plaintext)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # JSON でなければ CBOR を試みる
            try:
                outer = cbor2.loads(plaintext)
            except Exception:
                return {"_raw_bytes": plaintext.hex(), "_size": len(plaintext)}

        if not isinstance(outer, dict):
            return {"_decoded": outer}

        # "data" フィールドを展開
        import base64

        data_field = outer.get("data", "")
        if not data_field:
            return outer

        try:
            if isinstance(data_field, str):
                raw_data = base64.b64decode(data_field)
            elif isinstance(data_field, bytes):
                raw_data = data_field
            else:
                return outer
        except Exception:
            return outer

        # gzip 展開
        compressionalgo = outer.get("compressionalgo", "")
        if compressionalgo == "GZIP" or (
            len(raw_data) >= 2 and raw_data[:2] == b"\x1f\x8b"
        ):
            try:
                raw_data = gzip.decompress(raw_data)
            except Exception:
                pass  # 展開失敗時はそのまま

        # JSON パース
        try:
            body = json.loads(raw_data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                body = cbor2.loads(raw_data)
            except Exception:
                body = {"_raw_bytes": raw_data.hex(), "_size": len(raw_data)}

        return {
            **{k: v for k, v in outer.items() if k != "data"},
            "body": body,
        }
