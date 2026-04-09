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

        MSL メッセージは複数の CBOR アイテムが連結されている場合がある:
          Item 0: {32: header, 33: key_exchange, 16: signature}
          Item 1: {64: payload_chunk, 16: signature}

        Returns:
            {
                "header": dict | bytes | None,
                "entity_auth_data": dict | bytes | None,
                "key_exchange": bytes | None,
                "payload_chunks": list[dict],  # raw CBOR dict (復号前)
                "signature": bytes | None,
                "raw": list[dict],  # CBOR デコードした生データ
            }
        """
        from io import BytesIO

        # 連結された CBOR アイテムをすべてデコード
        buf = BytesIO(data)
        cbor_items: list[dict] = []
        while buf.tell() < len(data):
            try:
                item = cbor2.CBORDecoder(buf).decode()
                if isinstance(item, dict):
                    cbor_items.append(item)
                else:
                    break
            except Exception:
                break

        if not cbor_items:
            try:
                raw = cbor2.loads(data)
            except Exception as e:
                raise DecodeError(f"CBOR デコード失敗: {e}") from e
            if not isinstance(raw, dict):
                raise DecodeError(f"トップレベルが dict でない: {type(raw)}")
            cbor_items = [raw]

        # 全アイテムからフィールドを集約
        header_raw = None
        entity_auth_raw = None
        key_exchange_raw = None
        sig_raw = None
        chunks: list = []

        for item in cbor_items:
            if KEY_HEADER in item and header_raw is None:
                header_raw = item[KEY_HEADER]
            if KEY_ENTITY_AUTH in item and entity_auth_raw is None:
                entity_auth_raw = item[KEY_ENTITY_AUTH]
            if KEY_KEY_EXCHANGE in item and key_exchange_raw is None:
                key_exchange_raw = item[KEY_KEY_EXCHANGE]
            if KEY_MESSAGE_SIG in item:
                sig_raw = item[KEY_MESSAGE_SIG]
            if KEY_PAYLOAD_CHUNK in item:
                pc = item[KEY_PAYLOAD_CHUNK]
                if isinstance(pc, list):
                    chunks.extend(pc)
                else:
                    chunks.append(pc)

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

        return {
            "header": header,
            "entity_auth_data": entity_auth,
            "key_exchange": key_exchange_raw,
            "payload_chunks": chunks,
            "signature": sig_raw if isinstance(sig_raw, bytes) else None,
            "raw": cbor_items,
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

        # iOS CBOR format: IV field (key 7) is empty or 1 byte,
        # actual 16-byte IV is prepended to the ciphertext
        if not isinstance(iv, bytes) or len(iv) < 16:
            if len(ciphertext) > 16:
                iv = ciphertext[:16]
                ciphertext = ciphertext[16:]
            else:
                raise DecodeError(
                    f"iv が 16 bytes でなく、ciphertext からも抽出できない: iv={iv!r}"
                )

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
        # mitmproxy がレスポンスを gzip のまま保存する場合がある
        if raw_data[:2] == b"\x1f\x8b":
            raw_data = gzip.decompress(raw_data)

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

    def parse_appboot_response(self, raw: bytes) -> dict:
        """appboot レスポンス CBOR を解析し、鍵交換データを抽出する.

        appboot レスポンス構造 (msl_cbor_key_exchange_analysis.md §1.2):
          {
            33: bytes  ← key_response_data
            16: bytes  ← message signature
            32: dict   ← header (capabilities)
          }

        key_response_data (key 33) の sub-key:
          6: bytes(96)  ← サーバー DH レスポンス (推定: IV(16B) + CT(48B) + HMAC(32B))
          7: bytes(1)   ← ステータスフラグ (0x00)
          8: str        ← スキーム ID ("3" または "5")
          9: bytes(16)  ← サーバー nonce (KDF 入力)

        Args:
            raw: appboot レスポンスの生バイト列 (CBOR 形式)

        Returns:
            {
                "key_response_data": dict | None,  # CBOR デコードされた key_response_data
                "server_scheme_data": bytes | None, # key 33.6 (96B) — サーバー DH レスポンス
                "server_nonce": bytes | None,       # key 33.9 (16B) — サーバー nonce
                "scheme_id": str | None,            # key 33.8 — スキーム ID
                "status_flag": bytes | None,        # key 33.7 — ステータスフラグ
                "header": dict | None,              # CBOR デコードされたヘッダー
                "signature": bytes | None,          # メッセージ署名 (32B)
                "raw_message": list[dict],          # CBOR 生データ
            }

        Raises:
            DecodeError: CBOR デコードまたはパースに失敗した場合
        """
        msg = self.decode_message(raw)

        key_exchange_raw = msg.get("key_exchange")
        key_response_data: dict | None = None
        server_scheme_data: bytes | None = None
        server_nonce: bytes | None = None
        scheme_id: str | None = None
        status_flag: bytes | None = None

        if key_exchange_raw is not None:
            # key_exchange はバイト列の場合 CBOR デコード
            if isinstance(key_exchange_raw, bytes):
                krd = self._try_decode_cbor(key_exchange_raw)
            else:
                krd = key_exchange_raw

            if isinstance(krd, dict):
                key_response_data = krd
                # sub-key 6: サーバー DH レスポンス (96B)
                v6 = krd.get(KEYEX_SCHEME)
                if isinstance(v6, bytes):
                    server_scheme_data = v6

                # sub-key 7: ステータスフラグ
                v7 = krd.get(KEYEX_KEYDATA)
                if isinstance(v7, bytes):
                    status_flag = v7

                # sub-key 8: スキーム ID ("3" / "5")
                v8 = krd.get(KEYEX_IDENTITY)
                if v8 is not None:
                    scheme_id = str(v8)

                # sub-key 9: サーバー nonce (16B)
                v9 = krd.get(KEYEX_NONCE)
                if isinstance(v9, bytes):
                    server_nonce = v9

        return {
            "key_response_data": key_response_data,
            "server_scheme_data": server_scheme_data,
            "server_nonce": server_nonce,
            "scheme_id": scheme_id,
            "status_flag": status_flag,
            "header": msg.get("header"),
            "signature": msg.get("signature"),
            "raw_message": msg.get("raw", []),
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

        復号後のフォーマット:

        1. JSON 形式 (Chrome/Android):
           {"data": "<base64>", "messageid": int, "compressionalgo": str, "sequencenumber": int}
           data → base64 decode → gzip 展開 → JSON

        2. iOS CBOR バイナリフレーム:
           CBOR bstr(9) ヘッダー + CBOR bstr(N) gzip圧縮データ + トレーラー
           構造: [0x49][9-byte header][0x59 LL LL][gzip data][trailer]
        """
        # iOS CBOR バイナリフレーム (リクエスト): 先頭が 0x49 (bstr(9))
        if len(plaintext) > 14 and plaintext[0] == 0x49:
            return CborMslDecoder._parse_ios_binary_frame(plaintext)

        # iOS レスポンス: 00 00 ff + raw deflate 圧縮
        if len(plaintext) > 4 and plaintext[:2] == b"\x00\x00":
            import zlib

            try:
                decompressed = zlib.decompress(plaintext[3:], -15)
                try:
                    body = json.loads(decompressed)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body = {"_raw_text": decompressed.decode("utf-8", errors="replace")}
                return {"body": body, "_compression": "deflate"}
            except zlib.error:
                pass

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

    @staticmethod
    def _parse_ios_binary_frame(plaintext: bytes) -> dict[str, Any]:
        """iOS バイナリフレームを解析する.

        構造: CBOR bstr(9) header + CBOR bstr(N) gzip payload + trailer
        """
        from io import BytesIO

        buf = BytesIO(plaintext)
        result: dict[str, Any] = {}

        try:
            # 先頭の bstr(9) ヘッダーを読む
            header_item = cbor2.CBORDecoder(buf).decode()
            if isinstance(header_item, bytes):
                result["_frame_header"] = header_item.hex()

            # 次の 1 バイト (type/delimiter)
            pos = buf.tell()
            if pos < len(plaintext):
                frame_type = plaintext[pos]
                result["_frame_type"] = frame_type
                buf.seek(pos + 1)

            # 次の CBOR bstr = gzip 圧縮データ
            if buf.tell() < len(plaintext):
                compressed = cbor2.CBORDecoder(buf).decode()
                if isinstance(compressed, bytes) and len(compressed) >= 2:
                    if compressed[:2] == b"\x1f\x8b":
                        try:
                            raw_data = gzip.decompress(compressed)
                        except Exception:
                            raw_data = compressed
                    else:
                        raw_data = compressed

                    # JSON パース
                    try:
                        body = json.loads(raw_data)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        try:
                            body = cbor2.loads(raw_data)
                        except Exception:
                            body = {
                                "_raw_bytes": raw_data[:200].hex(),
                                "_size": len(raw_data),
                            }

                    result["body"] = body

            # トレーラー (sequence number 等)
            trailer_pos = buf.tell()
            if trailer_pos < len(plaintext):
                trailer = plaintext[trailer_pos:]
                result["_trailer"] = trailer.hex()

        except Exception as e:
            result["_parse_error"] = str(e)
            result["_raw_bytes"] = plaintext.hex()

        return result
