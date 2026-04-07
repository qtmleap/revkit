"""CborMslEncoder — iOS CBOR MSL メッセージのエンコードパイプライン

iOS Netflix (Argo) が使用する CBOR 形式の MSL リクエストメッセージを構築する。

CBOR トップレベル数値キーマッピング (cbor_decoder.py と共通):
  32  = header
  33  = key_request_data
  34  = entity_auth_data
  64  = payload_chunk
  16  = message signature (HMAC-SHA256, 32 bytes)

entity_auth_data 内部キー:
  30  = scheme name (e.g., "FAIRPLAY_MGK_APPID")
  35  = auth_data dict

auth_data フィールド (FAIRPLAY_MGK_APPID スキーム):
  apphmac        : HMAC-SHA256 (hex string)
  appid          : UUID string
  appkeyversion  : int (default 1)
  devicetoken    : hex string
  esn_prefix     : ESN プレフィックス (e.g. "NFAPPL-02-IPHONE9=1-")
  esn            : PRV ESN 全体
  device_key_data: bytes (~6,576 bytes)

payload_chunk 内部キー (cbor_decoder.py と共通):
  6  = ciphertext (AES-128-CBC 暗号化データ)
  7  = iv (初期化ベクタ, 16 bytes)
  8  = keyid ({ESN}_{session_index})
  9  = hmac (HMAC-SHA256, 32 bytes)
"""

from __future__ import annotations

import gzip
import hashlib
import hmac as hmac_mod
import json
import random

import cbor2

from netflix_msl.cbor_decoder import (
    ENTITY_AUTH_DATA,
    ENTITY_SCHEME,
    HEADER_CAPABILITIES,
    HEADER_RENEWABLE,
    KEY_ENTITY_AUTH,
    KEY_HEADER,
    KEY_KEY_EXCHANGE,
    KEY_MESSAGE_SIG,
    KEY_PAYLOAD_CHUNK,
    KEYEX_IDENTITY,
    KEYEX_KEYDATA,
    KEYEX_NONCE,
    KEYEX_SCHEME,
    PAYLOAD_CIPHERTEXT,
    PAYLOAD_HMAC,
    PAYLOAD_IV,
    PAYLOAD_KEYID,
)
from netflix_msl.crypto import NetflixCrypto


class EncodeError(Exception):
    """CBOR MSL メッセージの構築に失敗した場合."""


class CborMslEncoder:
    """iOS CBOR MSL リクエストメッセージを構築するエンコーダー."""

    def __init__(self, crypto: NetflixCrypto) -> None:
        """セッション鍵を持つ crypto インスタンスを受け取る.

        crypto.encryption_key と crypto.sign_key が設定済みであること。
        未設定の場合、暗号化・署名は失敗する。
        """
        self.crypto = crypto

    # ------------------------------------------------------------------
    # パブリック API
    # ------------------------------------------------------------------

    def build_entity_auth_data(
        self,
        esn: str,
        appid: str,
        devicetoken: str,
        apphmac: str,
        device_key_data: bytes,
        appkeyversion: int = 1,
        esn_prefix: str = "",
    ) -> dict:
        """FAIRPLAY_MGK_APPID スキームの entityauthdata を CBOR 形式で構築する.

        Args:
            esn:             PRV ESN 全体 (e.g. "NFAPPL-02-IPHONE9=1-AD04...")
            appid:           アプリ識別子 UUID (e.g. "a2becfec-b286-535c-b884-903a384caee6")
            devicetoken:     デバイストークン (hex string)
            apphmac:         アプリ認証 HMAC-SHA256 (hex string)
            device_key_data: デバイス固有鍵データ (~6,576 bytes)
            appkeyversion:   鍵バージョン (default 1)
            esn_prefix:      ESN プレフィックス。空の場合は esn から自動抽出。

        Returns:
            {
                ENTITY_SCHEME (30):    "FAIRPLAY_MGK_APPID",
                ENTITY_AUTH_DATA (35): { apphmac, appid, appkeyversion, devicetoken,
                                         esn_prefix, esn, device_key_data },
            }
        """
        if not esn_prefix:
            # "NFAPPL-02-IPHONE9=1-AD04..." → "NFAPPL-02-IPHONE9=1-"
            # PRV ESN は最後の "-" より後が hash 部分
            idx = esn.rfind("-")
            esn_prefix = esn[: idx + 1] if idx != -1 else esn

        auth_data: dict = {
            "apphmac": apphmac,
            "appid": appid,
            "appkeyversion": appkeyversion,
            "devicetoken": devicetoken,
            "esn_prefix": esn_prefix,
            "esn": esn,
            "device_key_data": device_key_data,
        }

        return {
            ENTITY_SCHEME: "FAIRPLAY_MGK_APPID",
            ENTITY_AUTH_DATA: auth_data,
        }

    def build_header(
        self,
        renewable: bytes,
        capabilities: dict,
    ) -> bytes:
        """MSL メッセージヘッダーを数値キーで構築し CBOR バイト列を返す.

        Args:
            renewable:     capabilities key 16 の固定バイト列
                           (全リクエスト共通の 44 bytes 定数)
            capabilities:  capabilities dict (key 15 の値)
                           {10: bytes, 11: int, 12: int, 13: int, 14: int,
                            94: {95: True}}

        Returns:
            CBOR エンコードされたヘッダーバイト列
        """
        header = {
            HEADER_CAPABILITIES: capabilities,
            HEADER_RENEWABLE: renewable,
        }
        return cbor2.dumps(header)

    def build_key_request_data(
        self,
        scheme_data: bytes,
        master_token: bytes,
        identity: str,
        nonce: bytes | None = None,
    ) -> bytes:
        """鍵交換リクエストデータ (key 33) を構築し CBOR バイト列を返す.

        Args:
            scheme_data:  クライアント鍵交換データ (464 bytes for appboot)
            master_token: 前回マスタートークン (新規セッション時は b"")
            identity:     ESN + スキームサフィックス (e.g. "NFAPPL-02-..._{scheme_id}")
            nonce:        クライアント nonce (16 bytes)。None の場合はランダム生成。

        Returns:
            CBOR エンコードされた鍵交換リクエストバイト列
        """
        if nonce is None:
            nonce = bytes(random.getrandbits(8) for _ in range(16))

        key_request = {
            KEYEX_SCHEME: scheme_data,
            KEYEX_KEYDATA: master_token,
            KEYEX_IDENTITY: identity,
            KEYEX_NONCE: nonce,
        }
        return cbor2.dumps(key_request)

    def encrypt_payload(
        self,
        plaintext: bytes,
        keyid: str,
    ) -> bytes:
        """ペイロードを AES-128-CBC で暗号化し、payload_chunk を CBOR バイト列で返す.

        Args:
            plaintext: 暗号化する平文バイト列
            keyid:     鍵 ID 文字列 (e.g. "{ESN}_{session_index}")

        Returns:
            CBOR エンコードされた payload_chunk バイト列

        Raises:
            EncodeError: encryption_key が未設定の場合
        """
        if not self.crypto.encryption_key:
            raise EncodeError(
                "encryption_key が未設定。先に import_session_keys() を呼ぶ。"
            )

        ciphertext, iv = self.crypto.encrypt(plaintext)

        chunk = {
            PAYLOAD_CIPHERTEXT: ciphertext,
            PAYLOAD_IV: iv,
            PAYLOAD_KEYID: keyid,
            PAYLOAD_HMAC: b"",  # 後で sign_payload_chunk() で上書き可能
        }
        return cbor2.dumps(chunk)

    def sign_payload_chunk(self, chunk_bytes: bytes) -> bytes:
        """payload_chunk バイト列に対して HMAC-SHA256 を計算する.

        Args:
            chunk_bytes: CBOR エンコードされた payload_chunk

        Returns:
            HMAC-SHA256 ダイジェスト (32 bytes)

        Raises:
            EncodeError: sign_key が未設定の場合
        """
        if not self.crypto.sign_key:
            raise EncodeError("sign_key が未設定。先に import_session_keys() を呼ぶ。")

        return hmac_mod.new(self.crypto.sign_key, chunk_bytes, hashlib.sha256).digest()

    def sign_message(self, header_bytes: bytes, payload_bytes: bytes) -> bytes:
        """ヘッダーとペイロードを結合した HMAC-SHA256 を計算する.

        Args:
            header_bytes:  CBOR エンコードされたヘッダーバイト列
            payload_bytes: CBOR エンコードされた payload_chunk バイト列

        Returns:
            HMAC-SHA256 ダイジェスト (32 bytes)

        Raises:
            EncodeError: sign_key が未設定の場合
        """
        if not self.crypto.sign_key:
            raise EncodeError("sign_key が未設定。先に import_session_keys() を呼ぶ。")

        data = header_bytes + payload_bytes
        return hmac_mod.new(self.crypto.sign_key, data, hashlib.sha256).digest()

    def build_message(
        self,
        header_bytes: bytes,
        entity_auth_data: dict | None,
        key_request_bytes: bytes | None,
        payload_bytes: bytes | None,
        signature: bytes,
    ) -> bytes:
        """MSL メッセージ全体を CBOR バイト列として構築する.

        MSL トップレベル構造:
          {
            34: bytes  ← entity_auth_data (CBOR encoded, appboot のみ)
            33: bytes  ← key_request_data (CBOR encoded)
            32: bytes  ← header (CBOR encoded)
            16: bytes  ← message signature (HMAC-SHA256, 32 bytes)
          }

        Args:
            header_bytes:      build_header() が返す CBOR バイト列
            entity_auth_data:  build_entity_auth_data() が返す dict。
                               None の場合は key 34 を含めない。
            key_request_bytes: build_key_request_data() が返す CBOR バイト列。
                               None の場合は key 33 を含めない。
            payload_bytes:     encrypt_payload() が返す CBOR バイト列。
                               None の場合は key 64 を含めない。
            signature:         sign_message() が返す 32 bytes の HMAC-SHA256

        Returns:
            CBOR エンコードされた MSL メッセージ全体のバイト列
        """
        msg: dict = {}

        if entity_auth_data is not None:
            msg[KEY_ENTITY_AUTH] = cbor2.dumps(entity_auth_data)

        if key_request_bytes is not None:
            msg[KEY_KEY_EXCHANGE] = key_request_bytes

        msg[KEY_HEADER] = header_bytes
        msg[KEY_MESSAGE_SIG] = signature

        if payload_bytes is not None:
            msg[KEY_PAYLOAD_CHUNK] = payload_bytes

        return cbor2.dumps(msg)

    # ------------------------------------------------------------------
    # ハイレベル API
    # ------------------------------------------------------------------

    def build_appboot_message(
        self,
        entity_auth_data: dict,
        header_bytes: bytes,
        key_request_bytes: bytes,
    ) -> bytes:
        """appboot リクエスト用 CBOR MSL メッセージを構築する.

        appboot は暗号化ペイロードを持たない (セッション鍵未確立)。
        署名は sign_key が設定されている場合のみ計算する。
        未設定の場合は 32 bytes のゼロバイト列を署名として使用する。

        Args:
            entity_auth_data:  build_entity_auth_data() が返す dict
            header_bytes:      build_header() が返す CBOR バイト列
            key_request_bytes: build_key_request_data() が返す CBOR バイト列

        Returns:
            CBOR エンコードされた appboot リクエストバイト列
        """
        if self.crypto.sign_key:
            signature = self.sign_message(header_bytes, key_request_bytes)
        else:
            signature = b"\x00" * 32

        return self.build_message(
            header_bytes=header_bytes,
            entity_auth_data=entity_auth_data,
            key_request_bytes=key_request_bytes,
            payload_bytes=None,
            signature=signature,
        )

    def build_encrypted_message(
        self,
        header_bytes: bytes,
        key_request_bytes: bytes | None,
        payload_plaintext: bytes,
        keyid: str,
        compress: bool = False,
    ) -> bytes:
        """暗号化ペイロードを含む MSL メッセージを構築する.

        セッション鍵確立後の通常リクエスト (manifest, logblob 等) に使用する。
        entity_auth_data (key 34) は含めない。

        Args:
            header_bytes:      build_header() が返す CBOR バイト列
            key_request_bytes: 鍵交換データ。None の場合は key 33 を含めない。
            payload_plaintext: 暗号化する平文バイト列
            keyid:             鍵 ID 文字列 (e.g. "{ESN}_3")
            compress:          True の場合 gzip 圧縮してから暗号化する

        Returns:
            CBOR エンコードされた MSL メッセージ全体のバイト列

        Raises:
            EncodeError: encryption_key または sign_key が未設定の場合
        """
        data = gzip.compress(payload_plaintext) if compress else payload_plaintext
        payload_bytes = self.encrypt_payload(data, keyid)
        signature = self.sign_message(header_bytes, payload_bytes)

        return self.build_message(
            header_bytes=header_bytes,
            entity_auth_data=None,
            key_request_bytes=key_request_bytes,
            payload_bytes=payload_bytes,
            signature=signature,
        )

    # ------------------------------------------------------------------
    # ユーティリティ
    # ------------------------------------------------------------------

    @staticmethod
    def build_payload_json(
        message_id: int,
        body: dict | list | str,
        sequence_number: int = 1,
        compress: bool = False,
    ) -> bytes:
        """MSL ペイロード本体を JSON 形式でエンコードする.

        ペイロード構造:
          {"messageid": int, "sequencenumber": int,
           "compressionalgo": str, "endofmsg": true, "data": "<base64>"}

        data フィールドは body を JSON 化したバイト列を (必要に応じて gzip 圧縮して)
        Base64 エンコードしたもの。

        Args:
            message_id:       MSL メッセージ ID
            body:             ペイロード本体 (dict/list/str)
            sequence_number:  シーケンス番号 (default 1)
            compress:         True の場合 gzip 圧縮する

        Returns:
            JSON エンコードされたペイロードバイト列 (encrypt_payload() に渡す)
        """
        import base64

        if isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")
        else:
            body_bytes = body.encode("utf-8") if isinstance(body, str) else body

        algo = ""
        if compress:
            body_bytes = gzip.compress(body_bytes)
            algo = "GZIP"

        envelope = {
            "messageid": message_id,
            "sequencenumber": sequence_number,
            "compressionalgo": algo,
            "endofmsg": True,
            "data": base64.b64encode(body_bytes).decode("utf-8"),
        }
        return json.dumps(envelope).encode("utf-8")
