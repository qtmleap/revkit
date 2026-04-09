"""iOSMslClient — iOS Netflix MSL appboot-to-session オーケストレーター

appboot から MSL セッション鍵確立までの End-to-end フローを実装する。

## フロー概要 (msl_key_relationship.md §2)

  Phase 0 (前提): ESN → TFIT-WB-AES → enc_key_0, sign_key_0
                  (tools/emulate_tfit.py で導出)

  Phase 3: kdf_renew(PSK, enc_key_0, sign_key_0, nonce) → enc_key_1, sign_key_1

  Phase 1: DH 鍵ペア生成 → appboot リクエスト構築 → POST appboot.netflix.com
           署名 = HMAC-SHA256(sign_key_0, key_request_data_bytes)
           レスポンス解析 → server_scheme_data (96B), server_nonce (16B)
           レスポンスヘッダー → x-netflix-deviceidtoken

  Phase 2: DH_compute_key(server_pub_key, client_priv_key)
           → HMAC-SHA384(48B_KEY, 0x00 || shared_secret) → enc_key, bootstrap_key

  Phase 4: (ログイン後) key_response_data から AES-128-CBC 復号 → enc_key_2, sign_key_2

  Phase 5: MSL 通信 (AES-128-CBC + HMAC-SHA256)

## 実測で確定した entity_auth_data 構造 (243 リクエストから確認)

  {
    35: {
      "apphmac":      bytes   # 初回は b""; 以降は device_id_token.encode("utf-8")
      "appid":        str     # IOS_APPID 定数
      "appkeyversion": int    # 1
      "devicetoken":  bytes   # 初回は b""; 以降は base64.b64decode(device_id_token)
      3:              str     # 完全 ESN (整数キー)
    },
    30: "MGK_APPID"
  }

  - apphmac は HMAC 値ではなく deviceIdToken 文字列の UTF-8 バイト列
  - devicetoken は deviceIdToken を Base64 デコードした 216B raw bytes
  - 両フィールドの出所は同一: x-netflix-deviceidtoken レスポンスヘッダー
  - 初回リクエストでは両フィールドとも b"" (空バイト)
  - entity_auth_data の scheme 名は "MGK_APPID" (旧 "FAIRPLAY_MGK_APPID" は誤り)
  - key_request_data の identity (key 33.8) は完全 ESN のみ (サフィックスなし)
  - 署名対象は key_request_data_bytes のみ (ヘッダーは含まない)

## 制約

- key 33.6 の TFIT エンコード部 (DH 公開鍵 128B → session_region 172B) は
  tools/emulate_tfit.py による Unicorn エミュレーションが必要。
  現在は session_region をコンストラクタパラメータとして受け取る。

- server_scheme_data (96B) から server DH 公開鍵の抽出は未解明。
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import os
from dataclasses import dataclass, field

import cbor2
import requests

from netflix_msl.constants import (
    IOS_APPBOOT_ENDPOINT,
    IOS_APPID,
    IOS_APPKEYVERSION,
    IOS_KEY336_DEVICE_HEADER,
)
from netflix_msl.crypto import NetflixCrypto, SessionKeys

# ---------------------------------------------------------------------------
# CBOR 数値キー定数
# ---------------------------------------------------------------------------

_ENTITY_SCHEME = 30
_ENTITY_AUTH_DATA = 35
_KEYEX_SCHEME = 6
_KEYEX_KEYDATA = 7
_KEYEX_IDENTITY = 8
_KEYEX_NONCE = 9
_KEY_ENTITY_AUTH = 34
_KEY_KEY_EXCHANGE = 33
_KEY_MESSAGE_SIG = 16

# key 33.6 XOR nonce 変形マスク (165 サンプル全てで一致)
_N2_MASK = bytes([0xF4, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00])
_N3_MASK = bytes([0xF4, 0x1B, 0x00, 0x18, 0x1B, 0x00, 0x00])
_TAIL_MASK = bytes([0xF3, 0x1C, 0x07, 0x1F])


@dataclass
class iOSAppbootParams:
    """appboot リクエストに必要なデバイス固有パラメータ.

    enc_key_0 / sign_key_0 は tools/emulate_tfit.py で ESN から導出する。
    session_region / s1 / s2 / s3 は TFIT エミュレーション実装後に自動導出予定。
    """

    # Phase 0 MGK (tools/emulate_tfit.py で導出可能)
    enc_key_0: bytes
    """Phase 0 MGK 暗号化鍵 (16 bytes). tools/emulate_tfit.py で導出。"""

    sign_key_0: bytes
    """Phase 0 MGK 署名鍵 (32 bytes). tools/emulate_tfit.py で導出。"""

    # key 33.6 session_region
    session_region: bytes
    """key 33.6 平文の [128:300] セッション領域 (172 bytes).
    TFIT エミュレーション (tools/emulate_tfit.py) または Frida キャプチャで取得.
    TODO: emulate_tfit.py による自動導出が未実装。"""

    # key 33.6 separators
    s1: bytes
    """key 33.6 の 9B セッション固定セパレータ (pt[307:316]).
    TODO: Frida キャプチャで取得が必要。"""

    s2: bytes
    """key 33.6 の 9B セッション固定セパレータ (pt[323:332]).
    TODO: Frida キャプチャで取得が必要。"""

    s3: bytes
    """key 33.6 の 9B セパレータ (pt[339:348]). byte[5] は per-request counter.
    TODO: Frida キャプチャで取得が必要。"""

    # オプション
    appid: str = IOS_APPID
    appkeyversion: int = IOS_APPKEYVERSION

    # 継続セッション用 (初回は None)
    device_id_token: str | None = None
    """x-netflix-deviceidtoken ヘッダー値 (Base64 文字列).
    初回リクエストは None。以降は前回レスポンスの値をセットする。
    - apphmac   = device_id_token.encode("utf-8") として entity_auth_data に設定
    - devicetoken = base64.b64decode(device_id_token) として entity_auth_data に設定"""


@dataclass
class iOSSessionState:
    """appboot 完了後のセッション状態."""

    session_keys: SessionKeys
    """Phase 2/3 で導出されたセッション鍵セット."""

    server_nonce: bytes
    """appboot レスポンスの key 33.9 (16B)."""

    server_scheme_data: bytes
    """appboot レスポンスの key 33.6 (96B) — サーバー DH レスポンス."""

    scheme_id: str
    """スキーム ID ("3" または "5")."""

    nfvdid_cookie: str = ""
    """Set-Cookie: nfvdid から取得したデバイス ID Cookie."""

    device_id_token: str = ""
    """x-netflix-deviceidtoken レスポンスヘッダーから取得したデバイス ID トークン."""

    dh_priv_key: bytes = field(default_factory=bytes)
    """クライアント DH 秘密鍵 (128 bytes). Phase 2 で使用後も保持する."""

    dh_pub_key: bytes = field(default_factory=bytes)
    """クライアント DH 公開鍵 (128 bytes)."""


class iOSMslClient:
    """iOS Netflix MSL appboot から暗号化 MSL リクエストまでのオーケストレーター.

    使用例:

        from tools.emulate_tfit import compute_mgk  # または外部から値を渡す

        params = iOSAppbootParams(
            enc_key_0=bytes.fromhex("0817065e..."),  # TFIT エミュレーション結果
            sign_key_0=bytes.fromhex("91f752f7..."),
            session_region=b"\\x00" * 172,            # TODO: TFIT エミュレーション
            s1=b"\\x00" * 9,                          # TODO: Frida キャプチャ
            s2=b"\\x00" * 9,
            s3=b"\\x00" * 9,
            device_id_token=None,                    # 初回は None
        )

        client = iOSMslClient(
            esn="NFAPPL-02-IPHONE9=1-AD0455...",
            appboot_params=params,
        )

        session = client.perform_appboot()
        # session.device_id_token を次回 iOSAppbootParams.device_id_token に設定する
    """

    def __init__(
        self,
        esn: str,
        appboot_params: iOSAppbootParams,
        timeout: int = 30,
    ) -> None:
        """クライアントを初期化する.

        Args:
            esn:              PRV ESN (e.g. "NFAPPL-02-IPHONE9=1-AD0455...")
            appboot_params:   デバイス固有パラメータ
            timeout:          HTTP タイムアウト秒数 (default 30)
        """
        self.esn = esn
        self.params = appboot_params
        self.timeout = timeout

        self.crypto = NetflixCrypto()
        self.session_state: iOSSessionState | None = None

        # HTTP セッション
        self._http = requests.Session()
        self._http.headers.update(
            {
                "User-Agent": "Netflix/24 CFNetwork/1335.0.3.4 Darwin/21.6.0",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Netflix.APIAction": "appboot",
                "X-Netflix.client.ftl.esn": esn,
                "X-Netflix.Request.Attempt": "1",
                "X-Netflix.Request.Client.Context": '{"appState":"foreground"}',
            }
        )

    # ------------------------------------------------------------------
    # パブリック API
    # ------------------------------------------------------------------

    def perform_appboot(self) -> iOSSessionState:
        """appboot フローを実行してセッション状態を返す.

        手順:
          1. DH 鍵ペアを生成
          2. entity_auth_data + key_request_data CBOR を構築
          3. POST appboot.netflix.com/{ESN_PREFIX}?keyVersion=1
          4. レスポンスを解析して server_scheme_data と server_nonce を抽出
          5. x-netflix-deviceidtoken ヘッダーを記録
          6. DH 共有秘密を計算 (server DH 公開鍵抽出が未実装のため暫定)
          7. Phase 2/3 KDF で SessionKeys を導出

        Returns:
            iOSSessionState: セッション鍵・Cookie・deviceIdToken を含む状態

        Raises:
            RuntimeError: appboot リクエストが失敗した場合
            ValueError: レスポンスの解析に失敗した場合
        """
        # --- Step 1: DH 鍵ペアを生成 ---
        print("[appboot] Step 1: DH 鍵ペアを生成中...")
        dh_priv_key, dh_pub_key = NetflixCrypto.generate_dh_keypair()
        print(f"    DH pub_key: {dh_pub_key[:16].hex()}... ({len(dh_pub_key)}B)")

        # --- Step 2: appboot CBOR リクエストを構築 ---
        print("[appboot] Step 2: CBOR リクエストを構築中...")
        cbor_message, k9_xor_nonce, nonce_7b = self._build_appboot_cbor()
        print(f"    Request size: {len(cbor_message)} bytes")

        # --- Step 3: POST appboot ---
        esn_prefix = _extract_esn_prefix(self.esn)
        url = IOS_APPBOOT_ENDPOINT + esn_prefix
        params = {"keyVersion": str(self.params.appkeyversion)}

        print(f"[appboot] Step 3: POST {url}")
        resp = self._http.post(
            url,
            params=params,
            data=cbor_message,
            timeout=self.timeout,
        )
        print(f"    HTTP {resp.status_code} ({len(resp.content)} bytes)")

        if resp.status_code != 200:
            raise RuntimeError(
                f"appboot failed: HTTP {resp.status_code} — {resp.text[:500]}"
            )

        # --- Step 4: レスポンスを解析 ---
        print("[appboot] Step 4: レスポンスを解析中...")
        parsed = _parse_appboot_response(resp.content)

        server_scheme_data = parsed.get("server_scheme_data")
        server_nonce = parsed.get("server_nonce")
        scheme_id = parsed.get("scheme_id") or "unknown"

        print(f"    scheme_id: {scheme_id}")
        if server_scheme_data:
            print(
                f"    server_scheme_data: {server_scheme_data[:16].hex()}... ({len(server_scheme_data)}B)"
            )
        if server_nonce:
            print(f"    server_nonce: {server_nonce.hex()}")

        # Step 5: Cookie と deviceIdToken を抽出
        nfvdid_cookie = _extract_nfvdid_cookie(resp)
        device_id_token = resp.headers.get("x-netflix-deviceidtoken", "")
        if nfvdid_cookie:
            print(f"    nfvdid cookie: {nfvdid_cookie[:32]}...")
        if device_id_token:
            print(f"    deviceIdToken: {device_id_token[:40]}...")

        if server_scheme_data is None:
            raise ValueError(
                "server_scheme_data (key 33.6) が appboot レスポンスに存在しない"
            )
        if server_nonce is None:
            raise ValueError(
                "server_nonce (key 33.9) が appboot レスポンスに存在しない"
            )

        # --- Step 6: DH 共有秘密を計算 ---
        # TODO: server_scheme_data (96B) から server DH 公開鍵 (128B) を抽出するロジックが未解明。
        #       正確な抽出方法は Frida フック (DH_compute_key の peer_pub 引数) で
        #       server DH 公開鍵を直接キャプチャして解明する必要がある。
        print("[appboot] Step 6: DH 共有秘密を計算中...")
        server_dh_pub_key = _extract_server_dh_pub_key(server_scheme_data)
        dh_shared_secret = NetflixCrypto.compute_dh_shared_secret(
            peer_public=server_dh_pub_key,
            private_key=dh_priv_key,
        )
        print(
            f"    dh_shared_secret: {dh_shared_secret[:16].hex()}... ({len(dh_shared_secret)}B)"
        )

        # --- Step 7: Phase 2/3 KDF でセッション鍵を導出 ---
        print("[appboot] Step 7: セッション鍵を導出中 (Phase 3 → Phase 2)...")
        session_keys = NetflixCrypto.derive_full_key_chain(
            enc_key_0=self.params.enc_key_0,
            sign_key_0=self.params.sign_key_0,
            dh_shared_secret=dh_shared_secret,
        )
        print(f"    enc_key:       {session_keys.enc_key.hex()}")
        print(f"    enc_key_1:     {session_keys.enc_key_1.hex()}")
        print(f"    bootstrap_key: {session_keys.bootstrap_key.hex()}")

        # セッション鍵を crypto に反映 (以降の暗号化で使用)
        self.crypto.import_session_keys(
            enc_key=session_keys.enc_key_1,
            sign_key=session_keys.sign_key_1,
        )

        self.session_state = iOSSessionState(
            session_keys=session_keys,
            server_nonce=server_nonce,
            server_scheme_data=server_scheme_data,
            scheme_id=scheme_id,
            nfvdid_cookie=nfvdid_cookie,
            device_id_token=device_id_token,
            dh_priv_key=dh_priv_key,
            dh_pub_key=dh_pub_key,
        )

        print("[appboot] 完了")
        return self.session_state

    # ------------------------------------------------------------------
    # 内部: CBOR メッセージ構築
    # ------------------------------------------------------------------

    def _build_appboot_cbor(self) -> tuple[bytes, bytes, bytes]:
        """appboot CBOR メッセージを構築する.

        entity_auth_data 構造 (実測フォーマット):
          {
            35: {
              "apphmac":      bytes   # 初回は b""; 以降は device_id_token.encode("utf-8")
              "appid":        str
              "appkeyversion": int
              "devicetoken":  bytes   # 初回は b""; 以降は base64.b64decode(device_id_token)
              3:              str     # 完全 ESN (整数キー)
            },
            30: "MGK_APPID"
          }

        key_request_data 構造:
          {
            6: bytes(352B)  # key 33.6 XOR 暗号化 scheme_data
            7: bytes(0B)    # master_token (空)
            8: str          # identity = 完全 ESN
            9: bytes(16B)   # k9_xor_nonce
          }

        署名: HMAC-SHA256(sign_key_0, key_request_data_bytes)

        Returns:
            (cbor_message, k9_xor_nonce, nonce_7b)
        """
        # --- apphmac / devicetoken を決定 ---
        if self.params.device_id_token:
            apphmac = self.params.device_id_token.encode("utf-8")
            try:
                pad = 4 - len(self.params.device_id_token) % 4
                padded = self.params.device_id_token + ("=" * pad if pad != 4 else "")
                devicetoken = base64.b64decode(padded)
            except Exception:
                devicetoken = b""
        else:
            apphmac = b""
            devicetoken = b""

        # --- entity_auth_data を構築 ---
        auth_data: dict = {
            "apphmac": apphmac,
            "appid": self.params.appid,
            "appkeyversion": self.params.appkeyversion,
            "devicetoken": devicetoken,
            3: self.esn,  # 整数キー
        }
        entity_auth_data = {
            _ENTITY_AUTH_DATA: auth_data,
            _ENTITY_SCHEME: "MGK_APPID",
        }

        # --- key 33.9 nonce と 7B nonce を生成 ---
        k9_xor_nonce = os.urandom(16)
        nonce_7b = os.urandom(7)

        # --- key 33.6 scheme_data (352B) を構築 ---
        scheme_data_enc = _build_key336_scheme_data(
            session_region=self.params.session_region,
            nonce_7b=nonce_7b,
            s1=self.params.s1,
            s2=self.params.s2,
            s3=self.params.s3,
            k9_xor_nonce=k9_xor_nonce,
        )

        # --- key_request_data を構築 ---
        key_request_data: dict = {
            _KEYEX_SCHEME: scheme_data_enc,
            _KEYEX_KEYDATA: b"",  # master_token (新規セッション)
            _KEYEX_IDENTITY: self.esn,  # identity = 完全 ESN
            _KEYEX_NONCE: k9_xor_nonce,
        }
        key_request_bytes = cbor2.dumps(key_request_data)

        # --- 署名: HMAC-SHA256(sign_key_0, key_request_data_bytes) ---
        signature = hmac_mod.new(
            self.params.sign_key_0, key_request_bytes, hashlib.sha256
        ).digest()

        # --- トップレベルメッセージを構築 ---
        message = {
            _KEY_ENTITY_AUTH: cbor2.dumps(entity_auth_data),
            _KEY_KEY_EXCHANGE: key_request_bytes,
            _KEY_MESSAGE_SIG: signature,
        }
        return cbor2.dumps(message), k9_xor_nonce, nonce_7b

    # ------------------------------------------------------------------
    # セッション状態アクセサ
    # ------------------------------------------------------------------

    @property
    def is_authenticated(self) -> bool:
        """appboot が完了してセッション鍵が確立されているかどうか."""
        return self.session_state is not None and self.crypto.encryption_key is not None

    @property
    def nfvdid_cookie(self) -> str:
        """nfvdid Cookie 値。perform_appboot() 前は空文字列。"""
        return self.session_state.nfvdid_cookie if self.session_state else ""

    @property
    def device_id_token(self) -> str:
        """x-netflix-deviceidtoken 値。perform_appboot() 前は空文字列。"""
        return self.session_state.device_id_token if self.session_state else ""


# ---------------------------------------------------------------------------
# モジュールレベルヘルパー
# ---------------------------------------------------------------------------


def _build_key336_scheme_data(
    session_region: bytes,
    nonce_7b: bytes,
    s1: bytes,
    s2: bytes,
    s3: bytes,
    k9_xor_nonce: bytes,
) -> bytes:
    """key 33.6 scheme_data 352B を XOR 暗号化して返す.

    NetflixCrypto.build_key336_scheme_data() と同じロジック。
    """
    n = nonce_7b
    n2 = bytes(a ^ b for a, b in zip(n, _N2_MASK))
    n3 = bytes(a ^ b for a, b in zip(n, _N3_MASK))
    tail = bytes(a ^ b for a, b in zip(n[:4], _TAIL_MASK))

    plaintext = (
        IOS_KEY336_DEVICE_HEADER + session_region + n + s1 + n2 + s2 + n3 + s3 + tail
    )
    assert len(plaintext) == 352, f"plaintext length {len(plaintext)} != 352"
    return bytes(plaintext[i] ^ k9_xor_nonce[i % 16] for i in range(352))


def _extract_esn_prefix(esn: str) -> str:
    """ESN から ESN プレフィックス部分を抽出する.

    "NFAPPL-02-IPHONE9=1-AD0455..." → "NFAPPL-02-IPHONE9=1-"
    """
    idx = esn.rfind("-")
    return esn[: idx + 1] if idx != -1 else esn


def _extract_nfvdid_cookie(resp: requests.Response) -> str:
    """Set-Cookie ヘッダーから nfvdid Cookie 値を抽出する."""
    set_cookie = resp.headers.get("Set-Cookie", "")
    if "nfvdid=" in set_cookie:
        start = set_cookie.index("nfvdid=") + len("nfvdid=")
        end = set_cookie.find(";", start)
        return set_cookie[start:end] if end != -1 else set_cookie[start:]
    return resp.cookies.get("nfvdid", "")


def _extract_server_dh_pub_key(server_scheme_data: bytes) -> bytes:
    """server_scheme_data (96B) からサーバー DH 公開鍵 (128B) を抽出する.

    TODO: server_scheme_data の構造が解明されていないため、現在は暫定実装。
          正確な抽出方法は Frida フック (DH_compute_key の peer_pub 引数) で
          server DH 公開鍵を直接キャプチャして解明する必要がある。

    現在の実装:
          server_scheme_data の先頭 96B をゼロパディングして 128B を返す。
          実際のセッション確立には Frida キャプチャした値を使用すること。
    """
    if len(server_scheme_data) >= 128:
        return server_scheme_data[:128]
    return server_scheme_data.ljust(128, b"\x00")


def _parse_appboot_response(raw: bytes) -> dict:
    """appboot レスポンス CBOR を解析する.

    Returns:
        {
          "server_scheme_data": bytes | None,
          "server_nonce":       bytes | None,
          "scheme_id":          str | None,
          "status_flag":        bytes | None,
          "raw":                dict,
        }
    """
    try:
        top = cbor2.loads(raw)
    except Exception as e:
        raise ValueError(f"CBOR デコード失敗: {e}") from e

    result: dict = {
        "server_scheme_data": None,
        "server_nonce": None,
        "scheme_id": None,
        "status_flag": None,
        "raw": top,
    }

    krd_raw = top.get(_KEY_KEY_EXCHANGE)
    if krd_raw is None:
        return result

    try:
        krd = cbor2.loads(krd_raw) if isinstance(krd_raw, bytes) else krd_raw
    except Exception:
        return result

    if not isinstance(krd, dict):
        return result

    v6 = krd.get(_KEYEX_SCHEME)
    if isinstance(v6, bytes):
        result["server_scheme_data"] = v6

    v7 = krd.get(_KEYEX_KEYDATA)
    if isinstance(v7, bytes):
        result["status_flag"] = v7

    v8 = krd.get(_KEYEX_IDENTITY)
    if v8 is not None:
        result["scheme_id"] = str(v8)

    v9 = krd.get(_KEYEX_NONCE)
    if isinstance(v9, bytes):
        result["server_nonce"] = v9

    return result
