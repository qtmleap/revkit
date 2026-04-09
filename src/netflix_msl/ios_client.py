"""iOSMslClient — iOS Netflix MSL appboot-to-session オーケストレーター

appboot から MSL セッション鍵確立までの End-to-end フローを実装する。

## フロー概要 (msl_key_relationship.md §2)

  Phase 0 (前提): ESN → TFIT-WB-AES → enc_key_0, sign_key_0
                  (tools/emulate_tfit.py または Frida キャプチャで取得)

  Phase 3: kdf_renew(PSK, enc_key_0, sign_key_0, nonce) → enc_key_1, sign_key_1

  Phase 1: DH 鍵ペア生成 → appboot リクエスト構築 → POST appboot.netflix.com
           レスポンス解析 → server_scheme_data (96B), server_nonce (16B)

  Phase 2: DH_compute_key(server_pub_key, client_priv_key)
           → HMAC-SHA384(48B_KEY, 0x00 || shared_secret) → enc_key, bootstrap_key

  Phase 4: (ログイン後) key_response_data から AES-128-CBC 復号 → enc_key_2, sign_key_2

  Phase 5: MSL 通信 (AES-128-CBC + HMAC-SHA256)

## 制約

- key 33.6 の TFIT エンコード部 (DH 公開鍵 128B → session_region 172B) は
  tools/emulate_tfit.py による Unicorn エミュレーションが必要。
  現在は session_region をコンストラクタパラメータとして受け取る。

- server_scheme_data (96B) から server DH 公開鍵の抽出は未解明。
  現在は server_scheme_data を直接パラメータとして受け取る。

## TODO (Frida キャプチャが必要な値)

  - enc_key_0 / sign_key_0: TFIT エミュレーション (emulate_tfit.py) で導出可能
  - devicetoken: Frida/Tweak `AppbootKeyExtract` でキャプチャ
  - apphmac:     Frida/Tweak `AppbootKeyExtract` でキャプチャ
  - device_key_data: Frida/Tweak `AppbootKeyExtract` でキャプチャ (~6,576 bytes)
  - session_region: TFIT エミュレーション (emulate_tfit.py) または Frida キャプチャ
  - s1, s2, s3: Frida キャプチャで取得
  - renewable / capabilities: 既知の固定値 (ios_auth_manifest_license_flow.md §2.1)
  - server_dh_pub_key: server_scheme_data (96B) のフォーマット解明後に自動抽出可能
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

from netflix_msl.cbor_decoder import CborMslDecoder
from netflix_msl.cbor_encoder import CborMslEncoder
from netflix_msl.constants import IOS_APPBOOT_ENDPOINT
from netflix_msl.crypto import NetflixCrypto, SessionKeys


@dataclass
class iOSAppbootParams:
    """appboot リクエストに必要なデバイス固有パラメータ.

    全フィールドは Frida/Tweak キャプチャまたは TFIT エミュレーションで取得する。
    """

    # Phase 0 MGK (TFIT エミュレーションで導出可能)
    enc_key_0: bytes
    """Phase 0 MGK 暗号化鍵 (16 bytes). TFIT エミュレーションで導出可能."""

    sign_key_0: bytes
    """Phase 0 MGK 署名鍵 (32 bytes). TFIT エミュレーションで導出可能."""

    # FAIRPLAY_MGK_APPID entity_auth_data
    appid: str
    """アプリ識別子 UUID (e.g. 'a2becfec-b286-535c-b884-903a384caee6').
    TODO: Frida キャプチャで取得が必要 (バイナリに埋め込まれている可能性あり)."""

    devicetoken: str
    """デバイストークン (hex string).
    TODO: Frida/Tweak AppbootKeyExtract でキャプチャ."""

    apphmac: str
    """アプリ認証 HMAC-SHA256 (hex string).
    TODO: Frida/Tweak AppbootKeyExtract でキャプチャ."""

    device_key_data: bytes
    """デバイス固有鍵データ (~6,576 bytes).
    TODO: Frida/Tweak AppbootKeyExtract でキャプチャ."""

    # key 33.6 session_region
    session_region: bytes
    """key 33.6 平文の [128:300] セッション領域 (172 bytes).
    TFIT エミュレーション (tools/emulate_tfit.py) または Frida キャプチャで取得.
    TODO: emulate_tfit.py による自動導出が未実装."""

    # key 33.6 separators
    s1: bytes
    """key 33.6 の 9B セッション固定セパレータ (pt[307:316]).
    TODO: Frida キャプチャで取得が必要."""

    s2: bytes
    """key 33.6 の 9B セッション固定セパレータ (pt[323:332]).
    TODO: Frida キャプチャで取得が必要."""

    s3: bytes
    """key 33.6 の 9B セパレータ (pt[339:348]). byte[5] は per-request counter.
    TODO: Frida キャプチャで取得が必要."""

    # MSL ヘッダー固定値
    renewable: bytes
    """capabilities key 16 の固定バイト列 (44 bytes).
    既知の固定値: 010100810001012022b1205c03559bc416af500d517f2c15463fc04717f8fb38b40c5ddce4e24fe11cc01955
    TODO: キャプチャから取得した値を使用すること."""

    capabilities: dict
    """capabilities dict (key 15 の値).
    {10: bytes, 11: int, 12: int, 13: int, 14: int, 94: {95: True}}
    TODO: キャプチャから取得した値を使用すること."""

    # オプション
    appkeyversion: int = 1
    esn_prefix: str = ""
    scheme_suffix: str = "_3"


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

    使用例 (Frida/Tweak でキャプチャした値を使用):

        params = iOSAppbootParams(
            enc_key_0=bytes.fromhex("0817065e..."),
            sign_key_0=bytes.fromhex("91f752f7..."),
            appid="a2becfec-b286-535c-b884-903a384caee6",
            devicetoken="0608a1b7...",     # TODO: Frida キャプチャ
            apphmac="a18bf28f...",          # TODO: Frida キャプチャ
            device_key_data=b"...",         # TODO: Frida キャプチャ (~6576B)
            session_region=b"...",          # TODO: TFIT エミュレーション or Frida
            s1=b"...",                      # TODO: Frida キャプチャ
            s2=b"...",                      # TODO: Frida キャプチャ
            s3=b"...",                      # TODO: Frida キャプチャ
            renewable=bytes.fromhex("010100..."),
            capabilities={10: b"...", ...},
        )

        client = iOSMslClient(
            esn="NFAPPL-02-IPHONE9=1-AD0455...",
            appboot_params=params,
        )

        session = client.perform_appboot()
        # session.session_keys.enc_key_1 で以降の MSL リクエストを暗号化
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
            appboot_params:   デバイス固有パラメータ (Frida キャプチャ値)
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
          2. appboot CBOR リクエストを構築
          3. POST appboot.netflix.com/{ESN_PREFIX}?keyVersion=1
          4. レスポンスを解析して server_scheme_data と server_nonce を抽出
          5. DH 共有秘密を計算
          6. Phase 2/3 KDF で SessionKeys を導出

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
        encoder = CborMslEncoder(self.crypto)
        cbor_message, k9_xor_nonce, nonce_7b = encoder.build_appboot_request(
            esn=self.esn,
            dh_pub_key=dh_pub_key,
            appid=self.params.appid,
            devicetoken=self.params.devicetoken,
            apphmac=self.params.apphmac,
            device_key_data=self.params.device_key_data,
            session_region=self.params.session_region,
            s1=self.params.s1,
            s2=self.params.s2,
            s3=self.params.s3,
            renewable=self.params.renewable,
            capabilities=self.params.capabilities,
            appkeyversion=self.params.appkeyversion,
            esn_prefix=self.params.esn_prefix,
            scheme_suffix=self.params.scheme_suffix,
        )
        print(f"    Request size: {len(cbor_message)} bytes")

        # --- Step 3: POST appboot ---
        esn_prefix = self._extract_esn_prefix(self.esn)
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
        decoder = CborMslDecoder(self.crypto)
        parsed = decoder.parse_appboot_response(resp.content)

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

        # Cookie と deviceIdToken を抽出
        nfvdid_cookie = self._extract_nfvdid_cookie(resp)
        device_id_token = resp.headers.get("x-netflix-deviceidtoken", "")
        if nfvdid_cookie:
            print(f"    nfvdid cookie: {nfvdid_cookie[:32]}...")
        if device_id_token:
            print(f"    deviceIdToken: {device_id_token[:32]}...")

        if server_scheme_data is None:
            raise ValueError(
                "server_scheme_data (key 33.6) が appboot レスポンスに存在しない"
            )
        if server_nonce is None:
            raise ValueError(
                "server_nonce (key 33.9) が appboot レスポンスに存在しない"
            )

        # --- Step 5: DH 共有秘密を計算 ---
        # TODO: server_scheme_data (96B) から server DH 公開鍵 (128B) を抽出するロジックが未解明。
        #       現在は server_scheme_data の構造が [IV(16B)][CT(48B)][HMAC(32B)] と推定されているが、
        #       実際の DH 公開鍵の位置・抽出方法は msl_cbor_key_exchange_analysis.md §5 参照。
        #       Frida フック (DH_compute_key の入力引数) で server DH 公開鍵を直接キャプチャすること。
        print("[appboot] Step 5: DH 共有秘密を計算中...")
        server_dh_pub_key = self._extract_server_dh_pub_key(server_scheme_data)
        dh_shared_secret = NetflixCrypto.compute_dh_shared_secret(
            peer_public=server_dh_pub_key,
            private_key=dh_priv_key,
        )
        print(
            f"    dh_shared_secret: {dh_shared_secret[:16].hex()}... ({len(dh_shared_secret)}B)"
        )

        # --- Step 6: Phase 2/3 KDF でセッション鍵を導出 ---
        print("[appboot] Step 6: セッション鍵を導出中 (Phase 3 → Phase 2)...")
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

    def build_encrypted_msl_request(
        self,
        payload_body: dict | list | str,
        endpoint: str,
        keyid: str | None = None,
        compress: bool = False,
    ) -> bytes:
        """暗号化 MSL リクエストを構築する.

        perform_appboot() 完了後にのみ呼び出せる。
        enc_key_1 / sign_key_1 でペイロードを暗号化・署名する。

        Args:
            payload_body: リクエスト本体 (dict/list/str)
            endpoint:     MSL エンドポイント URL (ログ用)
            keyid:        鍵 ID。None の場合は "{ESN}_3" を使用。
            compress:     True の場合 gzip 圧縮してから暗号化

        Returns:
            CBOR エンコードされた暗号化 MSL リクエスト

        Raises:
            RuntimeError: perform_appboot() が未完了の場合
        """
        if self.session_state is None:
            raise RuntimeError(
                "perform_appboot() を先に実行してセッションを確立すること"
            )

        encoder = CborMslEncoder(self.crypto)
        payload_bytes_raw = CborMslEncoder.build_payload_json(
            message_id=self._generate_message_id(),
            body=payload_body,
            compress=compress,
        )

        _keyid = keyid or f"{self.esn}_3"

        # ヘッダー構築 (entity_auth_data なし)
        header_bytes = encoder.build_header(
            renewable=self.params.renewable,
            capabilities=self.params.capabilities,
        )

        return encoder.build_encrypted_message(
            header_bytes=header_bytes,
            key_request_bytes=None,
            payload_plaintext=payload_bytes_raw,
            keyid=_keyid,
            compress=False,  # build_payload_json で既に対応済み
        )

    # ------------------------------------------------------------------
    # 内部ヘルパー
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_esn_prefix(esn: str) -> str:
        """ESN から ESN プレフィックス部分を抽出する.

        "NFAPPL-02-IPHONE9=1-AD0455..." → "NFAPPL-02-IPHONE9=1-"
        """
        idx = esn.rfind("-")
        return esn[: idx + 1] if idx != -1 else esn

    @staticmethod
    def _extract_nfvdid_cookie(resp: requests.Response) -> str:
        """Set-Cookie ヘッダーから nfvdid Cookie 値を抽出する."""
        set_cookie = resp.headers.get("Set-Cookie", "")
        if "nfvdid=" in set_cookie:
            start = set_cookie.index("nfvdid=") + len("nfvdid=")
            end = set_cookie.find(";", start)
            return set_cookie[start:end] if end != -1 else set_cookie[start:]
        # requests の cookies からも試みる
        nfvdid = resp.cookies.get("nfvdid", "")
        return nfvdid

    @staticmethod
    def _extract_server_dh_pub_key(server_scheme_data: bytes) -> bytes:
        """server_scheme_data (96B) からサーバー DH 公開鍵 (128B) を抽出する.

        TODO: server_scheme_data の構造が解明されていないため、現在は暫定実装。
              msl_cbor_key_exchange_analysis.md §5 の推定構造:
                [IV(16B)][CT(48B)][HMAC(32B)]
              サーバー DH 公開鍵は CT を dec_key で復号した後に得られると推定。
              dec_key の由来は未解明。

              正確な抽出方法は Frida フック (DH_compute_key の peer_pub 引数) で
              server DH 公開鍵を直接キャプチャして解明する必要がある。

        現在の実装:
              server_scheme_data の先頭 96B をゼロパディングして 128B を返す。
              実際のセッション確立には Frida キャプチャした値を使用すること。
        """
        # TODO: 実際の DH 公開鍵抽出ロジックをここに実装する。
        #       暫定: server_scheme_data の先頭 96B + 32B ゼロパディング
        #       これは正しい値ではない。Frida でキャプチャした server DH pub_key を使用すること。
        if len(server_scheme_data) >= 128:
            return server_scheme_data[:128]
        return server_scheme_data.ljust(128, b"\x00")

    @staticmethod
    def _generate_message_id() -> int:
        """MSL メッセージ ID (rand in [0, 2^52)) を生成する."""
        import random

        return random.randint(0, 2**52)

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
