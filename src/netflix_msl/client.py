"""NetflixMSL — MSL プロトコルクライアント (NetflixMSL.cpp の再実装)

StreamFab の NetflixMSL クラスの完全な Python 再実装。

バイナリ内オフセット:
  +0xD0:  ESN (sender)
  +0x288: messageid
  +0x290: locale
  +0x2A8: NetflixCrypto サブオブジェクト
  +0x318: sequence_number

コンストラクタ: NetflixMSL::NetflixMSL(NetflixCallback&) @ 0x102118f20
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import random
import time
from pathlib import Path
from typing import Any

import requests

from netflix_msl.constants import (
    DEFAULT_QUERY_PARAMS,
    ENDPOINTS,
    IMAGE_PROFILES,
    SUBTITLE_PROFILES,
    UI_PLATFORM,
    UI_VERSION,
    CLIENT_VERSION,
    USER_AGENT,
    ENetflixAudioCodec,
    ENetflixProfile,
    ENetflixVideoCodec,
    get_audio_profiles,
    get_video_profiles,
)
from netflix_msl.crypto import NetflixCrypto


class NetflixMSL:
    """StreamFab の NetflixMSL クラスの完全な Python 再実装."""

    def __init__(
        self,
        esn: str,
        netflix_id: str,
        secure_netflix_id: str,
        cache_dir: str = "cache",
    ):
        # ---- ユーザーデータ (set_user_data) ----
        self.esn = esn  # +0xD0
        self.netflix_id = netflix_id
        self.secure_netflix_id = secure_netflix_id

        # ---- MSL セッション状態 ----
        self.master_token: dict | None = None
        self.useridtoken: dict | None = None
        self.messageid: int = 0  # +0x288
        self.sequence_number: int = 0  # +0x318
        self.locale: str = "en-US"  # +0x290

        # ---- 暗号化 (NetflixCrypto サブオブジェクト +0x2A8) ----
        self.crypto = NetflixCrypto()

        # ---- HTTP セッション ----
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

        # ---- MSL データ永続化 ----
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ====================================================================
    # ユーティリティ
    # ====================================================================

    @staticmethod
    def randInt(min_val: int, max_val: int) -> int:
        """NetflixMSL::randInt @ 0x102128caa"""
        return random.randint(min_val, max_val)

    def _generate_messageid(self) -> int:
        """messageid: randint(0, 2^52).

        StreamFab バイナリでは time(NULL) % 2000 だが、
        Kodi 実装 / MSL 仕様では randint(0, 2^52)。
        """
        self.messageid = random.randint(0, 2**52)
        return self.messageid

    def _build_query_params(self, req_name: str) -> dict:
        """StreamFab 形式のクエリパラメータ."""
        return {
            "reqAttempt": "1",
            "reqPriority": "20",
            "reqName": req_name,
            **DEFAULT_QUERY_PARAMS,
        }

    # ====================================================================
    # ロケール (GetLocaleID, IsSupportedLocaleID, GetDefaultLocaleID)
    # ====================================================================

    def GetLocaleID(self) -> str:
        """NetflixMSL::GetLocaleID @ 0x102126df2"""
        return self.locale

    @staticmethod
    def IsSupportedLocaleID(locale: str) -> bool:
        """NetflixMSL::IsSupportedLocaleID @ 0x10212a11e"""
        supported = {
            "en-US",
            "ja-JP",
            "ko-KR",
            "zh-CN",
            "zh-TW",
            "de-DE",
            "fr-FR",
            "es-ES",
            "pt-BR",
            "it-IT",
        }
        return locale in supported

    @staticmethod
    def GetDefaultLocaleID() -> str:
        """NetflixMSL::GetDefaultLocaleID @ 0x10212a1fa"""
        return "en-US"

    # ====================================================================
    # MSL ヘッダー生成 (generate_msl_header @ 0x102129234)
    # ====================================================================

    def generate_msl_header(
        self,
        is_handshake: bool,
        is_renewable: bool,
        keyrequestdata_str: str = "",
        use_key: bool = False,
    ) -> dict:
        """MSL MessageHeader を構築.

        バイナリ文字列:
          "handshake", "compressionalgos", "GZIP", "capabilities",
          "languages", "renewable", "messageid", "keyrequestdata",
          "userauthdata", "NETFLIXID", "netflixid", "securenetflixid",
          "sender", "mastertoken"
        """
        header: dict[str, Any] = {
            "messageid": self._generate_messageid(),
            "renewable": is_renewable,
            "capabilities": {
                "languages": [self.locale],
                "compressionalgos": [],
            },
        }

        if is_handshake:
            # Kodi: handshake 時は sender なし、keyrequestdata あり
            header["keyrequestdata"] = [self.crypto.get_key_request()]
        else:
            # 通常リクエスト: sender あり、userauthdata あり
            header["sender"] = self.esn
            header["userauthdata"] = {
                "scheme": "NETFLIXID",
                "authdata": {
                    "netflixid": self.netflix_id,
                    "securenetflixid": self.secure_netflix_id,
                },
            }

        return header

    # ====================================================================
    # 暗号化 / 署名 (encrypt @ 0x102129d2c, sign @ 0x10212a05c)
    # ====================================================================

    def encrypt(self, plaintext: str) -> str:
        """AES-CBC 暗号化し、暗号化エンベロープ JSON 文字列を返す.

        Kodi 実装と同一形式:
          encrypt(plaintext) -> JSON({"keyid", "iv", "ciphertext", "sha256"})

        keyid = "{ESN}_{sequence_number}" (Kodi: '_'.join((esn, str(seq))))
        """
        ciphertext, iv = self.crypto.encrypt(plaintext.encode("utf-8"))
        envelope = {
            "keyid": f"{self.esn}_{self.sequence_number}",
            "iv": base64.standard_b64encode(iv).decode("utf-8"),
            "ciphertext": base64.standard_b64encode(ciphertext).decode("utf-8"),
            "sha256": "AA==",
        }
        return json.dumps(envelope)

    def sign(self, message: str) -> str:
        """HMAC-SHA256 署名.

        入力は encrypt() が返した JSON 文字列 (Base64 前)。
        Kodi: HMAC.new(sign_key, message.encode('utf-8'), SHA256)
        """
        return self.crypto.sign(message)

    # ====================================================================
    # 鍵交換 (generate_key_handshake_data, perform_key_handshake, OnKeyHandshake)
    # ====================================================================

    def generate_key_handshake_data(self) -> str:
        """NetflixMSL::generate_key_handshake_data @ 0x102128dce

        Kodi 実装に準拠:
          headerdata = Base64(JSON(header_with_keyrequestdata))  (平文)
          entityauthdata = {"scheme": "NONE", "authdata": {"identity": esn}}
          signature = ""  (平文のため署名なし)
          payload = 空 (暗号化なし)
        """
        self.crypto.generate_rsa_keypair()

        msl_header = self.generate_msl_header(
            is_handshake=True,
            is_renewable=True,
        )
        headerdata_json = json.dumps(msl_header)

        # Kodi: sort_keys=True
        header = json.dumps(
            {
                "entityauthdata": {
                    "scheme": "NONE",
                    "authdata": {"identity": self.esn},
                },
                "headerdata": base64.standard_b64encode(
                    headerdata_json.encode("utf-8")
                ).decode("utf-8"),
                "signature": "",
            },
            sort_keys=True,
        )

        # 空ペイロード (暗号化なし)
        payload = json.dumps(
            {
                "payload": base64.standard_b64encode(
                    json.dumps(
                        {
                            "messageid": self.messageid,
                            "data": "",
                            "sequencenumber": 1,
                            "endofmsg": True,
                        }
                    ).encode("utf-8")
                ).decode("utf-8"),
                "signature": "",
            }
        )

        return header + payload

    def perform_key_handshake(self) -> bool:
        """NetflixMSL::perform_key_handshake @ 0x10211e9e2"""
        print("[Step 1] MSL Key Handshake (ASYMMETRIC_WRAPPED / JWK_RSA)...")

        body = self.generate_key_handshake_data()
        url = ENDPOINTS["pbo_manifests"]
        params = self._build_query_params("handshake")

        print(f"    POST {url}")
        resp = self.session.post(url, params=params, data=body)
        print(f"    HTTP {resp.status_code} ({len(resp.text)} bytes)")

        if resp.status_code != 200:
            print(f"    [!] Handshake failed: {resp.text[:500]}")
            return False

        return self.OnKeyHandshake(resp.text)

    def OnKeyHandshake(self, response_text: str) -> bool:
        """NetflixMSL::OnKeyHandshake @ 0x10211923c

        バイナリ文字列: "headerdata", "keyresponsedata", "mastertoken", "errordata"
        """
        print("    Parsing key handshake response...")

        parts = self.parse_chunked_msl_response(response_text)
        if not parts:
            print("    [!] Failed to parse MSL response")
            return False

        header_part = parts[0]

        headerdata_b64 = header_part.get("headerdata", "")
        if not headerdata_b64:
            print("    [!] No headerdata in response")
            print(f"    Response keys: {list(header_part.keys())}")
            return False

        try:
            headerdata_raw = base64.b64decode(headerdata_b64)
            header_decoded = json.loads(headerdata_raw)
        except Exception as e:
            print(f"    [!] Failed to decode headerdata: {e}")
            return False

        print(f"    Header keys: {list(header_decoded.keys())}")

        if "errordata" in header_part:
            try:
                err_raw = base64.b64decode(header_part["errordata"])
                err = json.loads(err_raw)
                print(f"    [!] Error: {json.dumps(err, indent=2)}")
            except Exception:
                print("    [!] Errordata present but could not decode")
            return False

        key_response = header_decoded.get("keyresponsedata", {})
        if not key_response:
            print("    [!] No keyresponsedata in header")
            return False

        scheme = key_response.get("scheme", "")
        print(f"    Key exchange scheme: {scheme}")

        if scheme != "ASYMMETRIC_WRAPPED":
            print(f"    [!] Unexpected scheme: {scheme}")
            return False

        if not self.crypto.parse_key_response(key_response):
            print("    [!] Failed to parse key response")
            return False

        if "mastertoken" in key_response:
            self.master_token = key_response["mastertoken"]
            print("    [MSL] MasterToken from keyresponsedata")
        elif "mastertoken" in header_part:
            self.master_token = header_part["mastertoken"]
            print("    [MSL] MasterToken from header")

        if "useridtoken" in header_decoded:
            self.useridtoken = header_decoded["useridtoken"]
            print("    [MSL] UserIdToken updated")

        if self.master_token:
            self.update_master_token(self.master_token)

        self.save_msl_data()

        print("    [OK] Key handshake successful")
        return True

    # ====================================================================
    # MasterToken 管理 (update_master_token @ 0x10211a2fa)
    # ====================================================================

    def update_master_token(self, master_token: dict) -> None:
        """バイナリ文字列: "tokendata", "sequencenumber", "expiration" """
        self.master_token = master_token
        tokendata_b64 = master_token.get("tokendata", "")
        if tokendata_b64:
            try:
                tokendata = json.loads(base64.b64decode(tokendata_b64))
                seq = tokendata.get("sequencenumber", 0)
                exp = tokendata.get("expiration", 0)
                print(f"    [MSL] Token seq={seq}, expires={exp}")
            except Exception:
                pass

    # ====================================================================
    # MSL リクエスト生成 (generate_msl_request_data @ 0x102127482)
    # ====================================================================

    def generate_msl_request_data(self, payload_data: dict) -> str:
        """暗号化モードで MSL リクエスト全体を構築.

        Kodi 実装に準拠:
          signed_header = {headerdata: Base64(enc_envelope), signature: sign(enc_envelope), mastertoken}
          encrypted_chunk = {payload: Base64(enc_envelope), signature: sign(enc_envelope)}
          request = JSON(signed_header) + JSON(encrypted_chunk)
        """
        # ---- ヘッダー ----
        msl_header = self.generate_msl_header(
            is_handshake=False,
            is_renewable=True,
            use_key=True,
        )
        header_json = json.dumps(msl_header)

        # encrypt() は JSON 文字列を返す
        encryption_envelope = self.encrypt(header_json)

        header_envelope = {
            "headerdata": base64.standard_b64encode(
                encryption_envelope.encode("utf-8")
            ).decode("utf-8"),
            "signature": self.sign(encryption_envelope),
            "mastertoken": self.master_token,
        }

        # ---- ペイロード ----
        # data = Base64(JSON(actual_payload))
        data_b64 = base64.standard_b64encode(
            json.dumps(payload_data).encode("utf-8")
        ).decode("utf-8")

        payload_inner = json.dumps(
            {
                "messageid": self.messageid,
                "data": data_b64,
                "sequencenumber": 1,
                "endofmsg": True,
            }
        )

        # ペイロードも暗号化
        payload_envelope = self.encrypt(payload_inner)

        payload_chunk = {
            "payload": base64.standard_b64encode(
                payload_envelope.encode("utf-8")
            ).decode("utf-8"),
            "signature": self.sign(payload_envelope),
        }

        return json.dumps(header_envelope) + json.dumps(payload_chunk)

    # ====================================================================
    # レスポンスパース (parse_chunked_msl_response, decrypt_payload_chunks)
    # ====================================================================

    def parse_chunked_msl_response(self, response_text: str) -> list[dict]:
        """NetflixMSL::parse_chunked_msl_response @ 0x10211bc0e"""
        parts = []
        decoder = json.JSONDecoder()
        idx = 0
        text = response_text

        while idx < len(text):
            remaining = text[idx:].lstrip()
            if not remaining:
                break
            try:
                obj, end = decoder.raw_decode(remaining)
                parts.append(obj)
                idx += (len(text) - idx) - len(remaining) + end
            except json.JSONDecodeError:
                break

        return parts

    def decrypt_payload_chunks(self, payload_chunks: list[dict]) -> list[dict]:
        """NetflixMSL::decrypt_payload_chunks @ 0x10211c22a

        複数チャンクのデータを連結してからJSONパースする。
        endofmsg=False のチャンクは中間データ、endofmsg=True で完結。
        """
        # 全チャンクの data を連結
        concatenated_data = b""

        for chunk in payload_chunks:
            payload_b64 = chunk.get("payload", "")
            if not payload_b64:
                continue

            try:
                payload_outer_raw = base64.b64decode(payload_b64)

                if self.crypto.encryption_key:
                    payload_outer = json.loads(payload_outer_raw)

                    if "ciphertext" in payload_outer:
                        iv = base64.b64decode(payload_outer["iv"])
                        ct = base64.b64decode(payload_outer["ciphertext"])
                        decrypted = self.crypto.decrypt(ct, iv)
                        inner = json.loads(decrypted)
                    else:
                        inner = payload_outer
                else:
                    inner = json.loads(payload_outer_raw)

                data_b64 = inner.get("data", "")
                if data_b64:
                    data_raw = base64.b64decode(data_b64)
                    algo = inner.get("compressionalgo", "")
                    if algo == "GZIP":
                        data_raw = gzip.decompress(data_raw)
                    concatenated_data += data_raw

            except Exception as e:
                return [{"error": str(e)}]

        # 連結したデータを JSON パース
        if not concatenated_data:
            return []

        try:
            return [json.loads(concatenated_data)]
        except json.JSONDecodeError:
            return [{"raw": concatenated_data.decode("utf-8", errors="replace")}]

    def _parse_full_msl_response(self, response_text: str) -> dict | None:
        """完全な MSL レスポンスパース (ヘッダー + ペイロード)."""
        parts = self.parse_chunked_msl_response(response_text)
        if not parts:
            return None

        header_part = parts[0]
        payload_chunks = parts[1:]

        result: dict[str, Any] = {
            "header": header_part,
            "header_decoded": None,
            "payloads": [],
        }

        if "mastertoken" in header_part:
            self.update_master_token(header_part["mastertoken"])

        headerdata_b64 = header_part.get("headerdata", "")
        if headerdata_b64:
            try:
                headerdata_raw = base64.b64decode(headerdata_b64)
                if self.crypto.encryption_key:
                    try:
                        header_envelope = json.loads(headerdata_raw)
                        if "ciphertext" in header_envelope:
                            iv = base64.b64decode(header_envelope["iv"])
                            ct = base64.b64decode(header_envelope["ciphertext"])
                            decrypted = self.crypto.decrypt(ct, iv)
                            result["header_decoded"] = json.loads(decrypted)
                        else:
                            result["header_decoded"] = header_envelope
                    except json.JSONDecodeError:
                        result["header_decoded"] = json.loads(headerdata_raw)
                else:
                    result["header_decoded"] = json.loads(headerdata_raw)
            except Exception as e:
                result["header_decoded"] = {"error": str(e)}

        if payload_chunks:
            result["payloads"] = self.decrypt_payload_chunks(payload_chunks)

        return result

    # ====================================================================
    # マニフェスト (generate_manifest_request_data, load_manifest, OnLoadmanifest)
    # ====================================================================

    def generate_manifest_request_data(
        self,
        viewable_id: str,
        video_codec: str = ENetflixVideoCodec.H264,
        profile: str = ENetflixProfile.HD,
        audio_codec: str = ENetflixAudioCodec.HEAAC,
        challenge_b64: str = "",
    ) -> dict:
        """NetflixMSL::generate_manifest_request_data @ 0x10211facc

        バイナリ文字列:
          "version", "url", "/manifest", "id", "esn", "languages",
          "type", "standard", "manifestVersion", "v2", "viewableId",
          "flavor", "PRE_FETCH", "drmType", "widevine", "drmVersion",
          "usePsshBox", "isBranching", "useHttpsStreams",
          "imageSubtitleHeight", "uiVersion", "shakti-v25d2fa21",
          "uiPlatform", "SHAKTI", "clientVersion", "6.0011.474.011",
          "supportsPreReleasePin", "supportsWatermark",
          "showAllSubDubTracks", "titleSpecificData", "videoOutputInfo",
          "DigitalVideoOutputDescriptor", "outputType", "unknown",
          "supportedHdcpVersions", "isHdcpEngaged", "preferAssistiveAudio",
          "isNonMember", "supportsAdBreakHydration", "challenge",
          "licenseType", "limited", "profiles", "profileGroups", "default"
        """
        video_profiles = get_video_profiles(video_codec)
        audio_profiles = get_audio_profiles(audio_codec)
        all_profiles = (
            video_profiles + audio_profiles + SUBTITLE_PROFILES + IMAGE_PROFILES
        )

        payload: dict[str, Any] = {
            "version": 2,
            "url": "/manifest",
            "id": int(time.time() * 1000),
            "esn": self.esn,
            "languages": [self.locale],
            "params": {
                "type": "standard",
                "manifestVersion": "v2",
                "viewableId": int(viewable_id),
                "profiles": all_profiles,
                "flavor": "PRE_FETCH",
                "drmType": "widevine",
                "drmVersion": 25,
                "usePsshBox": True,
                "isBranching": False,
                "useHttpsStreams": True,
                "imageSubtitleHeight": 1080,
                "uiVersion": UI_VERSION,
                "uiPlatform": UI_PLATFORM,
                "clientVersion": CLIENT_VERSION,
                "supportsPreReleasePin": True,
                "supportsWatermark": True,
                "showAllSubDubTracks": False,
                "titleSpecificData": {},
                "videoOutputInfo": [
                    {
                        "type": "DigitalVideoOutputDescriptor",
                        "outputType": "unknown",
                        "supportedHdcpVersions": [],
                        "isHdcpEngaged": False,
                    }
                ],
                "preferAssistiveAudio": False,
                "isNonMember": False,
                "supportsAdBreakHydration": False,
                "profileGroups": [
                    {
                        "name": "default",
                        "profiles": all_profiles,
                    }
                ],
            },
        }

        if challenge_b64:
            payload["params"]["challenge"] = challenge_b64
            payload["params"]["licenseType"] = "limited"

        return payload

    def load_manifest(
        self,
        viewable_id: str,
        video_codec: str = ENetflixVideoCodec.H264,
        profile: str = ENetflixProfile.HD,
        audio_codec: str = ENetflixAudioCodec.HEAAC,
    ) -> dict | None:
        """NetflixMSL::load_manifest @ 0x10211ec08 / 0x102126dd2"""
        if not self.crypto.encryption_key:
            print("[!] Key handshake required first")
            return None

        print(
            f"[Step 2] Get Manifest (viewableId={viewable_id}, "
            f"codec={video_codec}, audio={audio_codec})..."
        )

        manifest_payload = self.generate_manifest_request_data(
            viewable_id,
            video_codec,
            profile,
            audio_codec,
        )

        body = self.generate_msl_request_data(manifest_payload)
        url = ENDPOINTS["pbo_manifests"]
        params = self._build_query_params("manifest")

        print(f"    POST {url}")
        resp = self.session.post(url, params=params, data=body)
        print(f"    HTTP {resp.status_code} ({len(resp.text)} bytes)")

        if resp.status_code != 200:
            print(f"    [!] Manifest request failed: {resp.text[:500]}")
            return None

        return self.OnLoadmanifest(resp.text)

    def OnLoadmanifest(self, response_text: str) -> dict | None:
        """NetflixMSL::OnLoadmanifest @ 0x10211cd9a"""
        result = self._parse_full_msl_response(response_text)
        if not result:
            print("    [!] Failed to parse manifest response")
            return None

        if not result.get("payloads"):
            print("    [!] No payload in manifest response")
            hd = result.get("header_decoded", {})
            if hd and isinstance(hd, dict):
                print(f"    Header decoded keys: {list(hd.keys())}")
            return None

        manifest = result["payloads"][0]
        print("    [OK] Manifest received")
        return manifest

    # ====================================================================
    # ライセンス (getlicense_request_data, request_license, ParsingLicenseData)
    # ====================================================================

    def getlicense_request_data(
        self,
        challenge_b64: str,
        session_id: str,
        xid: str,
    ) -> dict:
        """NetflixMSL::getlicense_request_data @ 0x10212820a

        バイナリ文字列:
          "version", "url", "/license", "id", "esn", "languages",
          "sessionId", "clientTime", "challengeBase64", "xid",
          "echo", "uiVersion", "clientVersion"
        """
        return {
            "version": 2,
            "url": "/license",
            "id": int(time.time() * 1000),
            "esn": self.esn,
            "languages": [self.locale],
            "params": {
                "sessionId": session_id,
                "clientTime": int(time.time()),
                "challengeBase64": challenge_b64,
                "xid": xid,
            },
            "echo": "",
            "uiVersion": UI_VERSION,
            "clientVersion": CLIENT_VERSION,
        }

    def request_license(
        self, challenge_b64: str, session_id: str, xid: str = ""
    ) -> dict | None:
        """ライセンスリクエストを送信.

        Note: challenge_b64 は CDM (Widevine) が生成したチャレンジ。
        CDM なしではチャレンジを生成できないため、CDM 連携時のみ使用可能。
        """
        if not self.crypto.encryption_key:
            print("[!] Key handshake required first")
            return None

        print("[License] Requesting license...")

        license_payload = self.getlicense_request_data(challenge_b64, session_id, xid)
        body = self.generate_msl_request_data(license_payload)
        url = ENDPOINTS["pbo_licenses"]
        params = self._build_query_params("license")

        resp = self.session.post(url, params=params, data=body)
        print(f"    HTTP {resp.status_code} ({len(resp.text)} bytes)")

        if resp.status_code != 200:
            print("    [!] License request failed")
            return None

        result = self._parse_full_msl_response(resp.text)
        if not result or not result.get("payloads"):
            return None

        return result["payloads"][0]

    @staticmethod
    def ParsingLicenseData(license_response: dict) -> str | None:
        """NetflixMSL::ParsingLicenseData @ 0x10211b750

        バイナリ文字列: 'licenseResponseBase64":"', 'seResponseBase64'
        """

        def _find_key(d: Any, key: str) -> str | None:
            if isinstance(d, dict):
                if key in d:
                    return d[key]
                for v in d.values():
                    r = _find_key(v, key)
                    if r:
                        return r
            elif isinstance(d, list):
                for item in d:
                    r = _find_key(item, key)
                    if r:
                        return r
            return None

        return _find_key(license_response, "licenseResponseBase64")

    # ====================================================================
    # ストリーム情報抽出
    # ====================================================================

    @staticmethod
    def extract_streams(manifest: dict) -> dict:
        """マニフェストからストリーム情報を抽出 (CDN URL, KID, PSSH 等)."""
        print("[Step 3] Extract stream info...")

        result_data = manifest.get("result", manifest)
        if isinstance(result_data, list):
            result_data = result_data[0] if result_data else {}

        info: dict[str, Any] = {
            "movieId": result_data.get("movieId"),
            "duration": result_data.get("duration"),
            "video_streams": [],
            "audio_streams": [],
            "pssh": [],
            "kids": set(),
        }

        for vt in result_data.get("video_tracks", []):
            for s in vt.get("streams", vt.get("downloadables", [])):
                stream = {
                    "content_profile": s.get("content_profile", ""),
                    "bitrate": s.get("bitrate", 0),
                    "res": f"{s.get('res_w', '?')}x{s.get('res_h', '?')}",
                    "vmaf": s.get("vmaf", 0),
                    "drmHeaderId": s.get("drmHeaderId", ""),
                    "urls": [],
                }
                for u in s.get("urls", []):
                    if isinstance(u, dict):
                        stream["urls"].append(u.get("url", ""))
                    elif isinstance(u, str):
                        stream["urls"].append(u)
                if stream["drmHeaderId"]:
                    info["kids"].add(stream["drmHeaderId"])
                info["video_streams"].append(stream)

        for at in result_data.get("audio_tracks", []):
            lang = at.get("language", "?")
            for s in at.get("streams", at.get("downloadables", [])):
                stream = {
                    "content_profile": s.get("content_profile", ""),
                    "bitrate": s.get("bitrate", 0),
                    "language": lang,
                    "channels": s.get("channels", ""),
                    "drmHeaderId": s.get("drmHeaderId", ""),
                    "urls": [],
                }
                for u in s.get("urls", []):
                    if isinstance(u, dict):
                        stream["urls"].append(u.get("url", ""))
                    elif isinstance(u, str):
                        stream["urls"].append(u)
                if stream["drmHeaderId"]:
                    info["kids"].add(stream["drmHeaderId"])
                info["audio_streams"].append(stream)

        for dh in result_data.get("drmHeader", result_data.get("drmHeaders", [])):
            if isinstance(dh, dict):
                info["pssh"].append(
                    {
                        "keyId": dh.get("keyId", ""),
                        "data": dh.get("data", ""),
                        "systemId": dh.get("systemId", ""),
                    }
                )

        info["kids"] = list(info["kids"])

        print(f"    movieId: {info['movieId']}")
        print(f"    duration: {info['duration']}ms")
        print(f"    video streams: {len(info['video_streams'])}")
        print(f"    audio streams: {len(info['audio_streams'])}")
        print(f"    KIDs: {info['kids']}")
        print(f"    PSSH boxes: {len(info['pssh'])}")

        if info["video_streams"]:
            best = max(info["video_streams"], key=lambda s: s["bitrate"])
            print(
                f"    best video: {best['content_profile']} "
                f"{best['res']} {best['bitrate']}kbps"
            )
            if best["urls"]:
                print(f"    CDN URL: {best['urls'][0][:100]}...")

        return info

    # ====================================================================
    # セグメントダウンロード
    # ====================================================================

    def download_segment(
        self, url: str, output_path: str, byte_range: str | None = None
    ) -> bool:
        """暗号化された CENC セグメントをダウンロード."""
        print("[Step 4] Download encrypted segment...")
        headers = {}
        if byte_range:
            headers["Range"] = f"bytes={byte_range}"

        resp = self.session.get(url, headers=headers, stream=True)
        print(
            f"    HTTP {resp.status_code} "
            f"Content-Length: {resp.headers.get('Content-Length', '?')}"
        )

        if resp.status_code not in (200, 206):
            print("    [!] Download failed")
            return False

        with open(output_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        size = os.path.getsize(output_path)
        print(f"    [OK] Saved {size} bytes -> {output_path}")
        print("    [!] CENC 暗号化済み — CEK なしでは復号不可")
        return True

    # ====================================================================
    # MSL データ永続化 (save/load/init/check @ 0x10211a66c 等)
    # ====================================================================

    def init_msl_data(self) -> bool:
        """NetflixMSL::init_msl_data @ 0x10211db48"""
        print("[Init] Loading MSL data...")
        if self.load_msl_data():
            if self.check_msl_data():
                print("    [OK] MSL data loaded from cache (valid)")
                return True
            else:
                print("    [!] Cached MSL data expired, re-handshaking...")
        else:
            print("    [!] No cached MSL data, performing handshake...")

        return self.perform_key_handshake()

    def check_msl_data(self) -> bool:
        """NetflixMSL::check_msl_data @ 0x10211dd14"""
        if not self.master_token or not self.crypto.encryption_key:
            return False

        tokendata_b64 = self.master_token.get("tokendata", "")
        if not tokendata_b64:
            return False

        try:
            tokendata = json.loads(base64.b64decode(tokendata_b64))
            expiration = tokendata.get("expiration", 0)
            now = int(time.time())
            if expiration > 0 and now >= expiration:
                print(f"    [!] Token expired (exp={expiration}, now={now})")
                return False
            return True
        except Exception:
            return False

    def save_msl_data(self) -> bool:
        """NetflixMSL::save_msl_data @ 0x10211a66c

        バイナリ文字列: "MSLDATA", "MSLDATA2", "cache_path",
                      "mastertoken", "encryption_key", "sign_key", "rsa_key", "esn"
        """
        data = {"esn": self.esn, "mastertoken": self.master_token}
        data.update(self.crypto.export_keys())

        cache_file = self.cache_dir / "MSLDATA"
        try:
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"    [MSL] Data saved -> {cache_file}")
            return True
        except Exception as e:
            print(f"    [!] save_msl_data failed: {e}")
            return False

    def load_msl_data(self) -> bool:
        """NetflixMSL::load_msl_data @ 0x10211dd1c

        バイナリ文字列:
          "load_msl_data success", "load_msl_data faild",
          "load_msl_data exception: ", "load_msl_data present :%1, exp :%2"
        """
        cache_file = self.cache_dir / "MSLDATA"
        if not cache_file.exists():
            return False

        try:
            with open(cache_file) as f:
                data = json.load(f)

            if data.get("esn") != self.esn:
                print("    [!] ESN mismatch in cached data")
                return False

            self.master_token = data.get("mastertoken")

            if not self.crypto.import_keys(data):
                print("    [!] load_msl_data faild")
                return False

            print("    load_msl_data success")
            return True

        except Exception as e:
            print(f"    load_msl_data exception: {e}")
            return False

    # ====================================================================
    # GetChallenge (CDM 連携)
    # ====================================================================

    def GetChallenge(self) -> str:
        """NetflixMSL::GetChallenge @ 0x10211eb96

        CDM がないため空文字列を返す。pywidevine 等が必要。
        """
        print("    [!] GetChallenge: CDM not available (requires pywidevine)")
        return ""
