"""Frida ログ → Chrome extension 形式変換の共通基盤.

Transformer 基底クラス、ユーティリティ関数、出力処理を提供する。
iOS / Android 固有のハンドラマッピングはサブクラスで定義する。
"""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

import cbor2


# ── ユーティリティ ──


def load_entries(path: Path) -> list[dict]:
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("@@LOG@@"):
                line = line[7:]
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def b64_to_hex(b64: str | None) -> str | None:
    if not b64:
        return None
    try:
        return base64.b64decode(b64).hex()
    except Exception:
        return None


def b64_to_jwk_oct(b64: str | None, key_ops: list[str] | None = None) -> dict | None:
    """base64 鍵 → Chrome 互換 JWK oct."""
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64)
        k = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        bits = len(raw) * 8
        alg = f"A{bits}CBC" if bits in (128, 256) else f"A{bits}"
        jwk: dict = {"alg": alg, "ext": True, "k": k, "kty": "oct"}
        if key_ops:
            jwk["key_ops"] = key_ops
        return jwk
    except Exception:
        return None


def b64_to_iv_obj(b64: str | None) -> dict | None:
    """base64 IV → Chrome 互換 {0:xx, 1:xx, ...}."""
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64)
        return {str(i): b for i, b in enumerate(raw)}
    except Exception:
        return None


# ── Transformer 基底クラス ──


class BaseTransformer:
    """イベントハンドラマッピングに基づいてログを変換する基底クラス."""

    # サブクラスでオーバーライドする
    _handlers: dict = {}

    def __init__(self):
        self.seq = 0
        self.capture_entries: list[dict] = []
        self.msl_messages: list[dict] = []
        self.http_captures: list[dict] = []
        self.crypto_keys: dict = {"generateKey": [], "importKey": [], "deriveKey": []}
        self.ale_keys: list[dict] = []
        self.esn: dict = {"prv": None, "pxa": None, "capturedAt": ""}
        self.manifests_raw: list[dict] = []  # 複数マニフェスト対応
        self.licenses: list[dict] = []
        self._seen_keys: set = set()
        self._cookies: dict[str, str] = {}  # name → value
        # CBOR MSL チャンク管理 (messageid → [payload_bytes, ...])
        self._cbor_chunks: dict[int, list[bytes]] = {}
        self._cbor_meta: dict[int, dict] = {}  # messageid → {sender, ts, ...}
        self.provisions: list[dict] = []  # aleProvision リクエスト/レスポンス
        self._pending_provision: dict | None = None  # リクエスト待ち合わせ
        self.storage_user_defaults: dict | None = (
            None  # UserDefaults / SharedPreferences
        )
        self.storage_keychain: list[dict] = []  # Keychain エントリ
        self.storage_shared_prefs: list[dict] = []  # Android SharedPreferences ファイル
        self.storage_files: list[dict] = []  # サンドボックスファイル
        self.storage_sandbox: dict | None = None  # サンドボックス構造

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def transform(self, entries: list[dict]):
        for e in entries:
            event = e.get("event", "")
            handler = self._handlers.get(event)
            if handler:
                handler(self, e)
        # CBOR チャンク結合 + ペイロード抽出
        self._finalize_cbor_chunks()

    # ── 共通ハンドラ (iOS / Android 共通のイベント) ──

    def handle_msl_message(self, e: dict):
        entry = {
            "seq": self.next_seq(),
            "type": "msl.message",
            "direction": e.get("direction", "unknown"),
            "ts": e.get("ts", ""),
            "algorithm": e.get("algorithm", "AES-CBC"),
            "size": e.get("size", 0),
            "format": e.get("format", "json"),
            "envelope": e.get("envelope"),
            "header": e.get("header"),
            "useridtoken": e.get("useridtoken"),
            "servicetokens": e.get("servicetokens"),
            "payload": e.get("payload"),
            "payloads": e.get("payloads"),
        }
        if e.get("data"):
            entry["data"] = e["data"]
        self.msl_messages.append(entry)
        self.capture_entries.append(entry)

    def handle_msl_api(self, e: dict):
        params = e.get("params")
        if params and isinstance(params, str):
            try:
                params = json.loads(params)
            except json.JSONDecodeError:
                pass
        url = e.get("url", "")
        entry = {
            "seq": self.next_seq(),
            "type": "msl.message",
            "direction": "encrypt",
            "ts": e.get("ts", ""),
            "algorithm": "AES-CBC",
            "size": len(json.dumps(params)) if params else 0,
            "format": "json",
            "envelope": None,
            "header": None,
            "useridtoken": None,
            "servicetokens": None,
            "payload": {"url": url, "params": params},
            "payloads": None,
        }
        self.msl_messages.append(entry)

        # aleProvision リクエストを検出
        if isinstance(params, dict) and params.get("url") == "/aleProvision":
            self._pending_provision = {
                "request": params,
                "requestTs": e.get("ts", ""),
                "url": url,
                "headers": e.get("headers"),
            }
        elif isinstance(params, str) and "aleProvision" in params:
            self._pending_provision = {
                "request": params,
                "requestTs": e.get("ts", ""),
                "url": url,
                "headers": e.get("headers"),
            }
        self.capture_entries.append(entry)

    def handle_msl_api_response(self, e: dict):
        resp_str = e.get("response")
        resp = None
        if resp_str and isinstance(resp_str, str):
            try:
                resp = json.loads(resp_str)
            except json.JSONDecodeError:
                resp = resp_str
        entry = {
            "seq": self.next_seq(),
            "type": "msl.message",
            "direction": "decrypt",
            "ts": e.get("ts", ""),
            "algorithm": "AES-CBC",
            "size": len(resp_str) if resp_str else 0,
            "format": "json" if isinstance(resp, dict) else "text",
            "envelope": None,
            "header": None,
            "useridtoken": None,
            "servicetokens": None,
            "payload": resp,
            "payloads": None,
        }
        self.msl_messages.append(entry)
        self.capture_entries.append(entry)
        # ライセンス・マニフェスト抽出
        self._extract_from_json_response(resp_str, e.get("ts", ""))

    def handle_http_request(self, e: dict):
        headers = e.get("headers") or {}
        # Cookie 収集
        cookie_str = headers.get("Cookie", headers.get("cookie", ""))
        if cookie_str:
            for pair in cookie_str.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, _, value = pair.partition("=")
                    name = name.strip()
                    value = value.strip()
                    if name and value:
                        self._cookies[name] = value

        # ESN 収集 (HTTP ヘッダー + URL パラメータ)
        for k, v in headers.items():
            if "esn" in k.lower() and v:
                self._update_esn_from_http(v, e.get("ts", ""))
        url = e.get("url", "")
        if "esn=" in url.lower():
            import re
            from urllib.parse import unquote

            m = re.search(r"[&?]esn=([^&]+)", url, re.IGNORECASE)
            if m:
                self._update_esn_from_http(unquote(m.group(1)), e.get("ts", ""))

        entry = {
            "seq": self.next_seq(),
            "type": "http.xhr",
            "ts": e.get("ts", ""),
            "url": e.get("url", ""),
            "method": e.get("method", "GET"),
            "requestHeaders": headers,
            "statusCode": None,
            "statusText": None,
            "responseHeaders": None,
        }
        self.http_captures.append(entry)
        self.capture_entries.append(entry)

    def handle_http_response(self, e: dict):
        entry = {
            "seq": self.next_seq(),
            "type": "http.xhr",
            "ts": e.get("ts", ""),
            "url": e.get("url", ""),
            "method": None,
            "requestHeaders": None,
            "statusCode": e.get("status", 0),
            "statusText": "OK" if e.get("status") == 200 else "",
            "responseHeaders": e.get("responseHeaders") or {},
        }
        self.http_captures.append(entry)
        self.capture_entries.append(entry)

    def handle_aes_cbc_encrypt(self, e: dict):
        entry = {
            "seq": self.next_seq(),
            "type": "encrypt",
            "ts": e.get("ts", ""),
            "algorithm": "AES-CBC",
            "algorithmDetail": {
                "name": "AES-CBC",
                "iv": b64_to_iv_obj(e.get("iv_b64")),
            },
            "keyInfo": b64_to_jwk_oct(e.get("key_b64"), ["encrypt", "decrypt"]),
            "plaintextSize": e.get("plaintext_size", 0),
            "ciphertextSize": e.get("ciphertext_size", 0),
        }
        self.capture_entries.append(entry)
        # encrypt 側の CBOR からも ESN (sender) を抽出
        self._extract_esn_from_cbor(e)

    def handle_aes_cbc_decrypt(self, e: dict):
        entry = {
            "seq": self.next_seq(),
            "type": "decrypt",
            "ts": e.get("ts", ""),
            "algorithm": "AES-CBC",
            "algorithmDetail": {
                "name": "AES-CBC",
                "iv": b64_to_iv_obj(e.get("iv_b64")),
            },
            "keyInfo": b64_to_jwk_oct(e.get("key_b64"), ["encrypt", "decrypt"]),
            "ciphertextSize": e.get("ciphertext_size", 0),
            "plaintextSize": e.get("plaintext_size", 0),
        }
        self.capture_entries.append(entry)
        # CBOR MSL ペイロードのチャンク蓄積
        self._accumulate_cbor_chunk(e)

    def handle_hmac(self, e: dict):
        entry = {
            "seq": self.next_seq(),
            "type": "sign",
            "ts": e.get("ts", ""),
            "algorithm": "HMAC",
            "algorithmDetail": {"name": "HMAC", "hash": {"name": "SHA-256"}},
            "keyInfo": b64_to_jwk_oct(e.get("key_b64"), ["sign", "verify"]),
            "dataSize": e.get("data_size", 0),
            "signatureHex": b64_to_hex(e.get("signature_b64")),
        }
        self.capture_entries.append(entry)

    def handle_aes_kw_unwrap(self, e: dict):
        entry = {
            "seq": self.next_seq(),
            "type": "importKey",
            "ts": e.get("ts", ""),
            "format": "raw",
            "algorithm": "AES-KW",
            "algorithmDetail": {"name": "AES-KW"},
            "originalExtractable": True,
            "keyUsages": ["encrypt", "decrypt"],
            "keyDataB64": e.get("wrapped_key_b64"),
            "exportedKey": b64_to_jwk_oct(
                e.get("unwrapped_key_b64"), ["encrypt", "decrypt"]
            ),
        }
        self.crypto_keys["importKey"].append(entry)
        self.capture_entries.append(entry)

    def handle_dh_shared_secret(self, e: dict):
        entry = {
            "seq": self.next_seq(),
            "type": "deriveKey",
            "ts": e.get("ts", ""),
            "algorithm": "DH",
            "algorithmDetail": {"name": "DH"},
            "derivedKeyAlgorithm": "AES-CBC",
            "originalExtractable": True,
            "keyUsages": ["encrypt", "decrypt"],
            "derivedKey": b64_to_jwk_oct(
                e.get("shared_secret_b64"), ["encrypt", "decrypt"]
            ),
            "derivedKeyRaw": b64_to_hex(e.get("shared_secret_b64")),
        }
        self.crypto_keys["deriveKey"].append(entry)
        self.capture_entries.append(entry)

    def handle_rsa(self, e: dict):
        is_encrypt = "Encrypt" in e.get("event", "")
        entry = {
            "seq": self.next_seq(),
            "type": "encrypt" if is_encrypt else "decrypt",
            "ts": e.get("ts", ""),
            "algorithm": "RSA-OAEP",
            "algorithmDetail": {"name": "RSA-OAEP"},
            "keyInfo": None,
            "plaintextSize": e.get("input_size", 0)
            if is_encrypt
            else e.get("output_size", 0),
            "ciphertextSize": e.get("output_size", 0)
            if is_encrypt
            else e.get("input_size", 0),
        }
        self.capture_entries.append(entry)

    def handle_aes_cbc_encrypt_key(self, e: dict):
        """初出の鍵を generateKey として記録."""
        key_b64 = e.get("key_b64")
        if not key_b64 or key_b64 in self._seen_keys:
            return
        self._seen_keys.add(key_b64)
        entry = {
            "seq": self.next_seq(),
            "type": "generateKey",
            "ts": e.get("ts", ""),
            "algorithm": "AES-CBC",
            "algorithmDetail": {
                "name": "AES-CBC",
                "length": (e.get("key_size", 16)) * 8,
            },
            "originalExtractable": True,
            "keyUsages": ["encrypt", "decrypt"],
            "key": b64_to_jwk_oct(key_b64, ["encrypt", "decrypt"]),
            "keyRaw": b64_to_hex(key_b64),
        }
        self.crypto_keys["generateKey"].append(entry)
        self.capture_entries.append(entry)

    def handle_aes_cbc_encrypt_combined(self, e: dict):
        self.handle_aes_cbc_encrypt_key(e)
        self.handle_aes_cbc_encrypt(e)

    def handle_ale_keys(self, e: dict):
        self.ale_keys.append(
            {
                "encryptionKey": e.get("encryptionKey", ""),
                "hmacKey": e.get("hmacKey", ""),
                "kid": e.get("kid", ""),
                "jweToken": e.get("jweToken", ""),
                "scheme": e.get("scheme", "CLEAR"),
                "rawKeyHex": e.get("rawKeyHex", ""),
                "capturedAt": e.get("ts", ""),
            }
        )

    def handle_esn(self, e: dict):
        esn = e.get("esn", "")
        if not esn:
            return
        self.esn["prv"] = esn
        self.esn["capturedAt"] = e.get("ts", "")

    def handle_manifest(self, e: dict):
        if "videoTracks" in e:
            self.manifest_raw = {
                "result": {
                    "movieId": e.get("movieId"),
                    "duration": e.get("duration"),
                    "video_tracks": e.get("videoTracks", []),
                    "audio_tracks": e.get("audioTracks", []),
                    "timedtexttracks": e.get("textTracks_detail", []),
                }
            }

    # ── CBOR MSL チャンク処理 ──
    # iOS MSL は CBOR エンコード: 整数キー {14=seq, 20=sender, 22=msgid, 44=algo, 62=data, 63=endofmsg}

    _CBOR_KEY_SEQ = 14
    _CBOR_KEY_SENDER = 20
    _CBOR_KEY_MSGID = 22
    _CBOR_KEY_ALGO = 44
    _CBOR_KEY_DATA = 62
    _CBOR_KEY_ENDOFMSG = 63

    def _accumulate_cbor_chunk(self, e: dict):
        """decrypt イベントの plaintext を CBOR パースしてチャンク蓄積."""
        pt_b64 = e.get("plaintext_b64")
        if not pt_b64:
            return
        try:
            raw = base64.b64decode(pt_b64)
            decoded = cbor2.loads(raw)
        except Exception:
            return
        if not isinstance(decoded, dict):
            return

        msgid = decoded.get(self._CBOR_KEY_MSGID)
        if msgid is None:
            return

        payload = decoded.get(self._CBOR_KEY_DATA)
        algo = decoded.get(self._CBOR_KEY_ALGO, "")
        sender = decoded.get(self._CBOR_KEY_SENDER, "")

        if payload and isinstance(payload, bytes):
            try:
                if algo == "GZIP":
                    payload = gzip.decompress(payload)
            except Exception:
                pass
            if msgid not in self._cbor_chunks:
                self._cbor_chunks[msgid] = []
                self._cbor_meta[msgid] = {"sender": sender, "ts": e.get("ts", "")}
            self._cbor_chunks[msgid].append(payload)

        # sender → ESN
        if sender:
            self._update_esn_from_sender(sender, e.get("ts", ""))

    def _update_esn_from_sender(self, sender: str, ts: str):
        """CBOR sender → PRV ESN (暗号ペイロード内の ESN)."""
        if not sender or sender == "Netflix":
            return
        if "-PXA-" in sender.upper():
            self.esn["pxa"] = sender
        else:
            self.esn["prv"] = sender
        self.esn["capturedAt"] = ts

    def _update_esn_from_http(self, esn: str, ts: str):
        """HTTP ヘッダー/URL パラメータ → PXA or PRV."""
        if not esn:
            return
        if "-PXA-" in esn.upper():
            if not self.esn["pxa"]:
                self.esn["pxa"] = esn
                self.esn["capturedAt"] = ts
        elif "-PRV-" in esn.upper():
            # PRV ESN は常に上書き (APPBOOT 等の仮 ESN を置換)
            self.esn["prv"] = esn
            self.esn["capturedAt"] = ts
        else:
            # 不明な形式は prv にフォールバック (正式 ESN がなければ)
            if not self.esn["prv"] or "-PRV-" not in (self.esn["prv"] or "").upper():
                self.esn["prv"] = esn
                self.esn["capturedAt"] = ts

    def _extract_esn_from_cbor(self, e: dict):
        """encrypt の plaintext を CBOR パースして sender (ESN) を抽出."""
        pt_b64 = e.get("plaintext_b64")
        if not pt_b64:
            return
        try:
            raw = base64.b64decode(pt_b64)
            decoded = cbor2.loads(raw)
        except Exception:
            return
        if not isinstance(decoded, dict):
            return
        sender = decoded.get(self._CBOR_KEY_SENDER, "")
        if sender:
            self._update_esn_from_sender(sender, e.get("ts", ""))
        # headerdata (CBOR キー 18) にも sender が含まれる場合がある
        headerdata = decoded.get(18)
        if isinstance(headerdata, dict):
            hdr_sender = headerdata.get(self._CBOR_KEY_SENDER, "")
            if hdr_sender:
                self._update_esn_from_sender(hdr_sender, e.get("ts", ""))

    def _finalize_cbor_chunks(self):
        """蓄積されたチャンクを結合して JSON パース → manifest/license/ESN 抽出."""
        for msgid, parts in self._cbor_chunks.items():
            combined = b"".join(parts)
            meta = self._cbor_meta.get(msgid, {})
            ts = meta.get("ts", "")

            try:
                obj = json.loads(combined)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            result = obj.get("result")
            # result が list の場合 (iOS 標準形式)
            if isinstance(result, list) and len(result) > 0:
                items = [r for r in result if isinstance(r, dict)]
            # result が dict の場合 (Android 形式)
            elif isinstance(result, dict):
                items = [result]
            else:
                continue

            for r0 in items:
                # マニフェスト
                if "video_tracks" in r0 or "audio_tracks" in r0:
                    self._extract_manifest_from_result(r0, ts)

                # ライセンス応答
                if "licenseResponseBase64" in r0:
                    self._extract_license(r0, ts)

                # ALE provisionResponse
                if "provisionResponse" in r0:
                    self._extract_ale_from_provision(r0, ts)

    def _extract_manifest_from_result(self, result: dict, ts: str):
        """Chrome manifest_<id>.json と同一形式で抽出."""
        movie_id = result.get("movieId")
        manifest = {
            "result": result,
        }
        self.manifests_raw.append(manifest)

        # msl.message としても記録
        entry = {
            "seq": self.next_seq(),
            "type": "msl.message",
            "direction": "decrypt",
            "ts": ts,
            "algorithm": "AES-CBC",
            "size": 0,
            "format": "json",
            "envelope": None,
            "header": None,
            "useridtoken": None,
            "servicetokens": None,
            "payload": {"result": result},
            "payloads": None,
        }
        self.msl_messages.append(entry)
        self.capture_entries.append(entry)

    def _extract_ale_from_provision(self, result: dict, ts: str):
        """provisionResponse から ALE 鍵を抽出 + provision.json 用データ蓄積."""
        prov_str = result.get("provisionResponse", "")
        if not prov_str:
            return
        try:
            # iOS: base64, Android: 直接 JSON
            try:
                prov = json.loads(base64.b64decode(prov_str))
            except Exception:
                prov = json.loads(prov_str)
        except Exception:
            return
        keyx = prov.get("keyx")
        if not keyx or not isinstance(keyx, dict):
            return
        data = keyx.get("data", {})
        raw_key = data.get("key") or data.get("wrappedkey")
        if not raw_key:
            return
        try:
            # base64url → bytes
            padded = raw_key + "=" * (4 - len(raw_key) % 4)
            key_bytes = base64.urlsafe_b64decode(padded)
        except Exception:
            return
        ale_key = {
            "encryptionKey": key_bytes[16:32].hex()
            if len(key_bytes) >= 32
            else key_bytes.hex(),
            "hmacKey": key_bytes[:16].hex() if len(key_bytes) >= 16 else "",
            "kid": keyx.get("kid", ""),
            "jweToken": prov.get("token", ""),
            "scheme": keyx.get("scheme", ""),
            "rawKeyHex": key_bytes.hex(),
            "capturedAt": ts,
        }
        self.ale_keys.append(ale_key)

        # provision.json: リクエストとレスポンスをペアリング
        provision_entry: dict = {
            "responseTs": ts,
            "response": {
                "provisionResponse": prov,
                "raw": result,
            },
            "keys": ale_key,
        }
        if self._pending_provision:
            provision_entry["request"] = self._pending_provision.get("request")
            provision_entry["requestTs"] = self._pending_provision.get("requestTs")
            self._pending_provision = None
        self.provisions.append(provision_entry)

    def _extract_license(self, result: dict, ts: str):
        """ライセンス応答を記録."""
        self.licenses.append(
            {
                "licenseResponseBase64": result.get("licenseResponseBase64", ""),
                "drmGroupId": result.get("drmGroupId"),
                "licenseType": result.get("licenseType"),
                "expiration": result.get("expiration"),
                "ts": ts,
            }
        )

        entry = {
            "seq": self.next_seq(),
            "type": "msl.message",
            "direction": "decrypt",
            "ts": ts,
            "algorithm": "AES-CBC",
            "size": 0,
            "format": "json",
            "envelope": None,
            "header": None,
            "useridtoken": None,
            "servicetokens": None,
            "payload": {"result": [result]},
            "payloads": None,
        }
        self.msl_messages.append(entry)
        self.capture_entries.append(entry)

    def _extract_from_json_response(self, body_str: str | None, ts: str):
        """JSON レスポンス文字列からライセンス・マニフェストを抽出."""
        if not body_str:
            return
        try:
            obj = json.loads(body_str)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(obj, dict):
            return

        result = obj.get("result")
        # result が list の場合 (MSL 標準形式)
        if isinstance(result, list):
            for item in result:
                if not isinstance(item, dict):
                    continue
                if "licenseResponseBase64" in item:
                    self._extract_license(item, ts)
                if "video_tracks" in item or "audio_tracks" in item:
                    self._extract_manifest_from_result(item, ts)
        # result が dict の場合
        elif isinstance(result, dict):
            if "licenseResponseBase64" in result:
                self._extract_license(result, ts)
            if "video_tracks" in result or "audio_tracks" in result:
                self._extract_manifest_from_result(result, ts)

    def handle_msl_response_payload(self, e: dict):
        """msl.response.payload / msl.payload イベントの処理."""
        body = e.get("body")
        ts = e.get("ts", "")
        self._extract_from_json_response(body, ts)

        # ESN 抽出 (PayloadChunk のリクエストボディにも ESN が含まれる)
        if body:
            import re

            m = re.search(r"NF[A-Z0-9]+-PRV-[A-Z0-9=\-]+", body)
            if m:
                self._update_esn_from_http(m.group(0), ts)
            m = re.search(r"NF[A-Z0-9]+-PXA-[A-Z0-9=\-]+", body)
            if m:
                self._update_esn_from_http(m.group(0), ts)

        # aleProvision リクエストを検出・保持
        if body:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict) and obj.get("url") == "/aleProvision":
                    self._pending_provision = {
                        "request": obj,
                        "requestTs": ts,
                    }
            except (json.JSONDecodeError, TypeError):
                pass

        # msl.message としても記録
        entry = {
            "seq": self.next_seq(),
            "type": "msl.message",
            "direction": "decrypt",
            "ts": ts,
            "algorithm": "AES-CBC",
            "size": e.get("size", 0),
            "format": "json",
            "envelope": None,
            "header": None,
            "useridtoken": None,
            "servicetokens": None,
            "payload": None,
            "payloads": None,
        }
        # body が小さい場合のみ payload に含める
        if body and len(body) < 65536:
            try:
                entry["payload"] = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                pass
        self.msl_messages.append(entry)
        self.capture_entries.append(entry)

    def handle_storage_user_defaults(self, e: dict):
        self.storage_user_defaults = e.get("entries")

    def handle_storage_keychain(self, e: dict):
        self.storage_keychain.append(e)

    def handle_storage_shared_prefs(self, e: dict):
        self.storage_shared_prefs.append(
            {
                "file": e.get("file"),
                "entries": e.get("entries"),
            }
        )

    def handle_storage_file(self, e: dict):
        self.storage_files.append(e)

    def handle_storage_sandbox(self, e: dict):
        self.storage_sandbox = e

    def handle_noop(self, _e: dict):
        pass


# ── 出力 ──


def write_output(t: BaseTransformer, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "keys").mkdir(exist_ok=True)
    (out_dir / "eme").mkdir(exist_ok=True)
    (out_dir / "eme" / "challenges").mkdir(exist_ok=True)
    (out_dir / "eme" / "responses").mkdir(exist_ok=True)

    # cookies.txt (Netscape format, same as Chrome extension export)
    if t._cookies:
        with open(out_dir / "cookies.txt", "w") as f:
            f.write("# Netscape HTTP Cookie File\n")
            f.write("# https://curl.se/docs/http-cookies.html\n")
            f.write(f"# Extracted from HTTP headers\n\n")
            for name, value in sorted(t._cookies.items()):
                f.write(f".netflix.com\tTRUE\t/\tTRUE\t0\t{name}\t{value}\n")

    with open(out_dir / "capture.jsonl", "w") as f:
        for entry in t.capture_entries:
            f.write(json.dumps(entry, indent=2, ensure_ascii=False) + "\n")

    if t.msl_messages:
        with open(out_dir / "msl_messages.jsonl", "w") as f:
            for msg in t.msl_messages:
                f.write(json.dumps(msg, indent=2, ensure_ascii=False) + "\n")

    if t.http_captures:
        with open(out_dir / "http_captures.json", "w") as f:
            json.dump(t.http_captures, f, indent=2, ensure_ascii=False)

    if t.esn["prv"] or t.esn["pxa"]:
        with open(out_dir / "esn.json", "w") as f:
            json.dump(t.esn, f, indent=2)

    if t.ale_keys:
        with open(out_dir / "keys" / "ale_keys.json", "w") as f:
            json.dump(t.ale_keys, f, indent=2)

    has_crypto = any(len(v) > 0 for v in t.crypto_keys.values())
    if has_crypto:
        with open(out_dir / "keys" / "crypto_keys.json", "w") as f:
            json.dump(t.crypto_keys, f, indent=2, ensure_ascii=False)

    # manifest_<id>.json (複数マニフェスト対応、movieId ごとに最新を保存)
    seen_movies: dict[str, dict] = {}
    for m in t.manifests_raw:
        mid = str(m.get("result", {}).get("movieId", "unknown"))
        seen_movies[mid] = m
    for mid, m in seen_movies.items():
        with open(out_dir / f"manifest_{mid}.json", "w") as f:
            json.dump(m, f, indent=2, ensure_ascii=False)

    # licenses.json
    if t.licenses:
        with open(out_dir / "keys" / "licenses.json", "w") as f:
            json.dump(t.licenses, f, indent=2, ensure_ascii=False)

    # provision.json (aleProvision リクエスト/レスポンス)
    if t.provisions:
        with open(out_dir / "provision.json", "w") as f:
            json.dump(t.provisions, f, indent=2, ensure_ascii=False)

    # storage/ ディレクトリ
    has_storage = (
        t.storage_user_defaults
        or t.storage_keychain
        or t.storage_shared_prefs
        or t.storage_files
        or t.storage_sandbox
    )
    if has_storage:
        (out_dir / "storage").mkdir(exist_ok=True)
        if t.storage_user_defaults:
            with open(out_dir / "storage" / "user_defaults.json", "w") as f:
                json.dump(t.storage_user_defaults, f, indent=2, ensure_ascii=False)
        if t.storage_keychain:
            with open(out_dir / "storage" / "keychain.json", "w") as f:
                json.dump(t.storage_keychain, f, indent=2, ensure_ascii=False)
        if t.storage_shared_prefs:
            with open(out_dir / "storage" / "shared_prefs.json", "w") as f:
                json.dump(t.storage_shared_prefs, f, indent=2, ensure_ascii=False)
        if t.storage_files:
            with open(out_dir / "storage" / "files.json", "w") as f:
                json.dump(t.storage_files, f, indent=2, ensure_ascii=False)
        if t.storage_sandbox:
            with open(out_dir / "storage" / "sandbox.json", "w") as f:
                json.dump(t.storage_sandbox, f, indent=2, ensure_ascii=False)

    with open(out_dir / "eme" / "sessions.json", "w") as f:
        json.dump([], f)
    with open(out_dir / "eme" / "key_statuses.json", "w") as f:
        json.dump([], f)


def print_summary(t: BaseTransformer, platform: str):
    print(f"[+] Transformed ({platform}): {len(t.capture_entries)} entries")
    print(f"    MSL messages:  {len(t.msl_messages)}")
    print(f"    HTTP captures: {len(t.http_captures)}")
    print(f"    ALE keys:      {len(t.ale_keys)}")
    print(f"    Crypto keys:   {sum(len(v) for v in t.crypto_keys.values())}")
    print(f"    ESN:           {t.esn['prv'] or '(none)'}")
    print(f"    Licenses:      {len(t.licenses)}")
    print(f"    Provisions:    {len(t.provisions)}")
    print(f"    Cookies:       {len(t._cookies)}")
    # マニフェスト: movieId ごとにユニーク
    movie_ids = {str(m.get("result", {}).get("movieId", "?")) for m in t.manifests_raw}
    print(
        f"    Manifests:     {len(movie_ids)} ({', '.join(sorted(movie_ids)) if movie_ids else 'none'})"
    )
