#!/usr/bin/env python3
"""test_appboot_e2e.py — iOS MSL appboot End-to-End テスト

ESN から MSL セッション鍵確立までの完全なチェーンをテストする。

## テストするフロー

  Phase 0:  ESN → TFIT エミュレーション → enc_key_0, sign_key_0
  Phase 3:  kdf_renew(PSK, enc_key_0, sign_key_0, nonce) → enc_key_1, sign_key_1
  Phase 1:  DH 鍵ペア生成 → entity_auth_data + key_request_data を構築
            → HMAC-SHA256(sign_key_0, key_request_data_bytes) で署名
            → POST appboot.netflix.com/{ESN_PREFIX}?keyVersion=1
  Phase 2:  server_scheme_data / server_nonce を解析
            → deviceIdToken を x-netflix-deviceidtoken ヘッダーから抽出

## 実測で確定した構造

  entity_auth_data CBOR:
    {
      35: {
        "apphmac":      bytes  # 初回は b"" (以降は compute_apphmac() 結果)
        "appid":        str    # IOS_APPID 定数
        "appkeyversion": int   # 1
        "devicetoken":  bytes  # 初回は b"" (以降は base64.b64decode(device_id_token))
        3:              str    # 完全 ESN (整数キー)
      },
      30: "MGK_APPID"
    }

  key_request_data CBOR:
    {
      6: bytes(352B)  # key 33.6 XOR 暗号化 scheme_data
      9: bytes(16B)   # key 33.9 XOR nonce
      8: str          # identity = 完全 ESN
      7: bytes(0B)    # master_token (新規セッション)
    }

  signature: HMAC-SHA256(sign_key_0, key_request_data_bytes)

## 使用法

  uv run tools/test_appboot_e2e.py
  uv run tools/test_appboot_e2e.py --esn <ESN>
  uv run tools/test_appboot_e2e.py --no-proxy
  uv run tools/test_appboot_e2e.py --device-id-token <B64_TOKEN> --devicetoken-hex <HEX>
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as hmac_mod
import os
import subprocess
import sys

import cbor2
import requests

# プロジェクトの src を Python パスに追加
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "src"))

from netflix_msl.constants import (  # noqa: E402
    IOS_APPBOOT_ENDPOINT,
    IOS_APPID,
    IOS_APPKEYVERSION,
    IOS_KDF_NONCE,
    IOS_KDF_PSK,
    IOS_KEY336_DEVICE_HEADER,
)
from netflix_msl.crypto import NetflixCrypto  # noqa: E402

# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------

TEST_ESN = "NFAPPL-02-IPHONE9=1-AD0455EF27D3A7B8F0872932FD9837874AF3E6F90157195BD22A8063FEB0B79E"

# デフォルトプロキシ (mitmproxy / Proxyman)
DEFAULT_PROXY = "http://192.168.0.51:9080"

# CBOR 数値キー定数
ENTITY_SCHEME = 30
ENTITY_AUTH_DATA = 35
KEYEX_SCHEME = 6
KEYEX_KEYDATA = 7
KEYEX_IDENTITY = 8
KEYEX_NONCE = 9
KEY_ENTITY_AUTH = 34
KEY_KEY_EXCHANGE = 33
KEY_MESSAGE_SIG = 16

# key 33.6 XOR nonce / nonce 変形マスク (実測値)
_N2_MASK = bytes([0xF4, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00])
_N3_MASK = bytes([0xF4, 0x1B, 0x00, 0x18, 0x1B, 0x00, 0x00])
_TAIL_MASK = bytes([0xF3, 0x1C, 0x07, 0x1F])


# ---------------------------------------------------------------------------
# Step 0: TFIT エミュレーション
# ---------------------------------------------------------------------------


def run_tfit_emulation(esn: str) -> tuple[bytes, bytes]:
    """tools/emulate_tfit.py を呼び出して MGK を導出する.

    Returns:
        (enc_key_0, sign_key_0) — 各 16B / 32B
    """
    script = os.path.join(_PROJECT_ROOT, "tools", "emulate_tfit.py")
    result = subprocess.run(
        ["uv", "run", script, esn],
        capture_output=True,
        text=True,
        cwd=_PROJECT_ROOT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"TFIT エミュレーション失敗:\n{result.stderr}")

    enc_key_0: bytes | None = None
    sign_key_0: bytes | None = None
    for line in result.stdout.splitlines():
        if "MGK key" in line and "(16B)" in line:
            enc_key_0 = bytes.fromhex(line.split(":")[-1].strip())
        elif "MGK vector" in line and "(32B)" in line:
            sign_key_0 = bytes.fromhex(line.split(":")[-1].strip())

    if enc_key_0 is None or sign_key_0 is None:
        raise RuntimeError(f"TFIT 出力から MGK を抽出できなかった:\n{result.stdout}")
    return enc_key_0, sign_key_0


# ---------------------------------------------------------------------------
# Step 1: entity_auth_data の構築 (実測フォーマット)
# ---------------------------------------------------------------------------


def build_entity_auth_data(
    esn: str,
    apphmac: bytes,
    devicetoken: bytes,
    appid: str = IOS_APPID,
    appkeyversion: int = IOS_APPKEYVERSION,
) -> dict:
    """実測フォーマットの entity_auth_data dict を構築する.

    entity_auth_data CBOR 構造 (243 リクエストから確認済み):
      {
        35: {
          "apphmac":      bytes   # raw bytes (初回は b"")
          "appid":        str
          "appkeyversion": int
          "devicetoken":  bytes   # raw bytes 216B (初回は b"")
          3:              str     # 完全 ESN (整数キー 3)
        },
        30: "MGK_APPID"
      }
    """
    auth_data: dict = {
        "apphmac": apphmac,
        "appid": appid,
        "appkeyversion": appkeyversion,
        "devicetoken": devicetoken,
        3: esn,  # 整数キー
    }
    return {
        ENTITY_AUTH_DATA: auth_data,
        ENTITY_SCHEME: "MGK_APPID",
    }


# ---------------------------------------------------------------------------
# Step 2: key_request_data の構築 (key 33)
# ---------------------------------------------------------------------------


def build_key336_scheme_data(
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
        IOS_KEY336_DEVICE_HEADER  # [0:128]
        + session_region  # [128:300]
        + n  # [300:307]
        + s1  # [307:316]
        + n2  # [316:323]
        + s2  # [323:332]
        + n3  # [332:339]
        + s3  # [339:348]
        + tail  # [348:352]
    )
    assert len(plaintext) == 352
    return bytes(plaintext[i] ^ k9_xor_nonce[i % 16] for i in range(352))


def build_key_request_data(
    session_region: bytes,
    s1: bytes,
    s2: bytes,
    s3: bytes,
    esn: str,
) -> tuple[bytes, bytes, bytes]:
    """key_request_data CBOR バイト列を構築する.

    Returns:
        (key_request_bytes, k9_xor_nonce, nonce_7b)
    """
    k9_xor_nonce = os.urandom(16)
    nonce_7b = os.urandom(7)

    scheme_data = build_key336_scheme_data(
        session_region=session_region,
        nonce_7b=nonce_7b,
        s1=s1,
        s2=s2,
        s3=s3,
        k9_xor_nonce=k9_xor_nonce,
    )

    key_request = {
        KEYEX_SCHEME: scheme_data,
        KEYEX_KEYDATA: b"",  # master_token = empty (新規セッション)
        KEYEX_IDENTITY: esn,  # identity = 完全 ESN (サフィックスなし)
        KEYEX_NONCE: k9_xor_nonce,
    }
    return cbor2.dumps(key_request), k9_xor_nonce, nonce_7b


# ---------------------------------------------------------------------------
# Step 3: appboot メッセージを構築
# ---------------------------------------------------------------------------


def build_appboot_message(
    entity_auth_data: dict,
    key_request_bytes: bytes,
    sign_key_0: bytes,
) -> bytes:
    """appboot CBOR MSL メッセージを構築する.

    トップレベル構造:
      {
        34: bytes  ← CBOR(entity_auth_data)
        33: bytes  ← key_request_data
        16: bytes  ← HMAC-SHA256(sign_key_0, key_request_data_bytes)
      }

    署名の対象は key_request_data_bytes のみ (実測で確認済み)。
    """
    signature = hmac_mod.new(sign_key_0, key_request_bytes, hashlib.sha256).digest()

    return cbor2.dumps(
        {
            KEY_ENTITY_AUTH: cbor2.dumps(entity_auth_data),
            KEY_KEY_EXCHANGE: key_request_bytes,
            KEY_MESSAGE_SIG: signature,
        }
    )


# ---------------------------------------------------------------------------
# Step 4: レスポンス解析
# ---------------------------------------------------------------------------


def parse_appboot_response(raw: bytes) -> dict:
    """appboot レスポンス CBOR または JSON MSL エラーを解析する.

    サーバーは 2 種類のレスポンスを返す:
      - 成功 (CBOR): {33: key_response_data_bytes, 16: signature, ...}
      - エラー (JSON): {"signature": "...", "errordata": "<base64>"}

    Returns:
        {
          "server_scheme_data": bytes | None,
          "server_nonce":       bytes | None,
          "scheme_id":          str | None,
          "status_flag":        bytes | None,
          "raw":                dict,
          "error":              dict | None,   # MSL エラーが返った場合
        }
    """
    import json as _json

    result: dict = {
        "server_scheme_data": None,
        "server_nonce": None,
        "scheme_id": None,
        "status_flag": None,
        "raw": {},
        "error": None,
    }

    # JSON MSL エラーレスポンスを先に試みる
    if raw and raw[0] == ord("{"):
        try:
            envelope = _json.loads(raw)
            result["raw"] = envelope
            errordata_b64 = envelope.get("errordata", "")
            if errordata_b64:
                import base64 as _b64

                pad = 4 - len(errordata_b64) % 4
                padded = errordata_b64 + ("=" * pad if pad != 4 else "")
                try:
                    error_dict = _json.loads(_b64.b64decode(padded))
                    result["error"] = error_dict
                except Exception:
                    result["error"] = {"_raw": errordata_b64}
            return result
        except _json.JSONDecodeError:
            pass

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

    krd_raw = top.get(KEY_KEY_EXCHANGE)
    if krd_raw is None:
        return result

    try:
        krd = cbor2.loads(krd_raw) if isinstance(krd_raw, bytes) else krd_raw
    except Exception:
        return result

    if not isinstance(krd, dict):
        return result

    v6 = krd.get(KEYEX_SCHEME)
    if isinstance(v6, bytes):
        result["server_scheme_data"] = v6

    v7 = krd.get(KEYEX_KEYDATA)
    if isinstance(v7, bytes):
        result["status_flag"] = v7

    v8 = krd.get(KEYEX_IDENTITY)
    if v8 is not None:
        result["scheme_id"] = str(v8)

    v9 = krd.get(KEYEX_NONCE)
    if isinstance(v9, bytes):
        result["server_nonce"] = v9

    return result


# ---------------------------------------------------------------------------
# メインフロー
# ---------------------------------------------------------------------------


def run_e2e_test(
    esn: str,
    device_id_token: str | None,
    devicetoken_bytes: bytes | None,
    proxy_url: str | None,
    timeout: int,
) -> None:
    """appboot E2E テストを実行する."""
    sep = "=" * 60
    print(sep)
    print("iOS MSL appboot End-to-End テスト")
    print(sep)
    print(f"ESN: {esn}")
    if device_id_token:
        print(f"device_id_token: {device_id_token[:40]}... (継続セッション)")
    else:
        print("device_id_token: なし (初回リクエスト)")
    print()

    # ------------------------------------------------------------------
    # Phase 0: TFIT エミュレーションで MGK を導出
    # ------------------------------------------------------------------
    print("[Phase 0] TFIT エミュレーション — MGK 導出中...")
    try:
        enc_key_0, sign_key_0 = run_tfit_emulation(esn)
        print(f"  enc_key_0:  {enc_key_0.hex()}")
        print(f"  sign_key_0: {sign_key_0.hex()}")
    except RuntimeError as e:
        print(f"  ERROR: {e}")
        print("  TFIT エミュレーション失敗。処理を中断します。")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Phase 3: KDF で sign_key_1 を導出 (appboot 署名用)
    # ------------------------------------------------------------------
    print()
    print("[Phase 3] KDF — sign_key_0 確認 (appboot 署名に sign_key_0 を使用)...")
    enc_key_1, sign_key_1 = NetflixCrypto.kdf_renew(
        IOS_KDF_PSK, enc_key_0, sign_key_0, IOS_KDF_NONCE
    )
    print(f"  enc_key_1:  {enc_key_1.hex()}")
    print(f"  sign_key_1: {sign_key_1.hex()}")
    print()
    print("  NOTE: appboot 署名は sign_key_0 を使用 (実測で確認)")

    # ------------------------------------------------------------------
    # entity_auth_data フィールドを準備
    # ------------------------------------------------------------------
    if device_id_token:
        # 継続セッション: deviceIdToken から apphmac と devicetoken を設定
        apphmac = device_id_token.encode("utf-8")
        if devicetoken_bytes is not None:
            devicetoken = devicetoken_bytes
        else:
            try:
                # Base64 パディング補完してデコード
                pad = 4 - len(device_id_token) % 4
                padded = device_id_token + ("=" * pad if pad != 4 else "")
                devicetoken = base64.b64decode(padded)
            except Exception as e:
                print(f"  WARNING: device_id_token Base64 デコード失敗: {e}")
                devicetoken = b""
    else:
        # 初回リクエスト: 両フィールドを空バイトに設定
        apphmac = b""
        devicetoken = b""

    print()
    print("[entity_auth] フィールド準備:")
    print(
        f"  apphmac:     {apphmac[:32].hex() if apphmac else '(empty)'} ({len(apphmac)}B)"
    )
    print(
        f"  devicetoken: {devicetoken[:16].hex() if devicetoken else '(empty)'} ({len(devicetoken)}B)"
    )

    # ------------------------------------------------------------------
    # Phase 1a: DH 鍵ペアを生成
    # ------------------------------------------------------------------
    print()
    print("[Phase 1a] DH 鍵ペア生成中...")
    dh_priv_key, dh_pub_key = NetflixCrypto.generate_dh_keypair()
    print(f"  DH pub_key: {dh_pub_key[:16].hex()}... ({len(dh_pub_key)}B)")

    # ------------------------------------------------------------------
    # session_region を TFIT-WB-AES で構築 (NFWebCrypto.framework が必要)
    # ------------------------------------------------------------------
    # TFIT エミュレーションで DH 公開鍵を WB-AES-128-ECB 暗号化して session_region を構築。
    # NFWebCrypto バイナリが存在しない場合は 172B ゼロ埋めにフォールバック。
    # NOTE: session_region[135:172] (37B MGK テール) は CBOR エンコーディングが未解明のため
    #       現状はゼロ埋め。サーバーが鍵交換を拒否する可能性がある。
    print()
    print("[Phase 1a'] session_region を TFIT エミュレーションで構築中...")
    session_region = NetflixCrypto.build_session_region(
        dh_pub_key=dh_pub_key,
        enc_key_0=enc_key_0,
        sign_key_0=sign_key_0,
    )
    is_zero_filled = session_region == bytes(172)
    if is_zero_filled:
        print(
            "  session_region: ゼロ埋め (TFIT バイナリ未検出またはエミュレーション失敗)"
        )
    else:
        print(
            f"  session_region: TFIT 暗号化済み {session_region[:7].hex()}..."
            f" ({len(session_region)}B)"
        )
        print(f"    prefix (7B):    {session_region[:7].hex()}")
        print(f"    TFIT[0] (16B):  {session_region[7:23].hex()}")
        print(f"    TFIT[-1] (16B): {session_region[119:135].hex()}")

    # セパレータは実測キャプチャから取得した既知の値を使用
    # (セッション固有値のため、実際の接続では Frida キャプチャが必要)
    s1 = b"\x00" * 9
    s2 = b"\x00" * 9
    s3 = b"\x00" * 9

    # ------------------------------------------------------------------
    # Phase 1b: entity_auth_data と key_request_data を構築
    # ------------------------------------------------------------------
    print()
    print("[Phase 1b] CBOR メッセージを構築中...")

    entity_auth_data = build_entity_auth_data(
        esn=esn,
        apphmac=apphmac,
        devicetoken=devicetoken,
    )

    key_request_bytes, k9_xor_nonce, nonce_7b = build_key_request_data(
        session_region=session_region,
        s1=s1,
        s2=s2,
        s3=s3,
        esn=esn,
    )

    cbor_message = build_appboot_message(
        entity_auth_data=entity_auth_data,
        key_request_bytes=key_request_bytes,
        sign_key_0=sign_key_0,
    )

    print(f"  CBOR message size: {len(cbor_message)} bytes")
    print(f"  k9_xor_nonce: {k9_xor_nonce.hex()}")
    print(f"  nonce_7b:     {nonce_7b.hex()}")

    # 構築したメッセージの構造を検証
    decoded_check = cbor2.loads(cbor_message)
    print(f"  top-level keys: {sorted(decoded_check.keys())}")
    ead_check = cbor2.loads(decoded_check[KEY_ENTITY_AUTH])
    print(f"  entity_auth scheme: {ead_check[ENTITY_SCHEME]}")
    krd_check = cbor2.loads(decoded_check[KEY_KEY_EXCHANGE])
    print(f"  key_request identity: {krd_check[KEYEX_IDENTITY]}")

    # ------------------------------------------------------------------
    # Phase 1c: POST appboot.netflix.com
    # ------------------------------------------------------------------
    esn_prefix = esn[: esn.rfind("-") + 1]
    url = IOS_APPBOOT_ENDPOINT + esn_prefix
    params = {"keyVersion": str(IOS_APPKEYVERSION)}

    print()
    print(f"[Phase 1c] HTTP POST — {url}")
    if proxy_url:
        print(f"  proxy: {proxy_url}")
    else:
        print("  proxy: なし (直接接続)")

    proxies = {"https": proxy_url, "http": proxy_url} if proxy_url else None
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Netflix/24 CFNetwork/1335.0.3.4 Darwin/21.6.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Netflix.APIAction": "appboot",
            "X-Netflix.client.ftl.esn": esn,
            "X-Netflix.Request.Attempt": "1",
            "X-Netflix.Request.Client.Context": '{"appState":"foreground"}',
        }
    )

    try:
        resp = session.post(
            url,
            params=params,
            data=cbor_message,
            proxies=proxies,
            verify=False,  # mitmproxy では証明書検証をスキップ
            timeout=timeout,
        )
    except requests.exceptions.ConnectionError as e:
        print(f"  CONNECTION ERROR: {e}")
        print()
        print("接続失敗。サーバーに到達できませんでした。")
        print("原因として以下が考えられます:")
        print("  - プロキシ (mitmproxy) が起動していない")
        print("  - ネットワーク接続がない")
        print("  - appboot.netflix.com がブロックされている")
        _print_request_summary(cbor_message, esn, apphmac, devicetoken)
        return
    except requests.exceptions.Timeout:
        print(f"  TIMEOUT (>{timeout}s)")
        _print_request_summary(cbor_message, esn, apphmac, devicetoken)
        return
    except Exception as e:
        print(f"  HTTP ERROR: {type(e).__name__}: {e}")
        _print_request_summary(cbor_message, esn, apphmac, devicetoken)
        return

    print(f"  HTTP {resp.status_code} ({len(resp.content)} bytes)")
    print(f"  Content-Type: {resp.headers.get('content-type', 'N/A')}")

    # deviceIdToken を抽出
    new_device_id_token = resp.headers.get("x-netflix-deviceidtoken", "")
    nfstatus = resp.headers.get("X-Netflix.nfstatus", "")
    if nfstatus:
        print(f"  X-Netflix.nfstatus: {nfstatus}")

    print()
    if resp.status_code != 200:
        print(f"[RESULT] HTTP {resp.status_code} — appboot 失敗")
        print(f"  Response body: {resp.text[:500]}")
        _print_request_summary(cbor_message, esn, apphmac, devicetoken)
        return

    # ------------------------------------------------------------------
    # Phase 1d: レスポンス解析
    # ------------------------------------------------------------------
    print("[Phase 1d] レスポンスを解析中...")

    if new_device_id_token:
        print(f"  x-netflix-deviceidtoken: {new_device_id_token[:60]}...")
        try:
            pad = 4 - len(new_device_id_token) % 4
            padded = new_device_id_token + ("=" * pad if pad != 4 else "")
            decoded_token = base64.b64decode(padded)
            print(
                f"    decoded: {len(decoded_token)} bytes = {decoded_token[:16].hex()}..."
            )
        except Exception:
            pass
    else:
        print("  x-netflix-deviceidtoken: なし")

    nfvdid = resp.cookies.get("nfvdid", "")
    if nfvdid:
        print(f"  nfvdid cookie: {nfvdid[:40]}...")

    try:
        parsed = parse_appboot_response(resp.content)
    except ValueError as e:
        print(f"  レスポンス解析エラー: {e}")
        print(f"  raw (hex): {resp.content[:80].hex()}")
        return

    # MSL エラーレスポンスの場合は表示して終了
    msl_error = parsed.get("error")
    if msl_error is not None:
        print(f"  MSL エラーレスポンス: {msl_error}")
        print()
        print(sep)
        print("[RESULT] appboot MSL エラー返却")
        print(sep)
        print(
            f"STATUS: MSL エラー (errorcode={msl_error.get('errorcode', '?')},"
            f" internalcode={msl_error.get('internalcode', '?')})"
        )
        print()
        print("原因: entity_auth_data または key_request_data が不正です。")
        print("      正しい session_region (TFIT-WB-AES 暗号化 DH 公開鍵) が必要です。")
        _print_request_summary(cbor_message, esn, apphmac, devicetoken)
        return

    server_scheme_data = parsed["server_scheme_data"]
    server_nonce = parsed["server_nonce"]
    scheme_id = parsed["scheme_id"]

    print(f"  scheme_id:          {scheme_id}")
    if server_scheme_data:
        print(
            f"  server_scheme_data: {server_scheme_data[:16].hex()}... ({len(server_scheme_data)}B)"
        )
    else:
        print("  server_scheme_data: なし")
    if server_nonce:
        print(f"  server_nonce:       {server_nonce.hex()} ({len(server_nonce)}B)")
    else:
        print("  server_nonce:       なし")

    # ------------------------------------------------------------------
    # 結果サマリー
    # ------------------------------------------------------------------
    print()
    print(sep)
    print("[RESULT] appboot フロー結果")
    print(sep)

    success = server_scheme_data is not None and server_nonce is not None
    if success:
        print("STATUS: サーバーから key_response_data を受信 (鍵交換データあり)")
        print()
        print("取得値:")
        print(f"  server_scheme_data: {len(server_scheme_data)}B")
        print(f"  server_nonce:       {server_nonce.hex()}")
        print(f"  scheme_id:          {scheme_id}")
        if new_device_id_token:
            print(f"  device_id_token:    {new_device_id_token[:60]}...")
            print()
            print("次回リクエスト用コマンド:")
            print(
                f"  uv run tools/test_appboot_e2e.py --device-id-token '{new_device_id_token}'"
            )
        print()
        print("NOTE: session_region が正しい TFIT 暗号化 DH 公開鍵でないため、")
        print("      サーバー側の DH 計算は失敗している可能性があります。")
        print(
            "      Phase 2 (DH 鍵合意) を完了するには emulate_tfit.py の session_region 導出が必要。"
        )
    else:
        print("STATUS: key_response_data が不完全 — 鍵交換未完了")
        raw_top = parsed.get("raw", {})
        print(
            f"  raw top-level keys: {sorted(raw_top.keys()) if isinstance(raw_top, dict) else 'N/A'}"
        )

    _print_request_summary(cbor_message, esn, apphmac, devicetoken)


def _print_request_summary(
    cbor_message: bytes,
    esn: str,
    apphmac: bytes,
    devicetoken: bytes,
) -> None:
    """送信したリクエストの概要を表示する."""
    print()
    print("--- 送信リクエスト概要 ---")
    print(f"  CBOR size: {len(cbor_message)} bytes")
    print(f"  ESN:       {esn}")
    print(
        f"  apphmac:   {apphmac[:8].hex() if apphmac else '(empty)'} ({len(apphmac)}B)"
    )
    print(
        f"  devicetoken: {devicetoken[:8].hex() if devicetoken else '(empty)'} ({len(devicetoken)}B)"
    )


# ---------------------------------------------------------------------------
# エントリーポイント
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="iOS MSL appboot End-to-End テスト",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--esn",
        default=TEST_ESN,
        help=f"PRV ESN (default: {TEST_ESN[:40]}...)",
    )
    parser.add_argument(
        "--device-id-token",
        default=None,
        help="継続セッション用 device_id_token (x-netflix-deviceidtoken ヘッダー値, Base64)",
    )
    parser.add_argument(
        "--devicetoken-hex",
        default=None,
        help="devicetoken の生バイト列 (hex)。--device-id-token と組み合わせて使用。",
    )
    parser.add_argument(
        "--proxy",
        default=DEFAULT_PROXY,
        help=f"プロキシ URL (default: {DEFAULT_PROXY})",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="プロキシを使用しない (直接接続)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP タイムアウト秒数 (default: 30)",
    )

    args = parser.parse_args()

    proxy_url = None if args.no_proxy else args.proxy

    devicetoken_bytes: bytes | None = None
    if args.devicetoken_hex:
        devicetoken_bytes = bytes.fromhex(args.devicetoken_hex)

    # urllib3 の SSL 警告を抑制
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    run_e2e_test(
        esn=args.esn,
        device_id_token=args.device_id_token,
        devicetoken_bytes=devicetoken_bytes,
        proxy_url=proxy_url,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
