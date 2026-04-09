# Unknown Values Investigation Report

Date: 2026-04-09

appboot → MSL 認証の Python 実装に必要な未知の値の調査結果。

---

## 1. 抽出済み (バイナリにハードコード)

### kAppBootKey — RSA-4096 SPKI/DER (550B)

| 項目 | 値 |
|------|-----|
| バイナリ | NFWebCrypto.framework |
| オフセット | `0x0020cd31` (`__TEXT.__cstring`) |
| 格納形式 | Base64 エンコード (736 chars) |
| 用途 | appboot レスポンスの RSASSA-PKCS1-v1_5 署名検証 |
| ハンドル | `"ABKP"` |
| Python 定数 | `constants.IOS_APPBOOT_RSA_KEY_DER` |

### kAppBootEccKey — ECDSA P-256 SPKI/DER (91B)

| 項目 | 値 |
|------|-----|
| バイナリ | NFWebCrypto.framework |
| オフセット | `0x0020d10c` (`__TEXT.__cstring`) |
| 格納形式 | Base64 エンコード (124 chars) |
| 用途 | appboot レスポンスの ECDSA 署名検証 |
| ハンドル | `"ABECCKP"` |
| Python 定数 | `constants.IOS_APPBOOT_ECC_KEY_DER` |

### kSharkBootKey (prod) — ECDSA P-256 SPKI/DER (91B)

| 項目 | 値 |
|------|-----|
| バイナリ | NFWebCrypto.framework |
| オフセット | `0x0020d08f` |
| 用途 | Shark boot 署名検証 |
| Python 定数 | `constants.IOS_SHARKBOOT_KEY_DER` |

### DH Prime p — 1024-bit (128B)

| 項目 | 値 |
|------|-----|
| バイナリ | **MslClient.framework** (NFWebCrypto ではない) |
| オフセット | `0x001265a0` (`__TEXT.__const`) |
| ロード関数 | `IosAdhKeyx::dhKeyGen` @ vaddr `0x00079d20` |
| Generator g | `5` (vaddr `0x00079d98`) |
| Python 定数 | `constants.IOS_DH_P`, `constants.IOS_DH_G` |

```
9694e9d8 d93a5ac7 4c509b4b bce85e92
132cd19c ce477d1a 7e47d527 d9ec2915
15f0b8b3 e1eaed50 06e1b1b9 1ea25b91
a01b10e2 e834b8d6 60b2e321 ad644ce1
a83b328d 9014ee7e 16f1e44f fe89579a
c3ee47d6 68b6b766 87c2fe90 a35b5e60
28fd04ef ea882373 ecf60ba2 f637e4cd
aa1b6089 d6c0b561 a8e520e7 96de27df
```

### PSK / KDF Nonce (既知、再確認)

| 値 | オフセット | サイズ |
|----|-----------|--------|
| PSK: `027617984f6227539a630b897c017d69` | NFWebCrypto @ `0x1ac8f5` | 16B |
| Nonce: `809f82a7addf548d3ea9dd067ff9bb91` | NFWebCrypto @ `0x1ac905` | 16B |

---

## 2. ランタイム生成 (ハードコードされていない)

### apphmac (32B, HMAC-SHA256)

**結論: バイナリに固定鍵なし。ランタイム導出。**

NFWebCrypto の全 6 HMAC call site を静的解析した結果、すべてランタイム導出の鍵を使用:

| Call site | 関数 | 鍵ソース |
|-----------|------|----------|
| `0x000101a0` | `nflxDhDerive` | `SHA384(DH private key)` (48B) |
| `0x0000e640` | `hmacSign` | `AppleNativeKey::getBytes()` |
| `0x00011990` | `HKDF-Extract` | caller 引数 |
| `0x000119b8` | `HKDF-Expand` | 前段の PRK |
| `0x0001aa4c` | HMAC wrapper (SHA256) | caller 引数 |
| `0x0001aac8` | HMAC wrapper (SHA384) | caller 引数 |

**キャプチャ方法**: `hook_entityauth_capture.js` で HMAC 出力 32B をフィルタ。入力 216B (devicetoken サイズ) の HMAC コールが `apphmac = HMAC(PSK, devicetoken)` の有力候補。

### devicetoken (216B, protobuf)

**結論: NRM (Netflix Registration Management) サービスからランタイム取得。**

- **Nbp.framework**: `-[MslRegistration getDeviceTokensWithCallback:]` @ `0x0005d5c0`
  → `getNRMCookieWithESN:callback:` → NRM サービスへ HTTP リクエスト
  → レスポンスの `tokens` プロパティ → `initWithGUID:tokens:` で credentials 構築
- **MslClient.framework**: `IosMGKAuthenticationData` コンストラクタ @ `0x0000d45c` の第5引数
- protobuf 構造: field 2 = 188B opaque payload, field 3 = type enum (6), field 4 = 14B nested proto
- セッション間で安定 (241 セッション中 41 種のユニーク値)

**キャプチャ方法**: `hook_entityauth_capture.js` で Nbp シンボルをフック、または `IosMGKAuthenticationData` コンストラクタ引数をキャプチャ。

### device_key_data (~6,576B)

**結論: ランタイム組立の CBOR 構造体。単一の静的 blob ではない。**

`entity_auth_data` は以下の CBOR フィールドから組み立てられる:

**IosMGKAuthenticationData** (@ `0x000103bc`):

| フィールド | オフセット | 内容 |
|-----------|-----------|------|
| `identity` | +0x98 | ESN 文字列 |
| `appid` | +0xb0 | アプリケーション ID |
| `appkeyversion` | +0xc8 | 整数 |
| `apphmac` | +0xd0 | Base64 HMAC |
| `devicetoken` | +0xe8 | NRM トークン |

**FpsMgkAppIdAuthData** (@ `0x00029bec`): `devtype`, `mgkid`, `keyrequest`, `appid`, `appkeyversion`, `apphmac`, `devicetoken`

6,576B は TFIT-WB-AES 暗号化された MGK 鍵素材 (`mgkid`/`keyrequest`) を含む CBOR エンコーディング全体のサイズ。

**キャプチャ方法**: `hook_entityauth_capture.js` で NSData/sqlite フック、または appboot リクエスト全体をバイナリキャプチャして CBOR デコード。

---

## 3. まとめ

### Python 実装で必要な値の状態

| 値 | 状態 | Python で再現可能か |
|----|------|-------------------|
| kAppBootKey (RSA-4096) | **抽出済み** | Yes — `constants.IOS_APPBOOT_RSA_KEY_DER` |
| kAppBootEccKey (P-256) | **抽出済み** | Yes — `constants.IOS_APPBOOT_ECC_KEY_DER` |
| DH prime p | **抽出済み** | Yes — `constants.IOS_DH_P` |
| DH generator g | **抽出済み** | Yes — `constants.IOS_DH_G = 5` |
| PSK / Nonce | **抽出済み** | Yes — `constants.IOS_KDF_PSK` / `IOS_KDF_NONCE` |
| Device header (128B) | **抽出済み** | Yes — `constants.IOS_KEY336_DEVICE_HEADER` |
| TFIT tables | **抽出済み** | Yes — `emulate_tfit.py` で Unicorn エミュレーション |
| apphmac | **要ランタイムキャプチャ** | No — Frida で鍵と入力を特定後、Python 再現の可能性あり |
| devicetoken | **要ランタイムキャプチャ** | No — NRM サービス応答。キャプチャ値をパラメータとして渡す |
| device_key_data | **要ランタイムキャプチャ** | 部分的 — CBOR 構造は既知、MGK 部分は TFIT で再現可能 |
