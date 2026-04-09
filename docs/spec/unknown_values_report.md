# Unknown Values Investigation Report

Date: 2026-04-09
Updated: 2026-04-09

appboot → MSL 認証の Python 実装に必要な全値の調査結果。
各値について **固定/可変**、**再利用可否**、**Python 再現可否** を明記する。

---

## 1. バイナリ固定値 (アプリバージョン単位で不変)

これらはすべて Netflix iOS バイナリにハードコードされており、アプリが更新されない限り不変。
Python 定数として埋め込み済みで、追加調査は不要。

### kAppBootKey — RSA-4096 SPKI/DER (550B)

| 項目 | 値 |
|------|-----|
| バイナリ | NFWebCrypto.framework |
| オフセット | `0x0020cd31` (`__TEXT.__cstring`) |
| 格納形式 | Base64 エンコード (736 chars) |
| 用途 | appboot レスポンスの RSASSA-PKCS1-v1_5 署名検証 |
| ハンドル | `"ABKP"` |
| Python 定数 | `constants.IOS_APPBOOT_RSA_KEY_DER` |
| **固定/可変** | **固定** — バイナリ埋め込み |
| **再利用可否** | **可** — アプリバージョンが同じなら不変 |
| **Python 再現** | **可** — 定数として利用 |

### kAppBootEccKey — ECDSA P-256 SPKI/DER (91B)

| 項目 | 値 |
|------|-----|
| バイナリ | NFWebCrypto.framework |
| オフセット | `0x0020d10c` (`__TEXT.__cstring`) |
| 格納形式 | Base64 エンコード (124 chars) |
| 用途 | appboot レスポンスの ECDSA 署名検証 |
| ハンドル | `"ABECCKP"` |
| Python 定数 | `constants.IOS_APPBOOT_ECC_KEY_DER` |
| **固定/可変** | **固定** — バイナリ埋め込み |
| **再利用可否** | **可** |
| **Python 再現** | **可** |

### kSharkBootKey (prod) — ECDSA P-256 SPKI/DER (91B)

| 項目 | 値 |
|------|-----|
| バイナリ | NFWebCrypto.framework |
| オフセット | `0x0020d08f` |
| 用途 | Shark boot 署名検証 |
| Python 定数 | `constants.IOS_SHARKBOOT_KEY_DER` |
| **固定/可変** | **固定** |
| **再利用可否** | **可** |
| **Python 再現** | **可** |

### DH Prime p — 1024-bit (128B)

| 項目 | 値 |
|------|-----|
| バイナリ | **MslClient.framework** (NFWebCrypto ではない) |
| オフセット | `0x001265a0` (`__TEXT.__const`) |
| ロード関数 | `IosAdhKeyx::dhKeyGen` @ vaddr `0x00079d20` |
| Generator g | `5` (vaddr `0x00079d98`) |
| Python 定数 | `constants.IOS_DH_P`, `constants.IOS_DH_G` |
| **固定/可変** | **固定** — バイナリ埋め込み |
| **再利用可否** | **可** |
| **Python 再現** | **可** — `cryptography` ライブラリで DH 計算 |

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

### PSK / KDF Nonce

| 値 | オフセット | サイズ |
|----|-----------|--------|
| PSK: `027617984f6227539a630b897c017d69` | NFWebCrypto @ `0x1ac8f5` | 16B |
| Nonce: `809f82a7addf548d3ea9dd067ff9bb91` | NFWebCrypto @ `0x1ac905` | 16B |

| **固定/可変** | **固定** — バイナリ埋め込み |
|--------------|--------------------------|
| **再利用可否** | **可** |
| **Python 再現** | **可** — `constants.IOS_KDF_PSK` / `IOS_KDF_NONCE` |

### Device Header (128B CBOR)

| 項目 | 値 |
|------|-----|
| 用途 | key 33.6 scheme_data の先頭 128 バイト |
| Python 定数 | `constants.IOS_KEY336_DEVICE_HEADER` |
| **固定/可変** | **固定** — iPhone デバイスタイプ共通 (165/180 サンプルで一致) |
| **再利用可否** | **可** |
| **Python 再現** | **可** |

### AppID

| 項目 | 値 |
|------|-----|
| 値 | `a2becfec-b286-535c-b884-903a384caee6` |
| **固定/可変** | **固定の可能性が高い** — 全キャプチャで同一値。UUIDv5 形式 (deterministic) |
| **再利用可否** | **可** (要確認: アプリバージョン更新で変わる可能性あり) |
| **Python 再現** | **可** — 定数として埋め込み |
| **追加調査** | 複数バージョンで値が同一か確認 |

### AppKeyVersion

| 項目 | 値 |
|------|-----|
| 値 | `1` |
| **固定/可変** | **固定の可能性が高い** — 全キャプチャで同一値 |
| **再利用可否** | **可** |
| **Python 再現** | **可** |
| **追加調査** | サーバー側で拒否される場合はバージョン依存の可能性あり |

---

## 2. デバイス固有値 (デバイス依存だが再現可能)

### Full ESN

| 項目 | 値 |
|------|-----|
| キャプチャ値 | `NFAPPL-02-IPHONE9=1-AD0455EF27D3A7B8F0872932FD9837874AF3E6F90157195BD22A8063FEB0B79E` |
| 構造 | `NFAPPL-02-{MODEL}={VARIANT}-{64HEXCHARS}` |
| **固定/可変** | **デバイス固有・固定** — 同一デバイスでは不変。デバイスが変われば変わる |
| **再利用可否** | **可** — 同一デバイスに対しては永続的に有効 |
| **Python 再現** | **不可** — ESN 生成ロジックは未解明。キャプチャ値をパラメータとして渡す |
| **追加調査** | ESN suffix (64 hex chars) の導出元。Keychain/デバイス識別子から生成？ |

### MGK (Model Group Key): enc_key_0 + sign_key_0

| 項目 | 値 |
|------|-----|
| enc_key_0 | `0817065e29e6d1c8668473af9e13b3c2` (16B) |
| sign_key_0 | `91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1` (32B) |
| 導出元 | `SHA384(ESN)` → 3× TFIT-WB-AES-128-ECB → enc_key_0 (16B) + sign_key_0 (32B) |
| **固定/可変** | **ESN 依存・固定** — 同一 ESN からは常に同一の MGK が導出される |
| **再利用可否** | **可** — ESN が同じなら毎回同じ値 |
| **Python 再現** | **可** — `tools/emulate_tfit.py` (Unicorn ARM64 エミュレーション) |
| **追加調査** | 不要 — Phase 3 KDF のライブ HMAC ログと Python 実装の出力が完全一致を確認済み |

---

## 3. ランタイム可変値 (要調査)

### devicetoken (216B, protobuf)

| 項目 | 値 |
|------|-----|
| キャプチャ hex | `0608a1b7ebdc0312bc01...0a0d00ef` (216B) |
| 取得元 | Nbp.framework → NRM (Netflix Registration Management) サービスへ HTTP リクエスト |
| 取得関数 | `-[MslRegistration getDeviceTokensWithCallback:]` @ Nbp `0x0005d5c0` |
| protobuf 構造 | field 1 (varint): ID, field 2 (188B): opaque payload, field 4: nested proto |
| **固定/可変** | **可変** — NRM サービスから取得。241 セッション中 41 種のユニーク値を観測 |
| **再利用可否** | **不明** — 有効期限がある可能性。同一セッション内では安定 |
| **Python 再現** | **不可** — NRM サービスとの通信プロトコルが未解明 |
| **追加調査が必要** | ★ 有効期限の有無。一度取得した値がどのくらい再利用可能か。NRM API の仕様 |

### apphmac (32B) → **有力候補特定: HKDF(MGK, PSK, Nonce)**

| 項目 | 値 |
|------|-----|
| **固定/可変** | **ESN 依存・決定的** — MGK (ESN + TFIT 依存) から決定的に導出 |
| **再利用可否** | **可** — 同一 ESN なら常に同一値 |
| **Python 再現** | **可** (候補) — `HMAC-SHA256(HMAC-SHA256(MGK, PSK), Nonce)` |
| **追加調査** | IosMGKAuthData コンストラクタで直接照合して最終確認 |

**2026-04-09 発見: HKDF フックで導出式を特定 + コンストラクタフック成功**

### HKDF 入力 (キャプチャ済み)

`AppleWebCrypto::HKDF` (NFWebCrypto @ offset `0x11900`) をフックし、以下の入力をキャプチャ:

```
HKDF(
  key  = MGK (48B: enc_key_0 || sign_key_0)
  ikm  = PSK (16B: 027617984f6227539a630b897c017d69)
  info = Nonce (16B: 809f82a7addf548d3ea9dd067ff9bb91)
)
```

内部処理 (静的解析 + ランタイム確認):
```
prk = HMAC-SHA256(key=MGK, data=PSK)     // Extract
okm = HMAC-SHA256(key=prk, data=Nonce)   // Expand
```

Python 計算結果:
```
prk = 6626cf896cb699d61fb42d242fe52f404d0867c379da777e3538bae7f35f3953
okm = 4c142e4b82b3ad21e2dcdbcc007c27a4787adc0568959080b004b5daa5a7385a
```

### FpsMgkAppIdAuthData コンストラクタ (キャプチャ済み)

**重要:** RE で `apphmac` と名付けられていた x5 引数は実際には **devicetoken** (216B protobuf)。

```
FpsMgkAppIdAuthData(
  x1: mgkid       = "NFAPPL-02-IPHONE9=1-"          (ESN prefix)
  x2: devtype     = "NFAPPL-02-IPHONE9=1-AD0455..."  (Full ESN)
  x3: appid       = "a2becfec-b286-535c-b884-903a384caee6"
  w4: appkeyversion = 1
  x5: devicetoken = 216B protobuf (base64 encoded)   ← RE では apphmac と誤認
  x6: webCrypto   = AppleWebCrypto*
  x7: authGen     = SynchronizedCdmAuthGeneration*
)
```

**結論:**
- apphmac はコンストラクタ引数ではなく、`getAuthData()` (offset 0x284bc) 内部で
  AppleWebCrypto を通じて計算される
- HKDF(MGK, PSK, Nonce) = `4c142e4b...` がこの内部計算に該当する可能性が高い
- ただし `getAuthData()` 内部の CBOR シリアライズを直接フックするまで最終確認は完了していない

**確認手段:**
1. `getAuthData()` (MslClient offset 0x284bc) をフックして CBOR 出力内の apphmac フィールドを抽出
2. appboot リクエスト CBOR をプロキシでキャプチャし apphmac フィールドを照合

### ~~appboot sign key (32B)~~ → **解決済み: Keychain キャッシュ**

| 項目 | 値 |
|------|-----|
| キャプチャ値 | `38b2030dd55e3367290213ca0d16ee079524ccd24fb7221a52145fb6de016fd8` |
| 用途 | appboot リクエスト全体 (8549B) の HMAC-SHA256 署名 |
| **固定/可変** | **~~可変 (導出値)~~** → **前回セッションの Phase 2 sign key (Keychain キャッシュ)** |
| **再利用可否** | 初回 appboot には不要 |
| **Python 再現** | **不要** — フレッシュ appboot では sign_key_1 で署名する |
| **追加調査** | **不要** |

**2026-04-09 解決:**
Netflix アプリの全データ (Library/, Documents/, tmp/) を削除してクリーンな初回起動を
キャプチャした結果、`38b2030d` も `8887ddf1` も出現しなかった。
これらは**前回の appboot で Phase 2 KDF から導出されたセッション鍵が iOS Keychain に
キャッシュされていた**値に過ぎないことが確定。

フレッシュ appboot (初回起動 / キャッシュなし) では:
1. Phase 3 KDF → sign_key_1 で appboot リクエストに署名
2. DH 鍵交換 → Phase 2 KDF → 新セッション鍵を導出
3. 新セッション鍵を Keychain にキャッシュ
4. 以降のリクエストはキャッシュされたセッション鍵で署名

---

## 4. appboot blob の構造 (8549B)

Tweak (`NetflixEntityAuth`) で HMAC 署名対象として 8549B の完全な blob をキャプチャ。

```
[0:20]    ESN prefix (ASCII: "NFAPPL-02-IPHONE9=1-")
[20]      NULL terminator
[21:28]   Header/flags (00 00 01 00 00 00 00)
[28:8210] Encrypted body (8182B — 暗号化された entity_auth + key_exchange)
[8210:8212] Length prefix (73 15)
[8212:8296] Full ESN (ASCII, 84 chars)
[8296:8332] AppID UUID (ASCII, 36 chars)
[8332]    AppKeyVersion (ASCII "1")
[8333:8549] DeviceToken protobuf (216B)
```

暗号化本体 (8182B) には entity_auth_data の apphmac、key_exchange の DH 公開鍵、
key 33.6 scheme_data 等が含まれるが、暗号化されているため直接読めない。

保存先: `raws/ios/captures/appboot_blob.bin`

---

## 5. HMAC 署名チェーン (ライブキャプチャ)

appboot 時の HMAC 呼び出し順序と使用鍵:

| 順序 | 鍵 | データ | 用途 |
|------|-----|--------|------|
| 1-6 | PSK / 前段出力 / Nonce | MGK (48B) の各パーツ | Phase 3 KDF (6 段チェーン) |
| 7-9 | sign_key_1 (`d45443fa...`) | 76B / 92B / 76B チャンク | key exchange データ署名 |
| 10 | session sign key (`8887ddf1...`) | 389B CBOR | MSL ヘッダー署名 |
| 11 | **appboot sign key (`38b2030d...`)** | **8549B appboot blob** | **appboot リクエスト署名** |
| 12+ | session sign key (`8887ddf1...`) | CBOR メッセージ各種 | 通常の MSL 通信 |

- Phase 3 KDF (順序 1-6) は Python 実装と完全一致を確認済み
- session sign key (`8887ddf1...`) は Phase 2 KDF (DH 共有秘密) から導出されたもの
- appboot sign key (`38b2030d...`) の導出元が最大の未解明事項

---

## 6. 全値の分類まとめ

### Python 単体で再現可能 (追加調査不要)

| 値 | 固定/可変 | Python 定数/関数 |
|----|----------|-----------------|
| kAppBootKey (RSA-4096) | バイナリ固定 | `constants.IOS_APPBOOT_RSA_KEY_DER` |
| kAppBootEccKey (P-256) | バイナリ固定 | `constants.IOS_APPBOOT_ECC_KEY_DER` |
| kSharkBootKey (P-256) | バイナリ固定 | `constants.IOS_SHARKBOOT_KEY_DER` |
| DH prime p / g | バイナリ固定 | `constants.IOS_DH_P` / `IOS_DH_G` |
| PSK / Nonce | バイナリ固定 | `constants.IOS_KDF_PSK` / `IOS_KDF_NONCE` |
| Device header (128B) | バイナリ固定 | `constants.IOS_KEY336_DEVICE_HEADER` |
| TFIT tables | バイナリ固定 | `tools/emulate_tfit.py` |
| MGK (enc_key_0 + sign_key_0) | ESN 依存・決定的 | `emulate_tfit.py` で導出 |
| Phase 3 KDF 全出力 | MGK 依存・決定的 | `crypto.kdf_renew()` |
| DH 鍵生成/共有秘密 | 毎回ランダム | `crypto.generate_dh_keypair()` |
| Phase 2 KDF 全出力 | DH 依存・決定的 | `crypto.derive_initial_session_keys()` |
| AppID | 固定の可能性高 | 定数として埋め込み |
| AppKeyVersion | 固定の可能性高 | 定数として埋め込み |

### デバイスから1回取得すれば再利用可能

| 値 | 固定/可変 | 取得方法 | 再利用条件 |
|----|----------|---------|-----------|
| Full ESN | デバイス固有・固定 | Tweak/Frida でキャプチャ | 同一デバイスなら永続 |

### 要追加調査 (Python 実装のブロッカー)

| 値 | 固定/可変 | 再利用 | 状態 | 備考 |
|----|----------|--------|------|------|
| **apphmac** (32B) | **毎リクエスト可変** | 不可 | **未解明** | 243 リクエスト中 67 ユニーク値。ランダム/ノンス依存 |
| **devicetoken** (216B) | 可変 | 不明 | **キャプチャ済み** | 有効期限は未確認。当面はキャプチャ値を渡す |
| ~~**appboot sign key**~~ | — | — | **解決済み** | Keychain キャッシュ。初回は sign_key_1 で署名 |

> **結論 (2026-04-09 最終更新):**
>
> **apphmac は毎リクエスト可変 (67/243 ユニーク値)。**
> HKDF(MGK, PSK, Nonce) の出力ではないことが CBOR 直接照合で確定。
> ランダムノンスまたはタイムスタンプに依存する値であり、
> 既知の固定定数からは Python で再現できない。
>
> **ただし、entity_auth_data の CBOR 構造は完全に判明した:**
> ```
> key 35: {
>   "apphmac": bytes(32B),       ← 毎リクエスト可変 (導出元不明)
>   "appid": "a2becfec-...",     ← 固定
>   "appkeyversion": 1,          ← 固定
>   "devicetoken": bytes(216B),  ← セッション可変
>   3: "NFAPPL-02-IPHONE9=1-..." ← Full ESN (固定)
> }
> key 30: "MGK_APPID"            ← entity auth scheme 名
> ```
>
> appboot sign key: フレッシュ appboot では sign_key_1 (Phase 3 KDF) で署名
> devicetoken: キャプチャ値をパラメータとして渡す
