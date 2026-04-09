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

### apphmac (32B, HMAC-SHA256)

| 項目 | 値 |
|------|-----|
| **固定/可変** | **毎回可変** — appboot リクエストごとに異なる |
| **再利用可否** | **不可** |
| **Python 再現** | **不可** — 導出ロジック (鍵 + 入力) が未解明 |
| **追加調査が必要** | ★★ 最大のブロッカー。以下を解明する必要がある: |

**静的解析の結果:**
NFWebCrypto の全 6 HMAC call site を静的解析した結果、すべてランタイム導出の鍵を使用。
バイナリに固定の HMAC 鍵は存在しない。

| Call site | 関数 | 鍵ソース |
|-----------|------|----------|
| `0x000101a0` | `nflxDhDerive` | `SHA384(DH private key)` (48B) |
| `0x0000e640` | `hmacSign` | `AppleNativeKey::getBytes()` |
| `0x00011990` | `HKDF-Extract` | caller 引数 |
| `0x000119b8` | `HKDF-Expand` | 前段の PRK |
| `0x0001aa4c` | HMAC wrapper (SHA256) | caller 引数 |
| `0x0001aac8` | HMAC wrapper (SHA384) | caller 引数 |

**Tweak キャプチャの結果:**
IosMGKAuthData コンストラクタ (MslClient @ base+0xd45c) が発火しなかった。
apphmac は appboot blob (8549B) の暗号化された本体部分に埋め込まれており、
HMAC フックからは個別に特定できなかった。

**調査方針:**
1. IosMGKAuthData コンストラクタのオフセットが正しいか再検証 (バイナリバージョン差異)
2. `FpsMgkAppIdAuthData::getAuthData()` @ `0x000284bc` をフックして apphmac を直接キャプチャ
3. apphmac が `HMAC(PSK, devicetoken)` かどうかをテスト (Frida で入力 216B の HMAC コールを監視)

### appboot sign key (32B)

| 項目 | 値 |
|------|-----|
| キャプチャ値 | `38b2030dd55e3367290213ca0d16ee079524ccd24fb7221a52145fb6de016fd8` |
| 用途 | appboot リクエスト全体 (8549B) の HMAC-SHA256 署名 |
| **固定/可変** | **可変 (導出値)** — セッションごとに異なる可能性 |
| **再利用可否** | **不可** — 導出元が不明なため再現できない |
| **Python 再現** | **不可** — 導出ロジック未解明 |
| **追加調査が必要** | ★★ apphmac と並ぶブロッカー |

**既知の事実:**
- Phase 3 KDF の出力 (sign_key_1 = `d45443fa...`) ではない
- Phase 2 KDF の出力 (session sign key = `8887ddf1...`) でもない
- `SHA256(sign_key_1)` でもない
- キャッシュクリア後の再起動でも同じ値が出現 → ESN/MGK から決定的に導出されている可能性
- Phase 2 (DH) の前に使用されている → DH 共有秘密には依存しない

**調査方針:**
1. Phase 3 KDF の中間値やバリエーションを網羅的にテスト
2. `HMAC(sign_key_1, ESN)`, `HMAC(session_bind, ESN)` 等の候補を Python で計算し照合
3. MslClient.framework の appboot リクエスト組立関数をデコンパイルし、署名鍵の取得パスを追跡

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

| 値 | 固定/可変 | 再利用 | 調査優先度 | 調査内容 |
|----|----------|--------|-----------|---------|
| **apphmac** (32B) | 毎回可変 | 不可 | ★★ 最高 | 導出ロジック (鍵 + 入力) の解明 |
| **appboot sign key** (32B) | 可変 (導出値) | 不可 | ★★ 最高 | 導出元の特定。Phase 3 中間値？ |
| **devicetoken** (216B) | 可変 | 不明 | ★ 高 | 有効期限。NRM API 仕様。再利用可能期間 |

> **結論**: apphmac と appboot sign key の導出ロジックを解明しない限り、
> Python 単体で appboot リクエストを構築・署名することは不可能。
> これが現時点での最大のブロッカーである。
