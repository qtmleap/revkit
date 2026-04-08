# Netflix iOS MSL 暗号化フロー解析

キャプチャ日: 2026-04-06
Tweak: NetflixSSLBypass (EVP_CipherInit_ex / EVP_CipherUpdate フック)

## 発見事項

### EVP_Cipher で処理されているもの

Tweak の EVP フックで 264 回の `EVP_CipherInit` と 457 回の `EVP_CipherUpdate` をキャプチャした結果、
**EVP_Cipher は MSL ペイロードの暗号化/復号には使われていない**ことが判明。

EVP_Cipher で処理されているのは以下の3種類のみ:

1. **AES セルフテスト (KAT)**: `key=000102030405060708090a0b0c0d0e0f`, `enc=encrypt`, 48 bytes × 40 回
2. **TFIT ホワイトボックス鍵導出チェーン**: 100以上のユニークな鍵で各 48 bytes を暗号化。出力が次の鍵になるチェーン構造
3. **AES-ECB テスト**: `key=fe70779b...`, 16 bytes × 60 回 (繰り返しパターン)

いずれも **固定サイズ (16 or 48 bytes)** のデータのみ。数百〜数千バイトの MSL ペイロード暗号化は含まれない。

### MSL ペイロード暗号化の実体

Frida の既存キャプチャ (`raws/ios/20260404/capture.jsonl`) では `msl.aesCbcEncrypt` / `msl.aesCbcDecrypt` イベントが
486 / 772 回記録されている。これは MslClient.framework 内の C++ 関数:

```
netflix::msl::crypto::aesCbcEncryptDecrypt(EncryptOrDecrypt, vector<uint8_t>&, vector<uint8_t>&, vector<uint8_t>&, vector<uint8_t>&)
```

が呼ばれている。この関数は内部で `EVP_CipherInit_ex` → `EVP_CipherUpdate` → `EVP_CipherFinal_ex` を呼ぶが、
**ElleKit の MSHookFunction ではこのオフセットのフックに失敗している** (Frida の Interceptor は成功する)。

## 暗号鍵のフロー

```mermaid
graph TD
    subgraph "Phase 0: 起動時 (dylib load)"
        A[AES Self-Test<br/>KAT: key=000102...0f] -->|48B × 40回| A1[Known Answer Test 結果検証]
    end

    subgraph "Phase 1: TFIT ホワイトボックス鍵導出"
        B[TFIT Seed Key<br/>Irdeto whitebox AES-128-ECB] -->|ECB encrypt 48B| B1[Derived Key 1]
        B1 -->|output = next key| B2[Derived Key 2]
        B2 -->|output = next key| B3[...]
        B3 --> B4[Model Group Key<br/>MGK for ESN generation]
    end

    subgraph "Phase 2: appboot 鍵交換"
        C[DH KeyGen<br/>NFWebCrypto::dhKeyGen] --> C1[Client DH Public Key<br/>464 bytes → CBOR key 33.6]
        C1 -->|POST /appboot| C2[Server DH Response<br/>96 bytes ← CBOR key 33.6]
        C2 --> C3[DH Shared Secret<br/>dhDerive]
        C3 --> C4[HKDF]
        C4 --> C5[MSL Session Keys<br/>enc_key: AES-128<br/>hmac_key: SHA-256]
    end

    subgraph "Phase 3: MSL ペイロード暗号化"
        C5 -->|enc_key| D1["aesCbcEncrypt<br/>(MslClient C++)<br/>内部で EVP_CipherInit_ex<br/>→ EVP_CipherUpdate<br/>→ EVP_CipherFinal_ex"]
        D1 --> D2[暗号化済みペイロード<br/>CBOR key 33.ciphertext]
        D1 --> D3[appboot request payload]
        D1 --> D4[manifest request]
        D1 --> D5[pbo_license request]
        D1 --> D6[logblob request]
        D1 --> D7[graphql Cloud/NGP request]
    end

    subgraph "Phase 4: MSL ペイロード復号"
        C5 -->|enc_key| E1["aesCbcDecrypt<br/>(MslClient C++)"]
        E1 --> E2[appboot response payload]
        E1 --> E3[manifest response<br/>CDN URLs, codec info]
        E1 --> E4[pbo_license response<br/>FairPlay license]
        E1 --> E5[logblob response]
        E1 --> E6[graphql Cloud/NGP response]
    end

    subgraph "Phase 5: HMAC 検証"
        C5 -->|hmac_key| F1["signHmacSha256<br/>(MslClient C++)"]
        F1 --> F2[リクエスト署名]
        C5 -->|hmac_key| F3["verifyHmacSha256<br/>(MslClient C++)"]
        F3 --> F4[レスポンス検証]
    end

    style A fill:#ffa,stroke:#aa0
    style B fill:#ffa,stroke:#aa0
    style C5 fill:#f66,stroke:#900,color:#fff
    style D1 fill:#6af,stroke:#06a
    style E1 fill:#6af,stroke:#06a
```

## 鍵の取得元まとめ

| 鍵 | 取得元 | 用途 |
|----|--------|------|
| TFIT MGK seed | NFWebCrypto.framework にハードコード (per-device-type) | ESN 生成用 Model Group Key 導出 |
| DH 秘密鍵 | NFWebCrypto::dhKeyGen (ランタイム生成) | appboot 鍵交換 |
| kAppBootKey (RSA-4096) | NFWebCrypto.framework にハードコード | DH パラメータの暗号化 (サーバーへ送信) |
| kAppBootEccKey (ECDSA P-256) | NFWebCrypto.framework にハードコード | サーバーレスポンスの署名検証 |
| MSL enc_key (AES-128) | 初回: DH 共有秘密から導出 (方法未解明)。更新: HMAC-SHA256 KDF (解明済み) | MSL ペイロードの AES-128-CBC 暗号化/復号 |
| MSL hmac_key (SHA-256) | 初回: 同上。更新: HMAC-SHA256 KDF (解明済み) | MSL ペイロードの HMAC-SHA256 署名/検証 |
| PSK (16B) | DH 共有秘密から導出? TFIT チェーン出力? (未解明) | KDF 鍵更新のマスター鍵 |
| AES self-test key | 固定値 `000102...0f` | OpenSSL KAT (Known Answer Test) |

## 現状の制限

| アプローチ | 状態 | 問題 |
|-----------|------|------|
| Tweak EVP_Cipher フック | ✓ 動作 | TFIT/KAT のみキャプチャ。MSL ペイロードは見えない |
| Tweak MSHookFunction (オフセット) | ✗ コールバック未発火 | ElleKit が MslClient 内部コードのフックに失敗 |
| Frida Interceptor (attach) | ✓ 動作 | 起動後 attach のため appboot に間に合わない |
| Frida enumerateSymbols | ✓ 動作 | アドレス取得可能だが attach タイミングの問題 |

## 解決済み: KDF 鍵更新アルゴリズム (2026-04-08)

Tweak `AppbootKeyExtract` v39 の HMAC ストリーミングフックにより、
MSL セッション鍵更新の KDF が完全に解明された。

**アルゴリズム**: カスタム HMAC-SHA256 チェーン (標準 HKDF ではない)

```
new_enc_key  = HMAC-SHA256(HMAC-SHA256(PSK, enc_key), nonce)[:16]
new_sign_key = HMAC-SHA256(HMAC-SHA256(PSK, sign_key), nonce)
```

詳細: [msl_kdf_analysis.md](msl_kdf_analysis.md)
Python 実装: `src/netflix_msl/crypto.py` → `NetflixCrypto.kdf_renew()`

## 次のステップ

1. **PSK の由来特定** — `027617984f6227539a630b897c017d69` がどこから来るかを解明
   - Keychain クリア + 新規セッションでキャプチャ
   - TFIT ホワイトボックスチェーンとの関連調査
2. **初期鍵導出 (DH → 初回セッション鍵)** — `DH_compute_key`/`dhDerive` + 直後の HMAC チェーンをキャプチャ
3. **SSL Pinning バイパス** — Netflix ログインに必要。Frida ベースの手法を検討
