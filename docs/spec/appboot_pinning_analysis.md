# appboot.netflix.com SSL Pinning 解析

## 概要

Netflix iOS アプリ (Argo v15.48.1) は `appboot.netflix.com` に対して
**二重の SSL ピンニング + 動的 trust store 更新**を実装している。

## ピンニングアーキテクチャ

```
NSURLSession TLS Handshake
    │
    ├── Layer 1: NflxTrustStore (Nbp.framework)
    │   └── OpenSSL X509_STORE による独自 CA 検証
    │       evaluateTrust:error: → OpenSSL で証明書チェーン検証
    │
    ├── Layer 2: NflxPinnedCertEvaluator (Nbp.framework)
    │   └── ホスト別の証明書ピンニング
    │       hasPinnedCertForHost: → ホスト名で辞書引き
    │       evaluatePinnedCertificate:forHost: → ピン照合
    │
    └── Layer 3: IosMslClient (MslClient.framework)
        └── appboot レスポンスから ssltruststore を受信して
            NFURLSession の証明書を動的更新
            shouldUseSSLTrustStore → サーバー側フラグで制御
```

## 関連フレームワーク

### Nbp.framework (6.8 MB)

| クラス | 役割 |
|-------|------|
| `NflxTrustStore` | OpenSSL ベースの独自 CA 検証。PEM 文字列から X509_STORE を構築 |
| `NflxPinnedCertEvaluator` | ホスト別ピンニング。`_pinnedCerts` (NSDictionary) にホスト→証明書マッピング |
| `NfNrdController` | `trustStoreFromString:` で trust store 初期化 |

### MslClient.framework (1.4 MB)

| プロパティ/メソッド | 型 | 用途 |
|---|---|---|
| `appbooturl` | config key | appboot エンドポイント URL |
| `sslTrustStore` | NSString | SSL trust store データ (サーバー配信) |
| `shouldUseSSLTrustStore` | BOOL | SSL trust store 使用フラグ |
| `useAppbootSSLTrustStore` | config key | サーバー側フィーチャーフラグ |
| `updateNFURLSessionCerts:` | method | NFURLSession に証明書を適用 |
| `_handleAppbootResponse:error:timeoutMS:` | method | appboot レスポンス処理 |

### NFWebCrypto.framework (2.3 MB)

| 鍵 | 仕様 | 用途 |
|----|------|------|
| `kAppBootKey` | RSA-4096 公開鍵 (SPKI/DER), Algorithm=RSASSA-PKCS1-v1_5, usage=VERIFY | サーバー応答の RSA 署名検証 (handle: "ABKP") |
| `kAppBootEccKey` | ECDSA P-256 公開鍵 (SPKI/DER), Algorithm=ECDSA, usage=VERIFY | サーバー応答の ECDSA 署名検証 (handle: "ABECCKP") |
| `kSharkBootKey` | ECDSA P-256 公開鍵 | Shark boot 署名検証 (prod) |
| `kSharkBootKey_Test` | ECDSA P-256 公開鍵 | Shark boot 署名検証 (test/staging) |

追加: Irdeto TFIT ホワイトボックス AES-128 (ESN 生成用 Model Group Key)

## appboot URL 一覧

| 環境 | URL |
|------|-----|
| prod | `https://appboot.netflix.com/appboot` |
| staging | `https://appboot-staging.netflix.com/appboot` |
| test | `https://appboot.test.netflix.net/appboot` |

## バイパス方法

`packages/frida/hook_appboot_bypass.js` で以下をフック:

1. `NflxTrustStore.evaluateTrust:error:` → 常に YES
2. `NflxPinnedCertEvaluator.hasPinnedCertForHost:` → 常に NO
3. `IosMslClient.shouldUseSSLTrustStore` → 常に NO
4. `NFURLSession.setTrustStore:` / `setPinnedCertificateEvaluator:` → NULL 化

## MSL 鍵交換フロー (確定: 署名検証モデル)

**重要: kAppBootKey は暗号化ではなく署名検証に使用される。**

静的解析の根拠 (`tools/re/find_appboot_key_usage.py`):
- `importKey()` の呼び出し引数: `usage=8` (VERIFY), `Algorithm=5` (RSASSA-PKCS1-v1_5)
- OpenSSL 内部では `d2i_RSA_PUBKEY()` → `RSA_verify()` のパス
- `RSA_public_encrypt()` / `EVP_PKEY_encrypt()` は Frida フックで未検出 (確認済み)

1. クライアントが DH 鍵ペア生成 (`dhKeyGen`)
2. DH 公開値をサーバーへ送信 (平文、RSA 暗号化なし)
3. サーバーが DH 公開値 + 署名を返送
4. クライアントが `kAppBootKey` (RSA-4096, RSASSA-PKCS1-v1_5) または
   `kAppBootEccKey` (ECDSA P-256) でサーバー応答の署名を検証
5. DH 共有シークレット計算
6. `HKDF` でセッション鍵導出
7. 以降の通信は AES-GCM/CBC で暗号化
