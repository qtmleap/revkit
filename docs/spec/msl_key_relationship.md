# Netflix iOS MSL 鍵の関係図

作成日: 2026-04-08

---

## 1. 鍵の全体関係

```mermaid
graph TD
    subgraph "NFWebCrypto.framework"
        PSK["PSK (128-bit)"]
        NONCE_HARD["nonce (128-bit)"]
        DH_P["DH p (1024-bit)"]
        DH_G["DH g = 5"]
        RSA_BOOT["kAppBootKey (RSA-4096)"]
        ECC_BOOT["kAppBootEccKey (ECDSA P-256)"]
    end

    subgraph "Phase 1: appboot 鍵交換"
        DH_P --> DH_GEN["DH 鍵ペア生成"]
        DH_G --> DH_GEN
        DH_GEN --> DH_PUB["クライアント DH 公開鍵"]
        RSA_BOOT -->|暗号化| DH_REQ["appboot リクエスト"]
        DH_PUB --> DH_REQ
        DH_REQ -->|POST /appboot| SERVER["Netflix サーバー"]
        SERVER --> DH_RESP["appboot レスポンス (key 33)"]
        ECC_BOOT -->|署名検証| DH_RESP
    end

    subgraph "Phase 2: 初期セッション鍵導出 (未解明)"
        DH_RESP --> KEY336["key 33.6 (768-bit 暗号文)"]
        DH_RESP --> NONCE_SRV["key 33.9 (サーバー nonce)"]
        KEY336 -->|"復号 (鍵=???)"| INIT_KEYS["初期セッション鍵"]
        INIT_KEYS --> ENC0["enc_key_0 (128-bit)"]
        INIT_KEYS --> SIGN0["sign_key_0 (256-bit)"]
    end

    subgraph "Phase 3: KDF 鍵更新 (解明済み)"
        PSK -->|HMAC key| KDF["KDF (HMAC-SHA256 chain)"]
        ENC0 -->|入力| KDF
        SIGN0 -->|入力| KDF
        NONCE_HARD -->|入力| KDF
        KDF --> ENC1["enc_key_1 (128-bit)"]
        KDF --> SIGN1["sign_key_1 (256-bit)"]
        ENC1 -->|次の更新入力| KDF2["KDF (次回更新)"]
        SIGN1 -->|次の更新入力| KDF2
    end

    subgraph "Phase 4: MSL 通信"
        ENC0 -->|暗号化/復号| MSL_ENC["AES-128-CBC"]
        SIGN0 -->|署名/検証| MSL_SIGN["HMAC-SHA256"]
        MSL_ENC --> PAYLOAD["manifest / license / logblob"]
        MSL_SIGN --> PAYLOAD
    end

    %% 赤: バイナリ埋め込み
    style PSK fill:#e74c3c,stroke:#c0392b,color:#fff
    style NONCE_HARD fill:#e74c3c,stroke:#c0392b,color:#fff
    style DH_P fill:#e74c3c,stroke:#c0392b,color:#fff
    style DH_G fill:#e74c3c,stroke:#c0392b,color:#fff
    style RSA_BOOT fill:#e74c3c,stroke:#c0392b,color:#fff
    style ECC_BOOT fill:#e74c3c,stroke:#c0392b,color:#fff

    %% 青: サーバーレスポンス由来
    style SERVER fill:#3498db,stroke:#2980b9,color:#fff
    style DH_RESP fill:#3498db,stroke:#2980b9,color:#fff
    style KEY336 fill:#3498db,stroke:#2980b9,color:#fff
    style NONCE_SRV fill:#3498db,stroke:#2980b9,color:#fff
    style ENC0 fill:#3498db,stroke:#2980b9,color:#fff
    style SIGN0 fill:#3498db,stroke:#2980b9,color:#fff

    %% 黄: 計算可能 (KDF 出力)
    style KDF fill:#f1c40f,stroke:#d4ac0f,color:#000
    style ENC1 fill:#f1c40f,stroke:#d4ac0f,color:#000
    style SIGN1 fill:#f1c40f,stroke:#d4ac0f,color:#000
    style KDF2 fill:#f1c40f,stroke:#d4ac0f,color:#000
```

### 凡例

| 色 | 意味 |
|----|------|
| 赤 | バイナリ埋め込み |
| 青 | サーバーレスポンス由来 |
| 黄 | 計算可能 (KDF 出力) |

---

## 2. KDF 鍵更新の詳細フロー

```mermaid
graph LR
    subgraph "入力"
        PSK2["PSK (128-bit)"]
        ENC_OLD["旧 enc_key (128-bit)"]
        SIGN_OLD["旧 sign_key (256-bit)"]
        NONCE2["nonce (128-bit)"]
    end

    subgraph "Step 1-2: セッションバインド"
        PSK2 -->|key| H1["HMAC-SHA256"]
        ENC_OLD -->|"msg: enc || sign"| H1
        SIGN_OLD -->|"msg: enc || sign"| H1
        H1 -->|session_check| H2["HMAC-SHA256"]
        NONCE2 -->|msg| H2
        H2 --> SB["session_bind (256-bit)"]
    end

    subgraph "Step 3-4: 新暗号化鍵"
        PSK2 -->|key| H3["HMAC-SHA256"]
        ENC_OLD -->|msg| H3
        H3 -->|enc_temp| H4["HMAC-SHA256"]
        NONCE2 -->|msg| H4
        H4 -->|truncate 128-bit| NEW_ENC["new_enc_key (128-bit)"]
    end

    subgraph "Step 5-6: 新署名鍵"
        PSK2 -->|key| H5["HMAC-SHA256"]
        SIGN_OLD -->|msg| H5
        H5 -->|sign_temp| H6["HMAC-SHA256"]
        NONCE2 -->|msg| H6
        H6 --> NEW_SIGN["new_sign_key (256-bit)"]
    end

    %% 赤: バイナリ埋め込み
    style PSK2 fill:#e74c3c,stroke:#c0392b,color:#fff
    style NONCE2 fill:#e74c3c,stroke:#c0392b,color:#fff

    %% 青: サーバーレスポンス由来
    style ENC_OLD fill:#3498db,stroke:#2980b9,color:#fff
    style SIGN_OLD fill:#3498db,stroke:#2980b9,color:#fff

    %% 黄: 計算可能
    style NEW_ENC fill:#f1c40f,stroke:#d4ac0f,color:#000
    style NEW_SIGN fill:#f1c40f,stroke:#d4ac0f,color:#000
    style SB fill:#f1c40f,stroke:#d4ac0f,color:#000
```

---

## 3. 鍵一覧

| 鍵名 | サイズ | 格納場所 | 用途 | 状態 |
|------|--------|----------|------|------|
| PSK | 128-bit | バイナリ | KDF マスター鍵 | 確定 |
| nonce | 128-bit | バイナリ | KDF 入力 | 確定 |
| enc_key_0 | 128-bit | 不明 | AES-128-CBC 暗号化 | 由来不明 |
| sign_key_0 | 256-bit | 不明 | HMAC-SHA256 署名 | 由来不明 |
| enc_key_1 | 128-bit | KDF 出力 | 更新後の暗号化鍵 | 計算可能 |
| sign_key_1 | 256-bit | KDF 出力 | 更新後の署名鍵 | 計算可能 |
| DH p | 1024-bit | バイナリ | DH 鍵交換 | 確定 |
| DH g | - | バイナリ | DH 鍵交換 | 確定 |
| kAppBootKey | 4096-bit | バイナリ | DH パラメータ暗号化 | 既知 |
| kAppBootEccKey | 256-bit | バイナリ | レスポンス署名検証 | 既知 |

---

## 4. 未解明ポイント

```mermaid
graph TD
    Q1["key 33.6 (768-bit) の復号鍵は何か"]
    Q2["初期 enc_key_0 / sign_key_0 の由来"]
    Q3["PSK 2箇所目直前の 256-bit データの正体"]
    Q4["ブートストラップ署名鍵 38b2030d... の導出元"]

    Q1 --> H1["仮説A: DH 共有秘密で復号"]
    Q1 --> H2["仮説B: PSK で復号"]
    Q1 --> H3["仮説C: TFIT チェーン出力で復号"]

    Q2 --> H4["仮説: key 33.6 に暗号化されて格納"]
    Q3 --> H5["仮説: 別の KDF 定数 or HMAC 鍵"]
    Q4 --> H6["仮説: TFIT ホワイトボックスチェーン出力"]

    style Q1 fill:#fa0,stroke:#a60,color:#fff
    style Q2 fill:#fa0,stroke:#a60,color:#fff
    style Q3 fill:#fa0,stroke:#a60,color:#fff
    style Q4 fill:#fa0,stroke:#a60,color:#fff
```
