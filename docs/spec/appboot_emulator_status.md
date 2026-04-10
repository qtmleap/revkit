# appboot リクエストエミュレータ — 進捗と課題

作成日: 2026-04-09
更新日: 2026-04-10

---

## 1. appboot フローチャート

```mermaid
flowchart TD
    START([Python appboot 開始]) --> ESN[ESN を入力]
    
    ESN --> TFIT["Phase 0: TFIT エミュレーション<br/>SHA384(ESN) → TFIT-WB-AES<br/>→ enc_key_0 (16B) + sign_key_0 (32B)"]
    TFIT --> KDF["Phase 3: KDF チェーン<br/>HMAC-SHA256 × 6段<br/>→ enc_key_1, sign_key_1, session_bind"]
    KDF --> DH["DH 鍵ペア生成<br/>p=Netflix固有1024bit, g=5<br/>→ dh_pub_key (128B), dh_priv_key (128B)"]
    
    DH --> EAD_BUILD["entity_auth_data 構築 (CBOR)"]
    DH --> KRD_BUILD["key_request_data 構築 (CBOR)"]
    
    subgraph ead ["entity_auth_data (平文 CBOR, ~467B)"]
        EAD_BUILD --> EAD_SCHEME["key 30: 'MGK_APPID' ✅ 固定"]
        EAD_BUILD --> EAD_ESN["key 35.3: ESN ✅ 固定"]
        EAD_BUILD --> EAD_APPID["key 35.appid: UUID ✅ 固定"]
        EAD_BUILD --> EAD_AKV["key 35.appkeyversion: 1 ✅ 固定"]
        EAD_BUILD --> EAD_APPHMAC["key 35.apphmac: 32B ❌ 導出元不明"]
        EAD_BUILD --> EAD_DT["key 35.devicetoken: 216B ⚠️ 取得方法は判明<br/>(x-netflix-deviceidtoken Base64デコード)"]
    end
    
    subgraph krd ["key_request_data (CBOR, ~499B)"]
        KRD_BUILD --> KRD_SD["key 6: scheme_data 352B ✅ 構築済み"]
        KRD_BUILD --> KRD_ID["key 8: ESN ✅"]
        KRD_BUILD --> KRD_NONCE["key 9: XOR nonce 16B ✅"]
        KRD_BUILD --> KRD_STATUS["key 7: empty ✅"]
    end
    
    subgraph sd ["scheme_data 352B の内部構造"]
        KRD_SD --> SD_HDR["[0:135] 固定 CBOR ヘッダー ✅"]
        KRD_SD --> SD_TFIT["[135:263] TFIT(DH_pub) 128B ✅<br/>8 block WB-AES-128-ECB"]
        KRD_SD --> SD_CFB["[263:352] CFB-chain CBOR テール 89B ✅<br/>AUTHENTICATED_DH + timestamp + flags"]
        KRD_SD --> SD_XOR["全体を key33.9 nonce で XOR ✅"]
    end
    
    EAD_APPHMAC --> SIGN["HMAC-SHA256(sign_key_0, krd_bytes)<br/>→ 署名 32B ✅"]
    EAD_DT --> SIGN
    KRD_SD --> SIGN
    
    SIGN --> MSG["CBOR メッセージ組立<br/>{34: ead, 33: krd, 16: sig}<br/>+ payload chunk ✅"]
    
    MSG --> POST["POST appboot.netflix.com ✅<br/>HTTP 200 返却"]
    
    POST --> SERVER_PARSE{"サーバー:<br/>CBOR パース"}
    SERVER_PARSE -->|"パース失敗"| EC1_PARSE["errorcode=1<br/>'Error parsing MSL encodable'<br/>✅ 解決済み (Netflix CBOR エンコーダ)"]
    SERVER_PARSE -->|"パース成功"| SERVER_EAD{"サーバー:<br/>entity_auth_data 検証"}
    
    SERVER_EAD -->|"apphmac/devicetoken 不正"| EC6["errorcode=6<br/>'App Id Validation failed'<br/>❌ ← 現在ここで詰まっている"]
    SERVER_EAD -->|"検証成功"| SERVER_TFIT{"サーバー:<br/>scheme_data TFIT 復号"}
    
    SERVER_TFIT -->|"復号失敗"| EC1_DECRYPT["errorcode=1<br/>'Error decrypting data with cryptex'<br/>⚠️ real ead 使用時はここに到達"]
    SERVER_TFIT -->|"復号成功"| SERVER_DH["サーバー:<br/>DH 公開鍵抽出 + 共有秘密計算"]
    
    SERVER_DH --> RESPONSE["appboot レスポンス<br/>server_scheme_data + nonce<br/>+ x-netflix-deviceidtoken ヘッダ"]
    
    RESPONSE --> PHASE2["Phase 2: DH 共有秘密 → セッション鍵<br/>✅ 実装済み (テスト通過)"]
    PHASE2 --> MSL["MSL 暗号化通信開始"]
    
    style EC6 fill:#e74c3c,stroke:#c0392b,color:#fff
    style EC1_DECRYPT fill:#e67e22,stroke:#d35400,color:#fff
    style EC1_PARSE fill:#27ae60,stroke:#229954,color:#fff
    style EAD_APPHMAC fill:#e74c3c,stroke:#c0392b,color:#fff
    style EAD_DT fill:#f39c12,stroke:#e67e22,color:#fff
    style TFIT fill:#2ecc71,stroke:#27ae60,color:#fff
    style KDF fill:#2ecc71,stroke:#27ae60,color:#fff
    style DH fill:#2ecc71,stroke:#27ae60,color:#fff
    style SIGN fill:#2ecc71,stroke:#27ae60,color:#fff
    style POST fill:#2ecc71,stroke:#27ae60,color:#fff
    style MSG fill:#2ecc71,stroke:#27ae60,color:#fff
    style SD_HDR fill:#2ecc71,stroke:#27ae60,color:#fff
    style SD_TFIT fill:#2ecc71,stroke:#27ae60,color:#fff
    style SD_CFB fill:#2ecc71,stroke:#27ae60,color:#fff
    style SD_XOR fill:#2ecc71,stroke:#27ae60,color:#fff
    style SERVER_PARSE fill:#3498db,stroke:#2980b9,color:#fff
    style SERVER_EAD fill:#3498db,stroke:#2980b9,color:#fff
    style SERVER_TFIT fill:#3498db,stroke:#2980b9,color:#fff
    style SERVER_DH fill:#3498db,stroke:#2980b9,color:#fff
    style PHASE2 fill:#2ecc71,stroke:#27ae60,color:#fff
```

### 凡例

- 🟢 緑: 実装済み・動作確認済み
- 🔴 赤: ブロッカー (未解決)
- 🟠 オレンジ: 到達はしたが未解決
- 🟡 黄: 取得方法は判明だが未検証
- 🔵 青: サーバー側処理

---

## 2. 現在の壁

### 壁 1: apphmac (32B) の値が Python で計算できない → errorcode=6

```
entity_auth_data の "apphmac" = HMAC(AIK, devicetoken_216B)
ただし TEE (Trusted Execution Environment) 内で計算されるため、ソフトウェア再現不可。

導出の全容:
  1. AIK (32B) はバイナリ Base64 "OLIDDdVeM2cpAhPK..." = 38b2030d...
  2. importKey() で TEE に sealed される → ハードウェア保護された鍵ハンドル
  3. AppleTeeApiCryptoShim::hmac() が TEE 内で HMAC 計算
  4. TEE 内の鍵は sealed されておりソフトウェアから読み出せない
  5. 標準 HMAC-SHA256(AIK_raw_bytes, devicetoken) では不一致
     → TEE が独自の鍵導出を行っている

Python で再現不可能な理由:
  - TEE (Secure Enclave) のハードウェア鍵がデバイス固有
  - バイナリの AIK バイトは TEE への「入力」であり、TEE 内部で変換される
  - 同じ AIK バイトでも TEE ごとに異なる出力を返す可能性

回避策:
  - mitmproxy で appboot リクエスト CBOR をキャプチャ → apphmac を直接抽出
  - 抽出した apphmac + devicetoken のペアをパラメータとして Python に渡す
  - 同一 devicetoken を使う限り apphmac は再利用可能
```

### 壁 2: TFIT 復号がサーバーで失敗する → errorcode=1

```
壁 1 を real ead で回避しても、次に errorcode=1 で止まる。

分かっていること:
  - "Error decrypting data with cryptex" = サーバーが scheme_data を復号できない
  - 4/8 キャプチャの real krd をリプレイしても同じエラー
  - つまり 4/8 時点の TFIT 暗号化データも今のサーバーでは復号できない

分かっていないこと:
  - サーバー側の TFIT/AES 鍵がいつローテーションされたか
  - 現在のサーバー鍵に対応する TFIT テーブルが何か
  - リプレイ保護 (タイムスタンプ検証) が原因の可能性
```

---

## 3. 実装済みコンポーネント一覧

| # | コンポーネント | 状態 | 検証方法 |
|---|--------------|------|---------|
| 1 | ESN → MGK (TFIT エミュレーション) | ✅ | ライブキャプチャ値と完全一致 |
| 2 | Phase 3 KDF (6段 HMAC チェーン) | ✅ | 13/13 テスト PASS |
| 3 | Phase 2 KDF (HMAC-SHA384) | ✅ | テストベクトル一致 |
| 4 | DH 鍵生成/共有秘密計算 | ✅ | ラウンドトリップ検証 |
| 5 | Netflix カスタム CBOR エンコーダ | ✅ | real ead と 467B byte-for-byte 一致 |
| 6 | entity_auth_data CBOR 構造 | ✅ | 正しい値を入れれば real と一致 |
| 7 | scheme_data 352B 構築 | ✅ | CFB-chain 復号で構造確認済み |
| 8 | HMAC-SHA256 署名 | ✅ | real signature と一致 |
| 9 | HTTP POST + レスポンス解析 | ✅ | サーバー到達、HTTP 200 |
| 10 | apphmac の正しい値 | ❌ | TEE 内 HMAC → Python 再現不可。mitmproxy キャプチャで回避 |
| 11 | TFIT 暗号化がサーバーで復号可能 | ❌ | real krd リプレイでも失敗 |

---

## 4. テスト実行方法

```bash
# KDF 回帰テスト (オフライン、13/13 PASS)
uv run python tools/verify_full_key_chain.py

# E2E appboot テスト (サーバー接続)
uv run python tools/test_appboot_e2e.py --no-proxy

# deviceIdToken 指定
uv run python tools/test_appboot_e2e.py --no-proxy --device-id-token 'Base64文字列'
```
