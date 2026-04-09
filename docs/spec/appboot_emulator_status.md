# appboot リクエストエミュレータ — 進捗と課題

作成日: 2026-04-09

Python で appboot → MSL 認証を実行するエミュレータの実装状況。

---

## 1. 全体フロー

```
ESN (デバイス固有)
  │
  ├─ Phase 0: TFIT-WB-AES → enc_key_0, sign_key_0 (MGK)
  ├─ Phase 3: KDF チェーン → enc_key_1, sign_key_1, session_bind
  ├─ DH 鍵ペア生成
  ├─ CBOR メッセージ構築 (entity_auth_data + key_request_data)
  ├─ HMAC-SHA256 署名 (sign_key_0)
  ├─ POST appboot.netflix.com/{ESN_PREFIX}
  ├─ レスポンス解析 (x-netflix-deviceidtoken, server DH pub, nonce)
  ├─ Phase 2: DH 共有秘密 → HMAC-SHA384 → セッション鍵
  └─ MSL 通信開始
```

## 2. 実装済み (動作確認済み)

| コンポーネント | ファイル | テスト状態 |
|--------------|---------|-----------|
| TFIT-WB-AES MGK 導出 | `tools/emulate_tfit.py` | ✅ ライブキャプチャと完全一致 |
| Phase 3 KDF (6段 HMAC チェーン) | `crypto.py:kdf_renew()` | ✅ 13/13 テスト PASS |
| Phase 2 KDF (HMAC-SHA384) | `crypto.py:derive_initial_session_keys()` | ✅ テストベクトル一致 |
| 48B key 導出 (SHA384) | `crypto.py:derive_hmac384_key()` | ✅ ライブ確認 |
| DH 鍵生成/共有秘密 | `crypto.py:generate_dh_keypair()` | ✅ ラウンドトリップ検証 |
| Netflix カスタム CBOR エンコーダ | `cbor_encoder.py:nf_cbor_encode()` | ✅ サーバーパース成功 |
| entity_auth_data 構築 | `test_appboot_e2e.py` | ✅ MGK_APPID スキーム |
| key_request_data 構築 | `test_appboot_e2e.py` | ✅ key 33.6/33.9 含む |
| session_region TFIT 暗号化 | `crypto.py:build_session_region()` | ✅ DH pub key → 8 block WB-AES |
| key 33.6 XOR 暗号化 | `crypto.py:build_key336_scheme_data()` | ✅ nonce XOR |
| HMAC-SHA256 メッセージ署名 | `test_appboot_e2e.py` | ✅ sign_key_0 で署名 |
| HTTP POST (appboot) | `test_appboot_e2e.py` | ✅ HTTP 200 返却 |
| AES-128-CBC 暗号化/復号 | `crypto.py` | ✅ (MSL ペイロード用) |
| RSA-4096 / P-256 署名検証鍵 | `constants.py` | ✅ バイナリ抽出済み |
| E2E テストスクリプト | `tools/test_appboot_e2e.py` | ✅ サーバー到達 |

## 3. 現在のサーバーレスポンス

```
errorcode=6, internalcode=204060
"App Id Validation failed."
```

### エラー遷移履歴:
1. `errorcode=1 "Error parsing MSL encodable"` → Netflix カスタム CBOR エンコーダで解消
2. `errorcode=6 "App Id Validation failed"` → CBOR パース成功、apphmac 検証で失敗

### 検証結果:
- apphmac なし → errorcode=1 (パースエラー) — **apphmac は必須フィールド**
- ランダム 32B apphmac → errorcode=6 (検証失敗) — **サーバーが apphmac を検証している**
- キャプチャ済み 32B apphmac (古いセッション) → errorcode=6 — **期限切れまたは DH 鍵と紐付き**
- 実キャプチャリプレイ → errorcode=1 (復号失敗) — **リプレイ保護動作**

## 4. 残課題

### 4.1 apphmac (32B) のサーバー検証ロジック (最優先)

apphmac は必須で、サーバーが検証する。ランダム値では通らない。
TFIT 暗号化 DH 鍵 → MGK → apphmac の関連が推定されるが、
32B の正確な導出式は未解明。

対処方針:
1. getAuthData() (MslClient 0x284bc) で apphmac 値を直接キャプチャ (Frida/Tweak)
2. 同一セッションの DH 鍵 + apphmac をペアでキャプチャし、導出関係を検証
3. TFIT 暗号化結果のハッシュ (SHA-256 of scheme_data) が apphmac の可能性を検証

### 4.2 server_scheme_data からの DH 公開鍵抽出

appboot レスポンスの key 33.6 (96B) からサーバー DH 公開鍵を抽出するロジックが未実装。
Frida フックで `DH_compute_key` の入力引数をキャプチャすることで解明可能。

### 4.3 payload chunk の正確なフォーマット

appboot リクエストは 2 つの CBOR メッセージの連結:
- Message 1 (1037B): entity_auth_data + key_request_data + signature
- Message 2 (~336B): payload_chunk (key 64) + signature (key 16)

payload_chunk の内部フォーマット (暗号化鍵、IV、ペイロード本体) が未解明。

## 5. 値の取得方法まとめ

| 値 | 取得方法 | 自動化 |
|----|---------|--------|
| ESN | Tweak でキャプチャ (1回) | 手動 |
| enc_key_0 / sign_key_0 | `emulate_tfit.py` (ESN → TFIT) | ✅ 自動 |
| Phase 3 KDF 全出力 | `crypto.kdf_renew()` | ✅ 自動 |
| DH 鍵ペア | `crypto.generate_dh_keypair()` | ✅ 自動 |
| Phase 2 セッション鍵 | `crypto.derive_full_key_chain()` | ✅ 自動 |
| deviceIdToken (apphmac) | `x-netflix-deviceidtoken` レスポンスヘッダ | ✅ 自動 (要初回取得) |
| devicetoken (216B) | deviceIdToken の Base64 デコード | ✅ 自動 |
| AppID / AppKeyVersion | 固定定数 | ✅ 自動 |
| 署名検証鍵 | `constants.py` に埋め込み済み | ✅ 自動 |

## 6. ファイル構成

```
src/netflix_msl/
  ├── ios_client.py       # E2E オーケストレーター (iOSMslClient)
  ├── crypto.py           # 暗号プリミティブ (DH, KDF, TFIT, HMAC, AES)
  ├── cbor_encoder.py     # Netflix カスタム CBOR エンコーダ + MSL メッセージビルダー
  ├── cbor_decoder.py     # CBOR MSL メッセージパーサー
  ├── constants.py        # バイナリ定数 (DH params, PSK, 署名鍵, AppID)
  └── client.py           # Chrome/Widevine MSL クライアント (参考実装)

tools/
  ├── test_appboot_e2e.py         # E2E appboot テスト (★ メインテストスクリプト)
  ├── verify_full_key_chain.py    # KDF 回帰テスト (13/13 PASS)
  └── emulate_tfit.py             # TFIT WB-AES Unicorn エミュレータ
```

## 7. テスト実行方法

```bash
# KDF 回帰テスト (オフライン、サーバー不要)
uv run python tools/verify_full_key_chain.py

# E2E appboot テスト (サーバー接続あり)
uv run python tools/test_appboot_e2e.py --no-proxy

# プロキシ経由
uv run python tools/test_appboot_e2e.py --proxy http://192.168.0.51:9080

# キャプチャ済み deviceIdToken を使用
uv run python tools/test_appboot_e2e.py --no-proxy --device-id-token 'Base64文字列'
```
