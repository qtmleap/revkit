# appboot リクエストエミュレータ — 進捗と課題

作成日: 2026-04-09
更新日: 2026-04-10

Python で appboot → MSL 認証を実行するエミュレータの実装状況。

---

## 1. 全体フロー

```
ESN (デバイス固有)
  │
  ├─ Phase 0: TFIT-WB-AES → enc_key_0, sign_key_0 (MGK)
  ├─ Phase 3: KDF チェーン → enc_key_1, sign_key_1, session_bind
  ├─ DH 鍵ペア生成
  ├─ entity_auth_data 構築 (ESN, appid, apphmac, devicetoken)  ← ★ ここで詰まっている
  ├─ scheme_data 352B 構築 (TFIT暗号化 DH + CFB-chain CBOR)   ← ★ ここで詰まっている
  ├─ CBOR メッセージ構築 + HMAC署名
  ├─ POST appboot.netflix.com/{ESN_PREFIX}
  ├─ レスポンス解析 (server DH pub, nonce, x-netflix-deviceidtoken)
  ├─ Phase 2: DH 共有秘密 → HMAC-SHA384 → セッション鍵
  └─ MSL 通信開始
```

## 2. 現在のブロッカー: 2 つのエラー

### ブロッカー 1: errorcode=6 "App Id Validation failed"

**原因:** entity_auth_data の `apphmac` フィールド (32B) の値が不正。

**証拠:**
- real ead (4/8キャプチャ) + fresh krd → **errorcode=1** (ec=6 を通過!)
- our ead (Python生成) + any krd → **errorcode=6** (App Id 検証失敗)

つまり CBOR 構造やエンコーディングは正しいが、**apphmac の 32B 値が間違っている。**

**apphmac (32B) について分かっていること:**
- entity_auth_data 内の必須フィールド (省略すると ec=1 パースエラー)
- 32B の raw bytes (Base64 文字列ではない)
- 241 リクエスト中 67 ユニーク値 → セッション可変だが一定期間安定
- devicetoken (216B) とは別の値 (同一セッションで devicetoken=216B, apphmac=32B)
- RE で `getAuthData()` (0x284bc) が `this+0xe8` から読み出すことは判明
- しかし `this+0xe8` に何がセットされるか、32B の導出元は不明
- HMAC/SHA256/HKDF/TFIT の全組み合わせを試したが一致なし

**apphmac (32B) について分かっていないこと:**
- 導出式 (何の入力から何の関数で計算されるか)
- `this+0xe8` に値をセットするコードパス (setApphmac の入力が何か)

### ブロッカー 2: errorcode=1 "Error decrypting data with cryptex"

**原因:** サーバーが scheme_data (key 33.6) の TFIT 暗号化を復号できない。

**証拠:**
- real ead + real krd (リプレイ) → errorcode=1
- real ead + fresh krd (新 DH) → errorcode=1
- 両方とも同じエラー → **DH 鍵の鮮度ではなく TFIT 暗号化自体の問題**

**考えられる原因:**
1. サーバー側 AES 鍵がローテーションされた (アプリバージョン 15.48.1 のキャプチャが古い)
2. TFIT エミュレーション出力がサーバーの期待と微妙に異なる
3. scheme_data 352B の CFB-chain エンコーディングが不正
4. PKCS#7 パディングの問題

**注意:** 4/8 の real krd も ec=1 を返すため、**キャプチャ時点で既にサーバー鍵が異なっていた**
可能性がある。あるいはリプレイ保護として DH 鍵のタイムスタンプを検証している。

## 3. エラー遷移の全履歴

| 段階 | テスト内容 | エラー | 意味 |
|------|----------|--------|------|
| 1 | 標準 cbor2 エンコード | ec=1 ic=100000 "Error parsing MSL encodable" | CBOR パース失敗 |
| 2 | Netflix カスタム CBOR | ec=6 ic=204060 "App Id Validation failed" | パース成功、ead 検証失敗 |
| 3 | real ead + fresh krd | **ec=1 ic=208001 "Error decrypting data with cryptex"** | **ead 通過、TFIT 復号失敗** |
| 4 | real ead + real krd (リプレイ) | ec=1 ic=208001 "Error decrypting data with cryptex" | 同上 (リプレイでも) |

**現在地は段階 3:** entity_auth_data を正しく構築できれば TFIT 復号段階に進める。

## 4. 実装済み (動作確認済み)

| コンポーネント | ファイル | テスト状態 |
|--------------|---------|-----------|
| TFIT-WB-AES MGK 導出 | `tools/emulate_tfit.py` | ✅ ライブキャプチャと完全一致 |
| Phase 3 KDF (6段 HMAC チェーン) | `crypto.py:kdf_renew()` | ✅ 13/13 テスト PASS |
| Phase 2 KDF (HMAC-SHA384) | `crypto.py:derive_initial_session_keys()` | ✅ テストベクトル一致 |
| 48B key = SHA384(session_bind[:16]) | `crypto.py:derive_hmac384_key()` | ✅ ライブ確認 |
| DH 鍵生成/共有秘密 | `crypto.py:generate_dh_keypair()` | ✅ ラウンドトリップ検証 |
| Netflix カスタム CBOR エンコーダ | `cbor_encoder.py:nf_cbor_encode()` | ✅ ead 467B byte-for-byte 一致 |
| entity_auth_data CBOR 構造 | `nf_cbor_encode()` | ✅ real 値を入れれば 467B 完全一致 |
| scheme_data 352B 構築 | `crypto.py:build_scheme_data_352()` | ✅ 135B header + 128B TFIT + 89B CFB |
| HMAC-SHA256 署名 (sign_key_0) | `test_appboot_e2e.py` | ✅ real と一致確認 |
| HTTP POST + レスポンス解析 | `test_appboot_e2e.py` | ✅ サーバー到達 |
| 二重 CBOR メッセージ (msg1+msg2) | `test_appboot_e2e.py` | ✅ payload chunk 追加 |

## 5. entity_auth_data の構造 (確定)

暗号化されていない平文 CBOR:

```
key 30: "MGK_APPID"                              ← 固定
key 35: {
  3:              ESN (string, 84 chars)          ← 固定 (デバイス毎)
  "apphmac":      bytes(32B)                      ← ★ 可変、導出元不明
  "appid":        "a2becfec-b286-...-903a384caee6" ← 固定
  "appkeyversion": 1                              ← 固定
  "devicetoken":  bytes(216B)                     ← 可変、x-netflix-deviceidtoken の Base64 デコード
}
```

- **4 つの固定フィールド:** scheme, ESN, appid, appkeyversion
- **devicetoken (216B):** サーバー発行の `x-netflix-deviceidtoken` ヘッダを Base64 デコード
  NFSharedStore App Group コンテナにキャッシュ (`DEVICE_ID_TOKEN` キー)
- **apphmac (32B):** ★ 導出元不明。`FpsMgkAppIdAuthData.this+0xe8` から読み出される

## 6. scheme_data 352B の構造 (確定)

```
[0:135]   固定 CBOR ヘッダー (IOS_SCHEME_DATA_HEADER_135B)
[135:263] TFIT-WB-AES-128-ECB(DH_pub_key) — 8 blocks = 128B
[263:352] CFB-chain XOR エンコードされた CBOR テール (89B)
```

CFB 復号後のテール CBOR:
```
key 30: "AUTHENTICATED_DH"   ← 固定
key 22: message_id (uint64)  ← 可変 (ランダム)
key 40: false                ← 固定
key 21: true                 ← 固定
key 24: timestamp (uint64)   ← 可変 (UNIX秒)
+ PKCS#7 padding (7 bytes of 0x07)
```

XOR エンコード: `CFB[0] = CBOR[0] XOR TFIT[-1]`, `CFB[n] = CBOR[n] XOR CFB[n-1]`
全体がさらに key 33.9 ノンス (16B) で XOR される。

## 7. 次のアクション

### 優先度 1: apphmac (32B) の導出元を解明

`FpsMgkAppIdAuthData.this+0xe8` に値をセットする全コードパスを追跡:
- Path A: `_updateEntityAuthDeviceIdToken` → `setApphmac()` → `this+0xe8`
- `[self deviceIdToken]` が返す値は Base64 文字列 (288 chars) だが、CBOR には 32B が入る
- `getAuthData()` 内で Base64 デコード以外の変換が行われている可能性

### 優先度 2: errorcode=1 TFIT 復号エラーの調査

real krd のリプレイでも ec=1 が出るため:
- サーバー側 TFIT/AES 鍵のローテーションを確認
- 最新アプリバージョンで新しい TFIT テーブルが使われていないか確認
- Frida で実機の appboot 成功時の scheme_data を完全キャプチャし、我々の出力と比較

## 8. テスト実行方法

```bash
# KDF 回帰テスト (オフライン、13/13 PASS)
uv run python tools/verify_full_key_chain.py

# E2E appboot テスト (サーバー接続、現在 ec=6)
uv run python tools/test_appboot_e2e.py --no-proxy

# deviceIdToken 指定
uv run python tools/test_appboot_e2e.py --no-proxy --device-id-token 'Base64文字列'
```

## 9. ファイル構成

```
src/netflix_msl/
  ├── ios_client.py       # E2E オーケストレーター (iOSMslClient)
  ├── crypto.py           # 暗号プリミティブ (DH, KDF, TFIT, HMAC, AES)
  ├── cbor_encoder.py     # Netflix カスタム CBOR エンコーダ + nf_cbor_encode()
  ├── cbor_decoder.py     # CBOR MSL メッセージパーサー
  ├── constants.py        # バイナリ定数 (DH params, PSK, 署名鍵, AppID, CBOR headers)
  └── client.py           # Chrome/Widevine MSL クライアント (参考実装)

tools/
  ├── test_appboot_e2e.py         # E2E appboot テスト (★ メインテストスクリプト)
  ├── verify_full_key_chain.py    # KDF 回帰テスト (13/13 PASS)
  └── emulate_tfit.py             # TFIT WB-AES Unicorn エミュレータ

packages/tweak/
  └── NetflixEntityAuth/          # ランタイムキャプチャ Tweak (FpsMgkAppIdAuthData フック)
```
