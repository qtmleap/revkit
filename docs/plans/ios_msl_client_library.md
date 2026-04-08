# 作業計画書: iOS MSL クライアントライブラリ
日時: 2026-04-08T19:10:00+09:00

## 目標
Netflix iOS MSL 通信を Python で独立実装し、動画マニフェスト取得まで実行する。

## 判明済みの事実

### 暗号パラメータ (全て確定済み)
| パラメータ | 値 | 備考 |
|-----------|-----|------|
| DH 素数 p | `9694e9d8...e27df` (1024-bit) | NFWebCrypto にハードコード、セッション間で固定 |
| DH 生成元 g | `5` | 固定 |
| AES モード | AES-128-CBC + PKCS7 | enc_key = 16 bytes |
| HMAC | HMAC-SHA256 | hmac_key = 32 bytes |
| IV 格納 | ciphertext の先頭 16 bytes に prepend | IV フィールド (key 7) は空 |

### CBOR メッセージ構造 (全て確定済み)
| メッセージ種別 | トップレベルキー | 特徴 |
|--------------|----------------|------|
| appboot リクエスト | {16, 33, 34} + {16, 64} | entity_auth_data (34) あり、header (32) なし |
| appboot レスポンス | {16, 32, 33} + {16, 64} | key_response_data (33) にセッション鍵 |
| 通常リクエスト (manifest 等) | {16, 32, 33} + {16, 64} | entity_auth なし、header (32) あり |
| 通常レスポンス | 同上 | gzip ラップされる場合あり |

### entity_auth_data 内部構造 (FAIRPLAY_MGK_APPID)
```
key 30: "FAIRPLAY_MGK_APPID"
key 35: {
    50: bytes(8096)       ← device_key_data (デバイス固有)
    80: "NFAPPL-02-IPHONE9=1-"  ← ESN プレフィックス
    81: "NFAPPL-02-IPHONE9=1-AD04..."  ← PRV ESN 全体
    "apphmac": bytes(32)  ← HMAC-SHA256
    "appid": "a2becfec-b286-535c-b884-903a384caee6"
    "appkeyversion": 1
    "devicetoken": bytes(216)
}
```

### key_exchange_data 構造
```
appboot:   key 6 = bytes(352), key 8 = "{ESN}" (suffix なし)
通常 MSL:  key 6 = bytes(1216), key 8 = "{ESN}_5" (suffix あり)
共通:      key 7 = bytes(0), key 9 = bytes(16) nonce
```

### HTTP ヘッダー (キャプチャ確認済み)
```
Host: appboot.netflix.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Netflix/24 CFNetwork/1335.0.3.4 Darwin/21.6.0
X-Netflix.APIAction: appboot
X-Netflix.Request.Attempt: 1
Cookie: nfvdid=...
```

## 未解明の要素

| 項目 | 重要度 | 解明方法 |
|------|--------|----------|
| **HKDF パラメータ** (shared_secret → enc_key + hmac_key) | ★★★ 必須 | Tweak で HKDF 関数をフック、または総当たり (salt/info/length の組み合わせ) |
| **entity_auth_data の生成ロジック** | ★★☆ | キャプチャからバイナリテンプレートとして再利用可能。独自生成は TFIT 解明が必要で困難 |
| **key 33.6 の構造** (352B/1216B) | ★★☆ | DH pub_key (128B) + 追加データの関係を解明。キャプチャテンプレート再利用も可 |
| **HMAC 署名対象** | ★☆☆ | キャプチャの signature と hmac_key で検証対象データを特定 |

## タスク一覧

### Phase 0: 残る未解明要素の調査 (並列)

#### tweak-engineer 担当
- [ ] T-1. **HKDF パラメータのキャプチャ** — NFWebCrypto の HKDF シンボルを特定してフック。salt, info, output length を記録
- [ ] T-2. **ESN キャプチャ** — `IosMslClient.esn` getter をフックして `g_keys[@"esn"]` に保存
- [ ] T-3. **Cookie キャプチャ** — `NSHTTPCookieStorage.cookiesForURL:` をフックし NetflixId / SecureNetflixId を抽出

#### python-engineer 担当
- [ ] P-0. **HKDF 総当たり検証** — キャプチャ済みの shared_secret / enc_key / hmac_key を使い、一般的な HKDF パラメータ (SHA-256, 空 salt, 各種 info 文字列) で enc_key が再現できるか検証。Tweak の HKDF フックと並行して進める
- [ ] P-1. **HMAC 署名対象の特定** — キャプチャの signature (key 16) と hmac_key を照合し、署名入力データの範囲を確定
- [ ] P-2. **キャプチャテンプレート抽出** — appboot / manifest リクエストの entity_auth_data, key_exchange_data, header をバイナリテンプレートとして `raws/templates/` に保存するスクリプト作成

### Phase 1: エンコーダー・クライアント実装

#### python-engineer 担当
- [ ] P-3. **DH 鍵交換の Python 実装** — `crypto.py` に `generate_dh_keypair(p, g)`, `compute_dh_shared_secret(priv_key, server_pub, p)`, `derive_session_keys(shared_secret)` を追加
- [ ] P-4. **iOS バイナリフレームのエンコード** — `cbor_encoder.py` に `build_ios_payload_frame()` を追加。復号で判明した構造 (bstr(9) + 0x3E + gzip bstr + trailer) を再現
- [ ] P-5. **encrypt_payload の IV prepend 対応** — ciphertext の先頭に IV を prepend し、IV フィールドを空にする iOS 形式
- [ ] P-6. **`ios_client.py` 新規作成** — Encoder + Decoder + HTTP を統合した iOS MSL クライアント
  - `load_session(keys_path)` — 鍵ロード (Tweak JSON 対応)
  - `load_templates(template_dir)` — entity_auth / header テンプレートをロード
  - `set_cookies(nfvdid, netflix_id, secure_netflix_id)` — Cookie 設定
  - `appboot()` — DH 鍵交換 + セッション確立
  - `get_manifest(video_id)` — マニフェスト取得

### Phase 2: マニフェスト取得

#### python-engineer 担当
- [ ] P-7. **manifest リクエスト構築** — 復号済みキャプチャから manifest ペイロード JSON の構造を再現
- [ ] P-8. **`tools/fetch_manifest.py` CLI 作成** — `--keys`, `--cookies`, `--video-id` で実行
- [ ] P-9. **差分検証** — 生成した CBOR と実キャプチャの構造比較ツール

## 実行順序

```
Phase 0 (並列):
  ├── [tweak]  T-1 (HKDF), T-2 (ESN), T-3 (Cookie)
  └── [python] P-0 (HKDF検証), P-1 (HMAC), P-2 (テンプレート)
      ↓
Phase 1 (順次):
  P-3 (DH実装) → P-4 (フレームエンコード) → P-5 (IV prepend) → P-6 (クライアント)
      ↓
Phase 2 (順次):
  P-7 (manifest構築) → P-8 (CLI) → P-9 (検証)
```

## 成果物

| ファイル | 説明 |
|---------|------|
| `src/netflix_msl/ios_client.py` | iOS MSL クライアント (メイン) |
| `src/netflix_msl/crypto.py` | DH 鍵交換 + HKDF 追加 (既存拡張) |
| `src/netflix_msl/cbor_encoder.py` | iOS フレームエンコード追加 (既存拡張) |
| `src/netflix_msl/constants.py` | iOS 固有定数追加 (既存拡張) |
| `tools/extract_msl_template.py` | テンプレート抽出 CLI |
| `tools/fetch_manifest.py` | マニフェスト取得 CLI |
| `raws/templates/` | 抽出済みテンプレート |
| `packages/tweak/AppbootKeyExtract/` | HKDF / ESN / Cookie キャプチャ拡張 |

## リスク・注意点

- **HKDF が最大のブロッカー**: shared_secret → enc_key + hmac_key の導出方法が判明しないと、Python 独立での鍵交換ができない。Tweak キャプチャ鍵で代替可能だが、毎回デバイスが必要になる
- **entity_auth_data はテンプレート再利用**: TFIT ホワイトボックス鍵導出の解明は現実的でないため、キャプチャした entity_auth_data をそのまま再利用する。デバイス/アカウント固有のため、別デバイスでは使えない
- **key 33.6 (352B/1216B)** の内部構造: DH pub_key (128B) + 認証データの関係が未解明。テンプレート内の pub_key 部分のみ差し替えが必要
- **Cookie の有効期限**: 定期的に再取得が必要
- **レート制限**: Netflix サーバーへのリクエスト頻度に注意
