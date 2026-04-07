# Netflix MSL Capture — Proxyman Script + Addon

Netflix の MSL (Media Service Layer) トラフィックをキャプチャ・解析する Proxyman スクリプト。

## 機能

- **MSL メッセージデコード**: base64 / LZW エンコードされたエンベロープをデコード
- **リクエストボディ解析**: MSL リクエストのパラメータをデコード・保存 (マニフェスト要求の詳細が見える)
- **マニフェスト抽出**: 動画/音声トラック情報 (解像度, ビットレート, コンテンツプロファイル, DRM KID)
- **HTTP マニフェスト API キャプチャ**: `/playapi/cadmium/manifest/1` (非 MSL) をキャプチャ
- **licensedmanifest キャプチャ**: `/msl/playapi/cadmium/licensedmanifest/1` の MSL エンベロープ解析
- **ALE 鍵抽出**: CLEAR スキームの provisioning レスポンスから HMAC/AES 鍵を検出
- **ESN 取得**: デバイス識別子 (Electronic Serial Number) をヘッダー / sender から抽出
- **KID テーブル生成**: 解像度ごとの DRM Key ID 一覧を Markdown テーブルで出力
- **全トラフィックログ**: JSONL 形式で全 MSL 通信を記録

## 前提条件

- **Proxyman v3.6.2 以上** (`writeToFile` / `readFromFile` API が必要)
- Proxyman の SSL Proxying が `*.netflix.com` に対して有効であること

## インストール

### 1. アドオンの配置

```bash
# Proxyman のカスタムアドオンフォルダを開く
# Proxyman > More > Documentations > Open Custom Addons Folder
# または直接:
cp addons/NetflixMSLParser.js \
   ~/Library/Application\ Support/com.proxyman.NSProxy/users/NetflixMSLParser.js
```

### 2. スクリプトの設定

#### スクリプト A: MSL トラフィック (既存)

1. Proxyman を開く
2. **Script Menu** > **Script List** (`Option + Cmd + I`)
3. **+** ボタンで新規スクリプト作成
4. **URL Matching Rule**: `*netflix.com/nq/msl_v1/*`
5. `netflix-msl-capture.js` の内容をスクリプトエディタに貼り付け
6. **Enable on Request** ✓ にチェック
7. **Enable on Response** ✓ にチェック

#### スクリプト B: HTTP マニフェスト API (StreamFab 等)

1. **+** ボタンでもう一つ新規スクリプト作成
2. **URL Matching Rule**: `*netflix.com/*manifest*`
3. `netflix-manifest-http-capture.js` の内容をスクリプトエディタに貼り付け
4. **Enable on Request** ✓ にチェック
5. **Enable on Response** ✓ にチェック

### 3. 出力ディレクトリ

デフォルトでは `~/Desktop/netflix-msl-capture/` に自動作成されます。
スクリプト冒頭の `OUTPUT_DIR` で変更可能:

```javascript
const OUTPUT_DIR = "~/Desktop/netflix-msl-capture";
```

## 出力ファイル構成

```
~/Desktop/netflix-msl-capture/
├── capture_log.jsonl              # 全キャプチャの JSONL ログ
├── esn.txt                        # 最後にキャプチャした ESN
├── raw/                           # 生のリクエスト/レスポンスボディ
│   ├── request_1_manifest_msl_...bin     # MSL リクエスト
│   ├── response_1_2026-...bin            # MSL レスポンス
│   ├── http_request_1_manifest_http_...bin   # HTTP manifest リクエスト
│   └── http_response_1_manifest_http_...bin  # HTTP manifest レスポンス
├── msl/                           # デコード済み MSL メッセージ
│   ├── request_1_manifest_msl_...json    # MSL リクエスト (デコード済み)
│   ├── response_2_2026-...json
│   └── http_response_1_licensedmanifest_http_...json  # licensedmanifest (MSL)
├── manifests/                     # マニフェスト
│   ├── manifest_81234567_2026-...json       # MSL 経由マニフェスト
│   ├── http_manifest_81234567_manifest_http_...json  # HTTP API マニフェスト
│   ├── request_params_1_manifest_msl_...json   # MSL マニフェスト要求パラメータ
│   ├── http_request_1_manifest_http_...json    # HTTP マニフェスト要求パラメータ
│   ├── kid_table_81234567_2026-...json
│   └── kid_table_81234567.md
├── keys/                          # ALE 鍵
│   ├── ale_keys.jsonl
│   └── ale_KID_2026-...json
├── headers/                       # HTTP ヘッダー
└── cookies/                       # Cookie
```

## Chrome 拡張機能との違い

| 機能 | Chrome 拡張 | Proxyman |
|------|:----------:|:-------:|
| HTTP トラフィックキャプチャ | ✓ | ✓ |
| MSL エンベロープデコード | ✓ | ✓ |
| マニフェスト抽出 | ✓ | ✓ (CLEAR のみ) |
| ALE 鍵抽出 | ✓ | ✓ (CLEAR のみ) |
| ESN 取得 | ✓ | ✓ |
| KID テーブル | ✓ | ✓ |
| Web Crypto API フック | ✓ | ✗ |
| EME セッション監視 | ✓ | ✗ |
| 暗号化ペイロードの復号 | ✓ | ✗ |
| プロファイルオーバーライド | ✓ | ✗ |
| 浮動パネル UI | ✓ | ✗ (Proxyman UI で確認) |

## トラブルシューティング

### `writeToFile` が動作しない
- Proxyman v3.6.2 以上か確認: **Proxyman > About Proxyman**
- ファイルパスに `~` を使用可（Proxyman が展開）

### MSL ペイロードがデコードできない
- SSL Proxying が有効か確認: **Certificate > Install Certificate on this Mac**
- Netflix アプリが Proxyman の CA 証明書を信頼しているか確認
- 暗号化スキームが CLEAR でない場合、ペイロード内容は暗号化されたまま（エンベロープの headerdata は読める）

### アドオンが見つからない
- `@users/` フォルダにファイルがあるか確認
- ファイル名が正確に `NetflixMSLParser.js` であるか確認
- Proxyman を再起動
