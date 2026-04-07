# Netflix MSL Capture (Proxyman)

macOS 上の Proxyman を使い、Chrome ブラウザ経由で Netflix の MSL (Message Security Layer) トラフィックをキャプチャ・解析するスキル。

## トリガー条件

- ユーザーが Proxyman スクリプトのセットアップ・修正を依頼したとき
- Netflix の MSL 通信をキャプチャ・解析したいとき
- キャプチャ済みの NDJSON / JSONL ログを解析・整理したいとき
- Chrome 拡張と Proxyman の違いについて聞かれたとき

## 主要ファイル

| ファイル | 役割 |
|---------|------|
| `packages/proxyman/netflix-msl-capture.js` | Proxyman スクリプト本体 (リクエスト/レスポンスフック) |
| `packages/proxyman/addons/NetflixMSLParser.js` | Proxyman カスタムアドオン (MSL デコード) |
| `packages/proxyman/README.md` | セットアップ手順・出力仕様 |

## 関連ドキュメント

| ドキュメント | 内容 |
|-------------|------|
| `docs/instructions/netflix/msl_capture_analysis.md` | MSL 通信フロー解析 (70 イベントのタイムライン) |
| `docs/instructions/netflix/stream_kid_memo.md` | ストリーム KID・PSSH・解像度マッピング |
| `docs/instructions/chrome/cdm_hook.md` | Chrome Widevine CDM L3 フック手順 |

## Proxyman の機能範囲

Proxyman は **HTTP レイヤー** のキャプチャツール。できること/できないことを把握しておくこと。

- **可能**: MSL エンベロープのデコード、CLEAR スキームのマニフェスト・ALE 鍵抽出、ESN 取得、KID テーブル生成
- **不可**: Web Crypto API フック、EME セッション監視、暗号化ペイロードの復号 (これらは Chrome 拡張が必要)

## セットアップ手順

1. `packages/proxyman/addons/NetflixMSLParser.js` を Proxyman のカスタムアドオンフォルダにコピー
2. Proxyman の Script List で新規スクリプトを作成し、URL ルール `*netflix.com/nq/msl_v1/*` を設定
3. `packages/proxyman/netflix-msl-capture.js` の内容をスクリプトエディタに貼り付け
4. Request / Response 両方を有効化
5. SSL Proxying を `*.netflix.com` に対して有効化

## 出力構成

```
~/Desktop/netflix-msl-capture/
  capture_log.jsonl       # 全キャプチャの JSONL ログ
  esn.txt                 # 最後にキャプチャした ESN
  raw/                    # 生のレスポンスボディ
  msl/                    # デコード済み MSL メッセージ (JSON)
  manifests/              # マニフェスト + KID テーブル
  keys/                   # ALE 鍵
```

## スクリプト修正時の注意

- Proxyman v3.6.2 以上が必要 (`writeToFile` / `readFromFile` API)
- ファイルパスに `~` を使用可 (Proxyman が展開)
- 暗号化スキームが CLEAR でない場合、ペイロード内容は暗号化されたまま (headerdata のみ読める)
