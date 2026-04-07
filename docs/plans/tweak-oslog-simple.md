# 作業計画書: Netflix Tweak — os_log ロード確認

日時: 2026-04-07T00:00:00+09:00

## 目標

NetflixSSLBypass Tweak を Netflix アプリ (Argo) に適用し、ロード時に os_log でログを出力する簡潔な実装にする。ログ監視エージェントで動作確認を行う。

## タスク一覧

### tweak-engineer 担当

- [x] `Tweak.x.swift` を改修: NSLog → `Logger` (iOS 15+) に変更
  - サブシステム: `work.tkgstrator.argodecryptor`、カテゴリ: `tweak`
  - viewDidAppear フックのログも Logger に統一
- [x] `Tweak.m` の constructor に os_log でロード完了ログを追加
- [x] theos コンテナでビルド確認
- [x] デバイスにインストール (iproxy 経由)

### log-monitor 担当

- [x] SSH 疎通確認 (`ssh -p 2222 root@host.docker.internal`)
- [x] oslog でログ監視（3回実施）
- [x] Tweak ロード成功判定: `loaded` + `loaded (os_log)` 確認
- [x] viewDidAppear フックのログ捕捉確認: 6クラス分確認
- [x] 結果レポート

## 実行順序

1. **並列**: tweak-engineer (コード改修 → ビルド → インストール) + log-monitor (最初からログ監視開始)
2. log-monitor は tweak-engineer の完了を待たず、常時ストリーム監視を継続

## 成果物

- `packages/tweak/NetflixSSLBypass/Sources/NetflixSSLBypass/Tweak.x.swift`: os_log 対応版
- `packages/tweak/NetflixSSLBypass/Sources/NetflixSSLBypassC/Tweak.m`: ロードログ追加

## リスク・注意点

- SSH 接続にはホスト Mac で `iproxy 2222 22` が必要
- zsh の `log` ビルトインと衝突するため `command log` を使用
- Logger は iOS 14+ なのでターゲット (iOS 15.0) では問題なし
