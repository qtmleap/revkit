# 作業計画書: AppDelegate フック完成

日時: 2026-04-07T00:00:00+09:00

## 目標

Netflix iOS アプリの AppDelegate クラス名を特定し、Tweak のフックを正しく動作させる。

## タスク一覧

### tweak-engineer 担当

- [x] `targetName` を `"NetflixApp.AppDelegate"` → `"AppDelegate"` に修正 (ObjC クラス)
- [x] `ClassHook<UIResponder>` → `ClassHook<NSObject>` に修正 (UIResponder だとフック失敗)
- [x] ビルド確認
- [x] デバイスへインストール (scp + dpkg)

### frida-engineer 担当

- [x] クラス名調査スクリプト作成 (`packages/frida/check_appdelegate.js`)
- [x] Tweak の constructor 内で ObjC runtime API を使って確認 (Frida 接続が不安定だったため代替手法)
- [x] 結果: クラス名は `AppDelegate` (ObjC クラス、Swift mangled なし)

### log-monitor 担当

- [x] `raws/oslog/charon_2026-04-07.log` で確認
- [x] `[NFXBypass] AppDelegate didBecomeActive` の出力確認済み

## 判明した事実

- AppDelegate のクラス名: `AppDelegate` (純粋な ObjC クラス)
- `ClassHook<UIResponder>` だと Tweak ロード自体が失敗する → `ClassHook<NSObject>` が正しい
- その他の AppDelegate 関連クラス: `SwiftUI.AppDelegate`, `SwiftUI.TestingAppDelegate`

## 成果物

- `packages/tweak/NetflixSSLBypass/Sources/NetflixSSLBypass/Tweak.x.swift`: AppDelegate フック修正済み
- `raws/oslog/charon_2026-04-07.log`: 動作確認ログ
