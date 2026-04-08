# 作業計画書: appboot DH 秘密鍵抽出 Tweak

日時: 2026-04-08T00:00:00+09:00

## 目標

Netflix iOS アプリの appboot リクエストで使用される DH 秘密鍵（および派生セッション鍵 enc_key / hmac_key）を iOS Tweak で抽出する。

## タスク一覧

### frida-engineer 担当 (Phase 1: 調査)

- [ ] F1: 既存スクリプト (`msl-crypto.ts`, `find_appboot.js`) の現状確認
- [ ] F2: `NFWebCrypto.framework` / `MslClient.framework` / `Nbp.framework` のエクスポートシンボル列挙 (`Module.enumerateExports()`)
  - DH 鍵生成関連シンボル (dhKeyGen, dhDerive, HKDF 等) の正確なマングル名を特定
- [ ] F3: Security.framework API vs 独自実装の判別
  - import テーブルから `SecKeyCreateRandomKey`, `CCDHCreate` 等のリンク有無を確認
- [ ] F4: ランタイムで DH 秘密鍵のメモリ形式を確認
  - `dhComputeSharedSecret` フック拡張、秘密鍵のポインタダンプ (形式: raw bignum / PKCS#8 / DER)
- [ ] F5: appboot フロー中のコールスタック取得 (`Thread.backtrace()`)
- [ ] F6: Tweak 開発者向け情報整理ドキュメント作成
  - シンボル名、オフセット、メモリ形式、フック方法をまとめる

### tweak-engineer 担当 (Phase 2: 実装)

- [ ] T1: 新規 Tweak `AppbootKeyExtract` のプロジェクト作成
  - Makefile, control, plist, ディレクトリ構成
  - Security フレームワークをリンク
- [ ] T2: フックアプローチの実装 (F6 の調査結果に基づき選択)
  - 案 A: `NFWebCrypto` C 関数シンボルフック (`MSHookFunction` + `dlsym`)
  - 案 B: `Security.framework` API フック (`SecKeyCreateRandomKey` 等)
  - 案 C: `IosSessionCryptoContext` vtable フック
- [ ] T3: ログ出力実装
  - プレフィックス `[NFXKey]`、NSLog で出力
  - DH 公開値、秘密鍵、enc_key、hmac_key を hex ダンプ
- [ ] T4: ビルド・デバイスインストール・動作確認

### log-monitor 担当 (Phase 3: 検証)

- [ ] L1: デバイスログ監視 (`[NFXKey]` プレフィックスのフィルタリング)
- [ ] L2: 鍵材料の出力確認・レポート

## 実行順序

1. **Phase 1 (調査)**: frida-engineer が F1-F6 を実行 → シンボル情報・フック方法を確定
2. **Phase 2 (実装)**: tweak-engineer が T1-T4 を実行（Phase 1 の結果に依存）
3. **Phase 3 (検証)**: log-monitor が L1-L2 で動作検証

※ Phase 1 完了後、調査結果をレビューしてから Phase 2 に進む

## 成果物

- `packages/tweak/AppbootKeyExtract/`: 新規 Tweak ソースコード
- `docs/spec/appboot_dh_symbols.md`: DH 関連シンボル調査結果
- デバイスログ: appboot 時の DH 秘密鍵・セッション鍵

## フックアプローチ候補

| 案 | 対象 | メリット | リスク |
|----|------|---------|--------|
| A: C 関数シンボルフック | `NFWebCrypto::dhKeyGen` | 直接的、正確 | シンボル非公開の可能性 |
| B: Security.framework API | `SecKeyCreateRandomKey` 等 | 確実にフック可能 | Netflix が使っていない可能性 |
| C: vtable フック | `IosSessionCryptoContext` | 派生鍵を直接取得 | バイナリ更新で壊れる |

## リスク・注意点

- Netflix アプリ更新でシンボルオフセットが変わる可能性
- C++ マングル名はコンパイラバージョンに依存
- DH 秘密鍵が `SecKey` でなく独自構造体の場合、Security.framework フックでは捕捉できない
- アプリクラッシュ時のデバッグのため、フックは段階的に有効化する
