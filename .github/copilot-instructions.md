# プロジェクト概要

Netflix iOS/Androidアプリのリバースエンジニアリングプロジェクト。
対象アプリが送信するHTTPリクエストの安全性を検証するため、暗号化されたリクエストボディの復号に必要な鍵・アルゴリズムを特定する。

## 対象アプリ

- アプリ名: Netflix
- Bundle ID (iOS): `com.netflix.Netflix`
- Bundle ID (Android): `com.netflix.mediaclient`

## 環境構成

| 項目 | バージョン / 値 |
|---|---|
| Python | 3.12（パッケージ管理: uv） |
| Frida | 17.8.0 |
| Objection | 1.12.3 |

### 対象デバイス

| デバイス | OS | ホスト |
|---|---|---|
| iPhone (Jailbroken) | iOS 15.8.3 | `192.168.0.34` |
| Pixel 4a (5G) / `bramble` | Android 14 (API 34) | `192.168.0.37` |

# ドキュメント運用

## 保存先

ドキュメント作成を指示された場合、以下の2種類を必ず作成すること:

| 種別 | 保存先 | 形式 |
|---|---|---|
| LLM向け | `.github/instructions/{名前}.instructions.md` | frontmatterに `applyTo` を記述し、関連ファイルパターンを指定。構造化された簡潔な形式 |
| 人間向け | `docs/{名前}.md` | 散文形式。図解にはMermaid記法を使用し、テーマは `%%{init: {'theme': 'dark'}}%%` を指定すること |

## 制約

- 1ファイルが400行を超える場合は、指示がなくてもトピック単位で分割すること
- ファイル名はスネークケースを使用すること
- ドキュメントを作成した際は、ファイル末尾に作成日時と更新日時を分単位で記載すること（例: `作成: 2026-03-14 15:30` / `更新: 2026-03-14 16:45`）

## 主要ドキュメント一覧

LLM向けの詳細コンテキストは以下を参照すること:

- `.github/instructions/*.instructions.md` — ファイルスコープ付きLLM向け指示（`applyTo` で適用先を指定）
- `docs/` — 人間向けドキュメント

| パス | 内容 |
|---|---|
| `docs/msl_ios.md` | iOS MSLプロトコルの構造・暗号スタック |
| `docs/msl_android.md` | Android MSLプロトコルの構造 |
| `docs/manifest_ios.md` | iOSマニフェスト仕様 |
| `docs/manifest_android.md` | Androidマニフェスト仕様 |
| `docs/auth_flow_android.md` | Android認証フロー |
| `docs/esn_android.md` | Android ESN仕様 |
| `docs/pxa_esn.md` | PXA ESN仕様 |

# ツール使用ルール

## Objection

> **重要**: 以下の非推奨コマンド・オプションをコード生成やコマンド提案で絶対に使用しないこと。

| 禁止 | 代替 | 説明 |
|---|---|---|
| `explore` | `start` | アプリへの接続コマンド |
| `--gadget` / `-g` | `--name` / `-n` | 対象アプリ指定オプション |

正しい使用例:

```bash
objection -n "com.netflix.Netflix" start
```

## Frida

- コマンド実行時は必ず `-H <ホストIP>` を指定して対象デバイスに接続すること
  - iOS: `-H 192.168.0.34`
  - Android: `-H 192.168.0.37`
- 実行中アプリ一覧の確認: `frida-ps -H <ホストIP> -a`

# アーキテクチャ

## 目的

対象アプリの暗号化通信（MSL等）をFridaでフックし、暗号化前の平文データ・復号済みデータ・暗号鍵・IVなどを取得する。

## JS / Python の役割分担

| レイヤー | ファイル | 責務 |
|---|---|---|
| JavaScript (Frida) | `hook_*.js` | 対象アプリのプロセス内で動作。暗号関数・API呼び出しをフックし、引数や戻り値（鍵・IV・平文・暗号文など）を `@@LOG@@{json}` 形式で `console.log` に出力する。**データの加工・保存はしない。** |
| Python (ホスト) | `run.py` | Fridaプロセスを起動・管理する。stdout から `@@LOG@@` プレフィクス付きの行をパースし、ドメイン別・イベント別にJSON/バイナリファイルとして `logs/` に保存する。MSL平文とHTTPリクエストの紐付け、Cookie/ヘッダの自動エクスポートも行う。 |

### ログプロトコル

JavaScript側は以下の形式で標準出力にログを送る:

```
@@LOG@@{"event":"msl.aesCbcEncrypt.key","key_b64":"...","ts":"..."}
```

- プレフィクス `@@LOG@@` に続くJSON文字列をPython側がパースする
- `event` フィールドでイベント種別を識別する
- バイナリデータは `_b64`（Base64）または `_hex`（16進数）サフィックスのフィールドで渡す

### シグナルハンドリング

`run.py` は `SIGINT` / `SIGTERM` を捕捉し、Fridaサブプロセスを安全に終了させる（`terminate` → 3秒待機 → `kill`）。Ctrl+C での中断時もログの集計とCookie/ヘッダのエクスポートが `finally` ブロックで実行される。フックスクリプト作成時は、JS側での終了処理は不要（Python側が管理する）。

## コード構成

| パス | 役割 |
|---|---|
| `hook_netflix.js` | iOS用フックスクリプト（ObjC/C++関数のフック） |
| `hook_netflix_android.js` | Android用フックスクリプト（Java/JNIメソッドのフック） |
| `hook_msl.js` | MSL暗号関数の個別フック |
| `hook_cronet.js` | Cronetネットワーク層のフック |
| `hook_esn.js` | ESN取得用フック |
| `hook_headers.js` | HTTPヘッダ/Cookie取得用フック |
| `run.py` | メインランナー（iOS/Android両対応、`--android` フラグで切替） |
| `run_android.sh` | Android用シェルラッパー |
| `run_cronet.py` | Cronet用ランナー |
| `__handlers__/` | Objectionハンドラ |

## 新しいフックを書くときの方針

1. **静的解析で対象関数を特定する**: フックを書く前に、アプリのバイナリを静的解析して目的の関数・メソッドを探すこと。推測でフック対象を決めてはならない
   - iOS: `strings`, `nm --demangle`, `class-dump` 等でMach-Oバイナリからシンボル・クラス・セレクタを抽出する
   - Android: `jadx` でAPK/DEXを逆コンパイルし、クラス名・メソッドシグネチャを確認する。ProGuardで難読化されている場合は既存フックのコメントにあるマッピングを参照する
2. **JS側**: 対象関数をフックし、取得したデータを `@@LOG@@{json}` で出力するだけにする
3. **Python側**: ログのパース・整形・保存・紐付けロジックは `run.py` に集約する
4. バイナリデータはJS側でBase64または16進数に変換してからログに含める
5. 終了処理はPython側が担うため、JS側で `Script.on('unload')` 等の後処理は基本不要
