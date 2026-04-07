# Mobile RE Toolkit

Frida, Chrome 拡張機能, mitmproxy を使ったモバイルアプリのリバースエンジニアリング環境。

iOS, Android, Chrome の各プラットフォームにおけるアプリの通信プロトコル・認証フロー・DRM を動的解析するためのツールキット。解析対象ごとのフックスクリプトや解析結果は `targets/` 以下にサブモジュールとして管理し、本リポジトリは汎用ツール基盤として公開可能な構成になっている。

## 構成

```
.
├── packages/
│   ├── frida/                          # Frida フックスクリプト (TypeScript → JS)
│   │   ├── src/
│   │   │   ├── ios/                    #   iOS 用フック (ObjC/C++)
│   │   │   ├── android/                #   Android 用フック (Java/JNI)
│   │   │   ├── chrome/                 #   Chrome 用フック (CDM vtable 等)
│   │   │   └── common/                 #   共通ユーティリティ
│   │   └── package.json
│   ├── chrome-extension/               # Chrome 拡張 (Web Crypto/EME/HTTP キャプチャ)
│   │   ├── src/
│   │   └── manifest.json
│   └── proxyman/                       # Proxyman アドオン
│
├── tools/                              # Python ユーティリティ
│   ├── run.py                          #   Frida フック実行ランナー (iOS/Android)
│   ├── transformers/                   #   ログ変換 (Frida → 統一フォーマット)
│   │   ├── base.py                     #     共通 Transformer 基底クラス
│   │   ├── ios.py                      #     iOS 固有マッピング
│   │   └── android.py                  #     Android 固有マッピング
│   └── ...
│
├── handlers/                           # Objection ハンドラ (CommonCrypto, Security 等)
│
├── targets/                            # 解析対象 (サブモジュール, .gitignore)
│   └── <target-name>/                  #   対象固有のスクリプト・ドキュメント・ログ
│
├── docs/                               # 解析結果・仕様書
├── assets/                             # IPA/APK バイナリ (.gitignore)
├── raws/                               # Frida 生キャプチャログ (.gitignore)
└── logs/                               # 変換済みログ (.gitignore)
```

## 開発環境

DevContainer で構築済み。`Rebuild Container` で全ツールが揃う。

### ランタイム

| ツール | 用途 |
|---|---|
| Python 3.12 (uv) | ユーティリティ、ログ変換、解析スクリプト |
| Node.js | Frida スクリプトのビルド (frida-compile) |
| Bun | Chrome 拡張のビルド |
| Frida 17.x | 動的インストルメンテーション |
| mitmproxy | プログラマブル HTTPS プロキシ (コンテナ内で完結) |

### リバースエンジニアリング

| ツール | 用途 |
|---|---|
| radare2 | ARM64 逆アセンブル・バイナリ解析 |
| Ghidra (headless) | 擬似コード生成・関数解析 |
| jadx | Android APK → Java 逆コンパイル |
| apktool | Android APK リソース展開・smali |
| ipsw | iOS Mach-O 解析・ObjC/Swift クラスダンプ |
| lief (Python) | Mach-O/ELF バイナリパーサー |
| capstone (Python) | ARM64 ディスアセンブラ |

## 使い方

### ビルド

```bash
# Frida フックスクリプト
cd packages/frida
npm run build:ios       # → hook_netflix.js
npm run build:android   # → hook_netflix_android.js
npm run build:chrome    # → hook_chrome_cdm.js

# Chrome 拡張
cd packages/chrome-extension
bun run build
```

### キャプチャ実行

```bash
# iOS (起動中のアプリにアタッチ、未起動なら自動で spawn)
uv run python tools/run.py packages/frida/hook_netflix.js

# Android (spawn モード)
uv run python tools/run.py --android packages/frida/hook_netflix_android.js
```

`.env` にデバイスの IP を設定:

```
IOS_HOST=192.168.x.x
ANDROID_HOST=192.168.x.x
```

### ログ変換

Frida の生ログを統一フォーマット (Chrome 拡張互換) に変換:

```bash
python -m tools.transformers.ios raws/ios/20260404/capture.jsonl
python -m tools.transformers.android raws/android/20260404/capture.jsonl
```

### バイナリ解析

```bash
# iOS: ObjC/Swift クラスダンプ
ipsw macho info <binary> --class-dump

# iOS: 逆アセンブル (Python)
uv run python -c "import lief, capstone; ..."

# Android: APK 逆コンパイル
jadx -d /tmp/out <apk>

# Ghidra ヘッドレス解析
analyzeHeadless /tmp/project name -import <binary>
```

### HTTPS プロキシ

```bash
# コンテナ内でプロキシ起動
uv run mitmdump -p 8080 -s tools/mitmproxy_addon.py

# デバイス側: Wi-Fi プロキシを <コンテナIP>:8080 に設定
# Frida の SSL pinning bypass と併用
```

## 解析対象の追加

新しい解析対象を追加するには:

```bash
# targets/ 以下にサブモジュールとして追加
git submodule add <repo-url> targets/<target-name>
```

各 target リポジトリには対象固有の以下を含める:

- フックスクリプト (TypeScript)
- 解析結果ドキュメント
- プロトコル仕様書
- キャプチャログ・バイナリ等の秘匿データ
