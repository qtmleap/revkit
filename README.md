# revkit

iOS / Android アプリのリバースエンジニアリングツールキット。

- **iOS Tweak 開発** — Theos/Orion による Substrate Tweak のビルド・デプロイ (arm64, rootless)
- **Frida フック** — iOS / Android アプリのランタイム解析・動的インストルメンテーション
- **mitmproxy** — HTTPS トラフィックキャプチャ・プロトコルデコード
- **バイナリ解析** — Ghidra, radare2, jadx, ipsw による APK / IPA の静的解析

## 構成

```
.
├── packages/
│   ├── frida/                  # Frida フックスクリプト (TypeScript → JS)
│   │   └── src/
│   │       ├── ios/            #   iOS 用フック (ObjC/C++)
│   │       ├── android/        #   Android 用フック (Java/JNI)
│   │       └── common/         #   共通ユーティリティ
│   ├── mitmproxy/              # mitmproxy アドオン
│   └── tweak/                  # iOS Tweak (Theos/Orion)
│
├── tools/                      # Python ユーティリティ
│   ├── run.py                  #   Frida フック実行ランナー
│   ├── transformers/           #   ログ変換 (Frida → 統一フォーマット)
│   └── ...
│
├── handlers/                   # Objection ハンドラ (CommonCrypto, Security 等)
├── docs/                       # 解析結果・仕様書
├── assets/                     # IPA/APK バイナリ (.gitignore)
├── raws/                       # Frida 生キャプチャログ (.gitignore)
└── logs/                       # 変換済みログ (.gitignore)
```

## 開発環境

DevContainer で構築済み。`Rebuild Container` で全ツールが揃う。

### ランタイム

| ツール | 用途 |
|---|---|
| Python 3.12 (uv) | ユーティリティ、ログ変換、解析スクリプト |
| Node.js 25.x | Frida スクリプトのビルド (frida-compile) |
| Bun | Chrome 拡張のビルド |
| Frida 17.x | 動的インストルメンテーション |
| mitmproxy | プログラマブル HTTPS プロキシ |

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
| unicorn (Python) | CPU エミュレーション |
| pywidevine (Python) | Widevine DRM 解析 |

### iOS Tweak 開発

| ツール | 用途 |
|---|---|
| Theos | Tweak ビルドシステム |
| Orion | Swift Tweak フレームワーク |
| Swift 5.8 (cross-compile) | iOS 向けクロスコンパイル |
| iOS SDK 15.6 / 16.5 | ビルドターゲット |

## macOS ホスト設定

DevContainer は Docker Desktop の Linux VM 内で動作するため、iOS デバイスと直接通信できない。USB 接続の iproxy を経由することで、WiFi の IP 変更やネットワーク不安定の影響を受けずに接続できる。

### 1. iproxy のインストール (macOS)

```bash
brew install libimobiledevice
```

### 2. iproxy の起動 (macOS)

iPhone を USB で接続した状態で:

```bash
iproxy 2222 22 &
iproxy 27042 27042 &
```

- `2222 → 22`: SSH 接続用
- `27042 → 27042`: Frida 接続用

### 接続経路

| 用途 | 方向 | 経路 |
|------|------|------|
| **SSH** | コンテナ → デバイス | `ssh iPhone` → `host.docker.internal:2222` → iproxy (USB) → デバイス:22 |
| **Frida** | コンテナ → デバイス | `frida -H host.docker.internal` → iproxy (USB) → デバイス:27042 |
| **mitmproxy** | デバイス → コンテナ | デバイスの WiFi プロキシを macOS の LAN IP:9080 に設定 |

## 使い方

### Frida フック

```bash
# iOS (objection 経由で spawn)
uv run python tools/run.py packages/frida/<script>.js

# Android (spawn モード)
uv run python tools/run.py --android packages/frida/<script>.js
```

`.env` にデバイスのホストを設定 (iproxy 経由の場合は `host.docker.internal`):

```
IOS_HOST=host.docker.internal
ANDROID_HOST=192.168.x.x
```

### mitmproxy

#### デバイス側の設定

1. デバイスの WiFi プロキシを macOS の LAN IP、ポート `9080` に設定
2. デバイスのブラウザで `http://mitm.it` にアクセスし、CA 証明書をインストール
   - iOS: 設定 → 一般 → VPN とデバイス管理 → mitmproxy をインストール → 設定 → 一般 → 情報 → 証明書信頼設定 で有効化

#### 起動

```bash
uv run mitmdump --listen-port 9080 --set block_global=false \
    -s packages/mitmproxy/<addon>.py
```

アドオンは `packages/mitmproxy/` に配置。

### iOS Tweak (Theos)

```bash
# ビルド
make -C packages/tweak/<tweak名>

# パッケージ (.deb 生成)
make -C packages/tweak/<tweak名> package

# デバイスへのインストール
make -C packages/tweak/<tweak名> package install THEOS_DEVICE_IP=<デバイスIP>
```

### バイナリ解析

```bash
# iOS: ObjC/Swift クラスダンプ
ipsw macho info <binary> --class-dump

# Android: APK 逆コンパイル
jadx -d /tmp/out <apk>

# Ghidra ヘッドレス解析
analyzeHeadless /tmp/project name -import <binary>
```

## Claude Code スキル

本プロジェクト固有のスラッシュコマンド。Claude Code 内で使用できる。

| コマンド | 説明 |
|---------|------|
| `/compose` | Agent Teams のリーダーとしてチームを編成し、計画策定→承認→実行のワークフローを開始する |

### エージェント

`/compose` から呼び出される専門エージェント。

| エージェント | 担当 |
|-------------|------|
| `tweak-engineer` | iOS Tweak 開発 (Orion/Theos, ElleKit C フック) |
| `frida-engineer` | Frida フックスクリプト、ランタイム解析 |
| `mitmproxy-engineer` | mitmproxy アドオン、トラフィックキャプチャ |
| `python-engineer` | Python ユーティリティ、デコーダー、データ処理 |
| `log-monitor` | Frida/mitmproxy/Tweak のログ監視・レポート |
