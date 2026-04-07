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

DevContainer はDocker Desktop の Linux VM 内で動作するため、LAN 上のデバイス (iOS/Android) と直接通信できない。以下の設定で macOS を踏み台にして SSH / Frida を中継する。

### 1. リモートログインを有効化

**システム設定 → 一般 → 共有 → リモートログイン** をオンにする。

### 2. SSH 公開鍵を登録

コンテナ内の鍵を macOS の authorized_keys に追加する:

```bash
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
```

### 3. VS Code ポートフォワーディング設定

`.vscode/settings.json` に以下を追加して、mitmproxy のポートを LAN に公開する:

```json
"remote.localPortHost": "allInterfaces"
```

### 4. SSH config を設定

`~/.ssh/config` に以下を追加して、macOS を踏み台にした ProxyJump を設定する。

**エイリアスあり** (macOS ホストを再利用する場合):

```sshconfig
Host docker-host
  HostName host.docker.internal
  User <macOS のユーザー名>

Host iPhone
  HostName <デバイスの LAN IP>
  User root
  ProxyJump docker-host
  LocalForward 27042 127.0.0.1:27042
```

**エイリアスなし** (シンプルに一つで完結):

```sshconfig
Host iPhone
  HostName <デバイスの LAN IP>
  User root
  ProxyJump <macOS のユーザー名>@host.docker.internal
  LocalForward 27042 127.0.0.1:27042
```

**iproxy (USB 経由)** — macOS ユーザー名やデバイス IP が不要:

macOS 側で iproxy を起動しておく:

```bash
iproxy 2222 22 &
iproxy 27042 27042 &
```

SSH config:

```sshconfig
Host iPhone
  HostName host.docker.internal
  User root
  Port 2222
```

Frida は `frida -H 127.0.0.1` ではなく `frida -H host.docker.internal` で接続する。

### 接続経路

| 用途 | 方向 | 経路 |
|------|------|------|
| **SSH** | コンテナ → デバイス | `ssh iPhone` (ProxyJump で macOS を経由) |
| **Frida** | コンテナ → デバイス | `ssh -fN iPhone` でトンネル確立後、`frida -H 127.0.0.1` で接続 |
| **mitmproxy** | デバイス → コンテナ | デバイスのプロキシを macOS の LAN IP:9080 に設定 |

## 使い方

### Frida フック

```bash
# iOS (objection 経由で spawn)
uv run python tools/run.py packages/frida/<script>.js

# Android (spawn モード)
uv run python tools/run.py --android packages/frida/<script>.js
```

`.env` にデバイスの IP を設定:

```
IOS_HOST=192.168.x.x
ANDROID_HOST=192.168.x.x
```

### mitmproxy

```bash
uv run mitmdump -p 8080 -s packages/mitmproxy/<addon>.py
```

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
