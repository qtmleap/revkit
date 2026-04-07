# Project Overview

Netflix の通信プロトコル (MSL: Message Security Layer) と認証フロー (Cookie, ESN, Widevine DRM) を解析するプロジェクト。
Chrome, iOS, Android の各プラットフォームにおける Netflix アプリの内部動作を Frida フックやトラフィックキャプチャで調査し、MSL クライアントの Python 実装に知見を還元する。

## 解析対象プラットフォーム

| プラットフォーム | 手法 | 主要パッケージ |
|----------------|------|--------------|
| **Chrome (macOS)** | Frida で Widevine CDM (L3) の vtable をフック + Chrome 拡張で EME/Web Crypto/HTTP を監視 | `packages/chrome-extension/`, `packages/frida/hook_chrome_cdm.js` |
| **Android** | Frida で Cronet HTTP スタック・MSL CBOR・ESN 生成をフック。Cookie + PRV ESN をキャプチャ | `packages/frida/hook_netflix_android.js`, `packages/frida/hook_cronet.js`, `packages/frida/hook_msl.js` |
| **iOS** | Frida で Netflix iOS アプリの FairPlay DRM・MSL 通信をフック | `packages/frida/hook_netflix_ios.js` |
| **HTTP プロキシ** | Proxyman で MSL トラフィックをキャプチャ・デコード (CLEAR スキームのみ) | `packages/proxyman/` |

## リポジトリ構成

```
src/netflix_msl/          # Python MSL クライアント実装
packages/
  chrome-extension/       # Chrome 拡張 (EME/Web Crypto/HTTP フック + 浮動パネル UI)
  frida/                  # Frida フックスクリプト (TypeScript → JS ビルド)
  proxyman/               # Proxyman スクリプト + アドオン
docs/
  instructions/           # プラットフォーム別の解析結果・リファレンス
  netflix/                # Netflix 固有の仕様書
```

## 開発環境

- Python 3.12+ (uv で管理)
- Frida 17.x + frida-tools
- Node.js (Chrome 拡張ビルド用)

## Tweak 開発 (Theos/Orion)

Theos ビルド環境は `theos` サイドカーコンテナで動作する。app コンテナから直接 `make` は実行できない。

### ビルド

```bash
docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak名>
```

### クリーン

```bash
docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak名> clean
```

### パッケージ (.deb 生成)

```bash
docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak名> package
```

### デバイスへのインストール

```bash
# 初回のみ: SSH 公開鍵をデバイスに登録 (パスワード: alpine)
docker compose -f .devcontainer/compose.yaml exec theos ssh-copy-id -o PubkeyAuthentication=no root@<デバイスIP>

# 以降はパスワード不要
docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak名> package install THEOS_DEVICE_IP=<デバイスIP>
```

- Tweak 開発担当はコード変更後に必ずビルドが通ることを確認する
- ビルド成功後、対象デバイスへのインストールまで行う
- VS Code タスク (`theos: build`, `theos: clean`, `theos: package`) も利用可能

### 構成

- Tweak ソース: `packages/tweak/<tweak名>/`
- Dockerfile: `.devcontainer/theos/Dockerfile`
- ターゲット: iOS 15.0–16.5 (arm64, rootless)
- 対応フレームワーク: Logos (.x), Orion (.x.swift)

## コード規約

- Python: `uv run ruff format` でフォーマット
- 不明な点を推測で説明しない。分からないなら分からないと言う
- 変更前に影響範囲を全て確認してから回答する
