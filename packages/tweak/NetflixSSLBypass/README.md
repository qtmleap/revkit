# Netflix SSL Bypass Tweak

Netflix iOS の `appboot.netflix.com` に対する SSL ピンニングをバイパスする Orion tweak。

## 前提条件

- macOS + Xcode
- [Theos](https://theos.dev/docs/installation)
- iOS デバイス (rootless jailbreak: Dopamine 等)
- Orion runtime (`dev.theos.orion14`)

## セットアップ

```bash
# Theos 未導入の場合
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"

# Orion をインストール (Theos のプラグイン)
# https://orion.theos.dev/getting-started.html
```

## ビルド & インストール

```bash
cd packages/tweak/NetflixSSLBypass

# ビルドのみ
make package

# ビルド + インストール (SSH 経由)
make package install THEOS_DEVICE_IP=192.168.0.49
```

## バイパス対象

| Layer | クラス | メソッド | 操作 |
|-------|--------|---------|------|
| 1 | NflxTrustStore | evaluateTrust:error: | → YES |
| 2 | NflxPinnedCertEvaluator | hasPinnedCertForHost: | → NO |
| 2 | NflxPinnedCertEvaluator | evaluatePinnedCertificate:forHost: | → YES |
| 3 | IosMslClient | shouldUseSSLTrustStore | → NO |
| 3 | IosMslClient | updateNFURLSessionCerts: | → NOP |
| 4 | NFURLSession | setTrustStore: | → nil |
| 4 | NFURLSession | setPinnedCertificateEvaluator: | → nil |

## ログ確認

```bash
# デバイス上で
oslog --predicate 'eventMessage CONTAINS "NFXBypass"' --stream
```
