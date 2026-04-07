# Netflix MSL クライアント実装仕様書

プラットフォーム別に分割済み。以下を参照:

| ファイル | 内容 |
|---------|------|
| [spec/00_common.md](spec/00_common.md) | 共通仕様 (MSL プロトコル、マニフェスト構造、セグメントダウンロード、復号) |
| [spec/01_chrome.md](spec/01_chrome.md) | Chrome (Widevine EME、AV1、LZW 圧縮) |
| [spec/02_android.md](spec/02_android.md) | Android (Widevine L1/L3、APPBOOT ESN、Cronet) |
| [spec/03_ios.md](spec/03_ios.md) | iOS (FairPlay SPC/CKC、二重 ESN、HLS) |
| [spec/04_streamfab.md](spec/04_streamfab.md) | StreamFab/CEF (コーデック探索、licensedmanifest 復号、偽装パラメータ) |

実トラフィックキャプチャ (Proxyman + StreamFab アプリログ, 2026-04-05) を復号・解析して得た実測値に基づく。
