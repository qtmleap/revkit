# Netflix iOS 動画再生フロー

## API コールシーケンス (起動 → 動画再生)

| Phase | Step | Endpoint | Host | Protocol |
|-------|------|----------|------|----------|
| Boot | 1 | `GET /iosui/healthcheck/15.48` | ios.prod.ftl.netflix.com | HTTP/JSON |
| Boot | 2 | `GET /iosui/user/15.48` (cold start) | ios.prod.ftl.netflix.com | HTTP/JSON |
| Boot | 3 | `POST /appboot/NFAPPL-02-...` | appboot.netflix.com | CBOR (MSL) |
| Auth | 4 | `POST /graphql` (FTL) | ios.prod.ftl.netflix.com | HTTP/JSON |
| DRM | 5 | `POST /nq/iosplatform/pbo_license/.../router` | ios.prod.ftl.netflix.com | MSL (msl_v1) |
| UI | 6 | `POST /iosui/user/15.48` | ios.prod.ftl.netflix.com | HTTP/JSON |
| Catalog | 7 | `POST /graphql` (NGP) | ios.ngp.prod.cloud.netflix.com | HTTP/JSON |
| Telemetry | 8 | `POST /msl/playapi/ios/logblob` | ios.prod.cloud.netflix.com | MSL (msl_v1) |
| Catalog | 9 | `POST /graphql` (Cloud) | ios.prod.cloud.netflix.com | MSL (msl_v1) |
| Browse | 10 | `GET /iosui/warmer/15.48` (lolomo) | ios.prod.ftl.netflix.com | HTTP/JSON |
| Browse | 11 | `GET /iosui/user/15.48` (video metadata) | ios.prod.ftl.netflix.com | HTTP/JSON |
| Playback | 12 | `POST /msl/playapi/ios/manifest` | ios.prod.ftl.netflix.com | MSL (msl_v1) |
| Playback | 13-14 | `GET /iosui/user/15.48` (playback details) | ios.prod.ftl.netflix.com | HTTP/JSON |
| Network | 15-16 | `GET /ftl/probe` | ios.prod.ftl.netflix.com / oca-api.netflix.com | HTTP |
| Telemetry | 17 | `POST /cl2` | ichnaea-web.netflix.com | HTTP/JSON |
| DRM | 18 | `POST /nq/iosplatform/pbo_license/.../router` | ios.prod.ftl.netflix.com | MSL (msl_v1) |
| Stream | 19 | `GET /range/...` | *.oca.nflxvideo.net | HTTP (binary) |

## ホスト別役割

| Host | 役割 |
|------|------|
| ios.prod.ftl.netflix.com | UI API, GraphQL, マニフェスト, DRM ライセンス |
| ios.prod.cloud.netflix.com | MSL テレメトリ (logblob), GraphQL (MSL ラップ) |
| ios.ngp.prod.cloud.netflix.com | GraphQL (NGP カタログ) |
| appboot.netflix.com | アプリ初期設定 (ESN 登録, trust store 配信) |
| oca-api.netflix.com | OCA ネットワークプローブ |
| ichnaea-web.netflix.com | クライアントテレメトリ |
| *.oca.nflxvideo.net | CDN (動画/音声セグメント配信) |

## MSL vs Plain HTTP

- **MSL (Content-Encoding: msl_v1)**: manifest, logblob, pbo_license, cloud graphql
- **Plain HTTP/JSON**: iosui/*, appboot, FTL graphql, ftl/probe, cl2

## 依存関係

1. healthcheck + appboot → nfvdid Cookie, deviceIdToken 取得
2. iosui/user (cold start) → プロファイル・設定
3. graphql (FTL) → 認証 Cookie 必要 (NetflixId, SecureNetflixId)
4. pbo_license (releaseLicense) → 既存 DRM セッション解放
5. warmer/lolomo → 認証済みセッション必要
6. iosui/user (video paths) → 動画メタデータ取得
7. msl/playapi/ios/manifest → ESN, auth, メタデータ必要 → CDN URL 返却
8. OCA segments → マニフェストの CDN URL からストリーミング
