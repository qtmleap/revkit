# Netflix iOS 認証・マニフェスト・ライセンス取得フロー詳細

キャプチャ日: 2026-04-04 〜 2026-04-06  
デバイス: iPhone 9 (IPHONE9-1 / saget)  
アプリバージョン: Argo 15.48.1  
iOS バージョン: 15.8.3  
SDK: 2012.4  

---

## 1. 全体フロー概要

アプリ起動からビデオ再生開始までの API コールシーケンス:

```
Phase 0: アプリ起動
  ├── GET  /iosui/healthcheck/15.48         (ios.prod.ftl.netflix.com)
  ├── GET  /iosui/user/15.48?appStartType=cold  (ios.prod.ftl.netflix.com)
  └── POST /appboot/NFAPPL-02-IPHONE9=1-   (appboot.netflix.com) ← CBOR/MSL

Phase 1: セッション確立
  ├── POST /graphql                          (ios.prod.ftl.netflix.com) ← Cookie 必須
  ├── POST /nq/iosplatform/pbo_license/~1.0.0/router (releaseLicense)
  ├── POST /iosui/user/15.48
  └── POST /msl/playapi/ios/logblob          (ios.prod.cloud.netflix.com) ← MSL

Phase 2: カタログ閲覧
  ├── POST /graphql x N                     (cloud/NGP/FTL) ← 多数, 多くは 500 エラー
  ├── GET  /iosui/warmer/15.48              (ios.prod.ftl.netflix.com)
  └── POST /graphql                         (ios.prod.ftl.netflix.com)

Phase 3: 動画再生
  ├── POST /msl/playapi/ios/manifest        (ios.prod.ftl.netflix.com) ← MSL msl_v1
  ├── POST /nq/iosplatform/pbo_license/~1.0.0/router (prefetch/license) ← MSL
  ├── POST /msl/playapi/ios/event           (ios.prod.ftl.netflix.com) ← MSL
  └── GET  *.oca.nflxvideo.net              CDN セグメント

Phase 4: 再生中テレメトリ
  ├── POST /msl/playapi/ios/logblob x N     (ios.prod.cloud.netflix.com) ← MSL
  └── POST /cl2                             (ichnaea-web.netflix.com)
```

---

## 2. 認証フロー

### 2.1 appboot

**エンドポイント:** `POST https://appboot.netflix.com/appboot/{ESN_PREFIX}?keyVersion=1`

appboot はアプリ起動時に毎回呼ばれ、セッション鍵の交換・nfvdid Cookie の取得・deviceIdToken の取得を担う。

#### リクエストヘッダー

```
X-Netflix.APIAction: appboot
X-Netflix.client.ftl.esn: NFAPPL-02-IPHONE9=1-PXA-0202QNLQD8VD6TCRRNRI2OG2OPICNFJLEF570TVLF9DQ39EONO97LJKBT2BPB8SQA04VPAHGF6NE4RDCV0F7OJSI46KO12RM3ABRB581
X-Netflix.Request.Attempt: 1
X-Netflix.Request.Client.Context: {"appState":"foreground"}
Content-Type: application/x-www-form-urlencoded
User-Agent: Netflix/24 CFNetwork/1335.0.3.4 Darwin/21.6.0
```

注意: `Content-Type` は `application/json` **ではなく** `application/x-www-form-urlencoded`。  
ボディは CBOR 形式の MSL メッセージ (8,675 bytes 程度)。

#### リクエスト CBOR 構造 (デコード例)

MSL デコーダーで解析した結果:

```json
{
  "format": "cbor",
  "messages": [
    {
      "entityauthdata": {
        "scheme": "FAIRPLAY_MGK_APPID",
        "authdata": {
          "apphmac": "a18bf28fa9ef4838eab3767523638dd4...",
          "appid": "a2becfec-b286-535c-b884-903a384caee6",
          "appkeyversion": 1,
          "devicetoken": "0608a1b7ebdc0312bc01...<hex>",
          "esn_prefix": "NFAPPL-02-IPHONE9=1-",
          "esn": "NFAPPL-02-IPHONE9=1-AD0455EF27D3A7B8F0872932FD9837874AF3E6F90157195BD22A8063FEB0B79E",
          "device_key_data": "<bytes:6576>"
        }
      },
      "header": {
        "renewable": "010100810001012022b1205c03...",
        "capabilities": {
          "10": "<codec_data>",
          "94": {"95": true},
          "11": 1775490174,
          "12": 2195053559663813,
          "13": 1776613374,
          "14": 3
        }
      },
      "payload": {
        "keyid": "NFAPPL-02-IPHONE9=1-AD0455EF27D3A7B8..._3",
        "ciphertext_or_scheme": [18],
        "sha256_or_hmac": "a97e47477522ab39...",
        "iv_or_keydata": ""
      }
    }
  ]
}
```

**CBOR フィールド解説:**

| フィールド | 内容 |
|-----------|------|
| `scheme` | `FAIRPLAY_MGK_APPID` — iOS 固有の Entity Auth スキーム |
| `apphmac` | アプリ認証 HMAC (SHA-256 hex) |
| `appid` | アプリ識別子 (UUID 形式) |
| `appkeyversion` | 鍵バージョン (= URL クエリの `keyVersion=1`) |
| `devicetoken` | デバイストークン (hex エンコード)。サーバーに渡すデバイス認証情報 |
| `esn_prefix` | `NFAPPL-02-IPHONE9=1-` (モデル識別子) |
| `esn` | PRV ESN (Private ESN) — MSL 通信用 |
| `device_key_data` | デバイス固有鍵データ (~6,576 bytes)。Irdeto TFIT ホワイトボックス AES-128 で保護 |
| `renewable` | MSL セッション更新フラグ + マスタートークン候補 |
| `capabilities.10` | コーデック/プロファイルケイパビリティ (大きなバイト列) |
| `capabilities.94.95` | true = 拡張機能フラグ |
| `capabilities.11-14` | 数値フラグ (用途不明) |

#### レスポンスヘッダー

```
Content-Type: application/x-msl+json
Set-Cookie: nfvdid=BQFmAAEBEMYkqQ1UhvY3YKq-...%3D%3D; Domain=.netflix.com; Path=/; Max-Age=31536000
x-netflix-deviceidtoken: Bgiht+vcAxK8AQdGEPjoUt/i6NMYqUIk0m46t8cabsYD+...
X-Netflix.nfstatus: 1_1
```

**重要な出力:**

| 項目 | 取得先 | 用途 |
|-----|--------|------|
| `nfvdid` Cookie | `Set-Cookie` ヘッダー | 以降の全リクエストに付与 |
| `x-netflix-deviceidtoken` | レスポンスヘッダー | デバイス ID トークン (base64) |

appboot レスポンスは CBOR 形式の暗号化されたペイロードを返す (1,643 bytes)。復号後に `ssltruststore` 等の設定が含まれると推測される (appboot_pinning_analysis.md 参照)。

#### 失敗ケース

`keyVersion=1` の appboot が `HTTP 400` を返す場合がある (20260406 最初のセッション: seq=4 → 400)。これはデバイストークンの再発行や接続エラーによるもの。2回目の appboot 呼び出し (seq=4 @ 09:42) では `HTTP 200` を返している。

### 2.2 二重 ESN 体系

iOS は **PXA ESN** と **PRV ESN** の2種類の ESN を使い分ける:

| ESN 種別 | 形式 | 用途 |
|---------|------|------|
| **PXA (Proxy Auth)** | `NFAPPL-02-IPHONE9=1-PXA-0202{hash}` | HTTP 直接通信 (Falcor UI, GraphQL) |
| **PRV (Private)** | `NFAPPL-02-IPHONE9=1-{hash}` | MSL 通信 (manifest, license) |

PXA ESN は `X-Netflix.client.ftl.esn` ヘッダーとして全 HTTP リクエストに含まれる。  
PRV ESN は MSL メッセージの `entityauthdata.authdata.esn` フィールドと、ライセンス URL の `&esn=` パラメータに使用される。

**実キャプチャ値 (20260406):**
```
PXA: NFAPPL-02-IPHONE9=1-PXA-0202QNLQD8VD6TCRRNRI2OG2OPICNFJLEF570TVLF9DQ39EONO97LJKBT2BPB8SQA04VPAHGF6NE4RDCV0F7OJSI46KO12RM3ABRB581
PRV: NFAPPL-02-IPHONE9=1-AD0455EF27D3A7B8F0872932FD9837874AF3E6F90157195BD22A8063FEB0B79E
```

### 2.3 Cookie の種類と取得元

| Cookie 名 | 取得元 | 用途 | MSL リクエストでの扱い |
|----------|--------|------|----------------------|
| `nfvdid` | appboot/healthcheck `Set-Cookie` | デバイス識別 | 全 MSL リクエストの `Cookie` ヘッダーに含める |
| `NetflixId` | ログイン後 (外部取得) | ユーザー認証 | FTL GraphQL / iosui リクエストに含める |
| `SecureNetflixId` | ログイン後 (外部取得) | ユーザー認証 (HMAC 付き) | FTL GraphQL / iosui リクエストに含める |

**実キャプチャ値 (20260406):**

```
nfvdid=BQFmAAEBEEyzI9hpfD5J1wHxkttQdc5gIg0pYKWpOEZsFL0y6urcGEnankAM2xZdUZ_Mqeh5Xd2cne6Jy78Vs-xljfljtAiTaDzAOxYWUee-M9npCqHcQltnbAuXE8YS13gu0XTiHCY0WcPMydqLcTVz6x6hE2AW

NetflixId=v%3D3%26ct%3DBgjHlOvcAxLDA_ZHLaqvoBF_dhsoUpk4GRNTOE1Aspy3i4O29JhuISanHwv8nNkm9Pt-MO7vEWMnxjTitquHDo_Xwfu6uwnDT0ar2pA240HGb1WsvHKK67qEDQ6hRMzPr8dhHQYpKvK0bpcwcrP2KE9jNzFdODeHPQf...pg%3DZEULH5S2GNGCRAABCSG6J2EGGA%26ch%3DAQEAEAABABTp79nN9l_2MuRhqTXl0-SjAqcm83QU8vw.

SecureNetflixId=v%3D3%26mac%3DAQEAEQABABTxXNCkto3HXTSU1QQWHAZJOwIsbhLOMnQ.%26dt%3D1775465271021
```

`nfvdid` は healthcheck レスポンスでも新規発行される。appboot の `Set-Cookie` で更新される値が最終的に使用される値となる。

### 2.4 全 HTTP リクエスト共通ヘッダー

MSL エンドポイント (manifest, logblob, pbo_license) で共通:

```
Content-Encoding: msl_v1
Content-Type: application/json
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
User-Agent: Netflix/24 CFNetwork/1335.0.3.4 Darwin/21.6.0
X-Netflix.client.type: argo
X-Netflix.client.appversion: 15.48.1
X-Netflix.client.iosversion: 15.8.3
X-Netflix.client.idiom: phone
X-Netflix.client.ftl.esn: {PXA_ESN}
X-Netflix.request.client.context: {"appState":"foreground"}
X-Netflix.request.attempt: 1
X-Netflix.request.expiry.timeout: 15000
X-AllowCompression: false
X-Netflix.argo.translated: true
Cookie: nfvdid={nfvdid_value}
```

Falcor/GraphQL (UI) エンドポイントでは追加で:

```
X-Netflix.context.profile-guid: ZEULH5S2GNGCRAABCSG6J2EGGA
X-Netflix.context.ui-flavor: argo
X-Netflix.context.sdk-version: 2012.4
X-Netflix.context.form-factor: phone
X-Netflix.context.app-version: 15.48.1
X-Netflix.context.os-version: 15.8.3
X-Netflix.context.pixel-density: 2.0
X-Netflix.context.max-device-width: 375
X-Netflix.request.client.user.guid: ZEULH5S2GNGCRAABCSG6J2EGGA
Cookie: NetflixId=...; SecureNetflixId=...; nfvdid=...
```

---

## 3. マニフェスト取得フロー

### 3.1 エンドポイント

| ホスト | URL | 備考 |
|--------|-----|------|
| `ios.prod.ftl.netflix.com` | `POST /msl/playapi/ios/manifest` | 通常使用 (20260406 キャプチャ) |
| `ios.prod.cloud.netflix.com` | `POST /msl/playapi/ios/manifest` | 20260405 キャプチャでも確認 |

### 3.2 リクエストヘッダー

```
Content-Encoding: msl_v1
Content-Type: application/json
X-Netflix.client.request.name: manifest          # または prefetch/manifest
X-Netflix.pbobrahv: 6                             # マニフェスト用固定値
X-Netflix.argo.nfnsm: 3
X-Client-Request-Id: 4702703437841032             # ランダム uint64
X-Netflix.client.ftl.esn: {PXA_ESN}
Cookie: nfvdid={nfvdid_value}
Content-Length: 2946                              # 約 2,946 〜 2,994 bytes
```

**request.name の種類:**
- `manifest` — 通常の manifest 取得
- `prefetch/manifest` — プリフェッチ (レスポンスが大きい: ~97KB vs ~67KB)

### 3.3 MSL ラッピング (Content-Encoding: msl_v1)

リクエストボディは CBOR 形式の MSL メッセージ:

```json
{
  "format": "cbor",
  "messages": [
    {
      "header": {
        "renewable": "...",
        "capabilities": { "10": "...", "94": {"95": true}, ... }
      },
      "payload": {
        "keyid": "{PRV_ESN}_3",
        "ciphertext_or_scheme": "b75aa851ed932ae8...",
        "sha256_or_hmac": "02948f9b5b548db3...",
        "iv_or_keydata": ""
      },
      "signature": "30f31233815cea01..."
    }
  ]
}
```

`keyid` のサフィックス `_3` は session key ID を示す。  
`payload.ciphertext_or_scheme` に AES-CBC 暗号化されたリクエスト本体が含まれる。

### 3.4 リクエスト本体 (MSL デコード後)

```json
{
  "mslTimeout": null,
  "body": {
    "url": "/manifest",
    "version": 2,
    "preferredlanguages": {
      "appselectedlanguages": ["en-JP", "en"],
      "platformselectedlanguages": ["en-JP"]
    },
    "params": [
      {
        "viewableId": 81639725,
        "drmType": "fairplay",
        "flavor": "PRE_FETCH",
        "manifestVersion": "v2",
        "platform": "2012.4",
        "sdk": "2012.4",
        "build": 24,
        "clientVersion": "15.48.1",
        "hardware": "IPHONE9-1",
        "osName": "iOS",
        "osVersion": "15.8.3",
        "uiPlatform": "ios",
        "netType": "wifi",
        "cellularCap": "auto",
        "useHttpsStreams": true,
        "supportsPartialHydration": true,
        "supportsWatermark": true,
        "supportsSecureStop": false,
        "supportsUnequalizedDownloadables": true,
        "supportsAdBreakHydration": true,
        "supportsPreReleasePin": true,
        "liveMetadataFormat": "HLS",
        "contentPlaygraph": ["start"],
        "unletterboxed": false,
        "requiresAudioTrackGroups": true,
        "preferAssistiveAudio": false,
        "prefersClosedCaptions": false,
        "desiredVmaf": "phone_plus_lts",
        "xid": "6561032184169739597",
        "profiles": [
          "h264hpl22-dash-playready-live",
          "h264hpl30-dash-playready-live",
          "h264hpl31-dash-playready-live",
          "h264hpl40-dash-playready-live",
          "hevc-main10-L30-dash-cenc-live",
          "hevc-main10-L31-dash-cenc-live",
          "hevc-main10-L40-dash-cenc-live",
          "hevc-main10-L41-dash-cenc-live",
          "playready-h264mpl30-dash",
          "playready-h264mpl31-dash",
          "playready-h264mpl40-dash",
          "playready-h264hpl22-dash",
          "playready-h264hpl30-dash",
          "playready-h264hpl31-dash",
          "playready-h264hpl40-dash",
          "hevc-main10-L30-dash-cenc-prk",
          "hevc-main10-L31-dash-cenc-prk",
          "hevc-main10-L40-dash-cenc-prk",
          "hevc-main10-L41-dash-cenc-prk",
          "hevc-main10-L30-dash-cenc-prk-do",
          "hevc-main10-L31-dash-cenc-prk-do",
          "hevc-main10-L40-dash-cenc-prk-do",
          "hevc-main10-L41-dash-cenc-prk-do",
          "heaac-2-dash",
          "heaac-2hq-dash",
          "dd-5.1-dash",
          "ddplus-5.1-dash",
          "ddplus-5.1hq-dash",
          "ddplus-atmos-dash",
          "webvtt-lssdh-ios13",
          "nflx-cmisc",
          "webvtt-lssdh-ios8",
          "BIF240",
          "BIF320"
        ]
      }
    ]
  }
}
```

### 3.5 レスポンス構造

レスポンスも CBOR 形式 MSL でラップされ、gzip 圧縮されている。  
デコードされた本体構造:

```json
{
  "result": [
    {
      "movieId": 81639724,
      "viewableType": "EPISODE",
      "streamingType": "VOD",
      "drmType": "fairplay",
      "drmContextId": "default",
      "drmVersion": 0,
      "hasDrmStreams": true,
      "hasClearStreams": false,
      "partiallyHydrated": true,
      "playbackContextId": "E3-Bgilt-vcAxLxBA6p...",
      "manifestVersion": "v2",
      "packageId": "...",
      "duration": 1408974,
      "bookmark": 0,
      "expiration": 1775318240,
      "urlExpirationDuration": 43200,
      "manifestExpirationDuration": 86400,
      "clientIpAddress": "...",
      "video_tracks": [...],
      "audio_tracks": [...],
      "timedtexttracks": [...],
      "trickplays": [...],
      "servers": [...],
      "locations": [...],
      "links": {
        "ldl": {
          "rel": "license",
          "href": "/license?licenseType=limited&playbackContextId=...&esn=NFAPPL-02-IPHONE9%3D1-..."
        },
        "license": {
          "rel": "license",
          "href": "/license?licenseType=standard&playbackContextId=...&esn=..."
        },
        "events": {
          "rel": "events",
          "href": "/events?playbackContextId=...&esn=..."
        }
      },
      "auxiliaryManifestToken": "...",
      "cdnResponseData": {
        "pbcid": "6.1kV-6afnxMkPpstTqMHdFuEeDabaX-W2EIrPJMAYDdM"
      }
    }
  ]
}
```

### 3.6 CDN サーバー構造

マニフェストの `servers` フィールドに OCA (Open Connect Appliance) CDN 情報が含まれる:

```json
{
  "dns": {
    "host": "ipv6-c004-tyo013-ix.1.oca.nflxvideo.net",
    "ipv6": "2a00:86c0:130:130::5",
    "ipv4": "45.57.2.5",
    "forceLookup": false
  },
  "id": 140765,
  "rank": 1,
  "key": "1-17676-high",
  "type": "OPEN_CONNECT_APPLIANCE",
  "lowgrade": false,
  "name": "c004.tyo013.ix.nflxvideo.net"
}
```

各ストリームの `urls` フィールドに CDN トークン付き URL が含まれる:

```
https://ipv6-c004-tyo013-ix.1.oca.nflxvideo.net/?o=1&v=21&e=1775318240&t={token}
```

`e` パラメータは expiry (Unix timestamp)、`t` は認証トークン。

### 3.7 ビデオトラック詳細 (実測)

| プロファイル | 最大解像度 | ビットレート範囲 | codec |
|------------|-----------|----------------|-------|
| `playready-h264hpl40-dash` | 1920x1080 | 59 〜 3,184 kbps | H.264 High Profile L4.0 |
| `hevc-main10-L40-dash-cenc-prk-do` | 1920x1080 | 86 〜 ? kbps | HEVC Main10 L4.0 |

タグ: `MCCLEAREN`, `SEGMENT_MAP_2KEY` (CMAF セグメントマップ方式)

### 3.8 マニフェストの重要フィールド

| フィールド | 内容 | Python での再現に必要か |
|----------|------|----------------------|
| `playbackContextId` | ライセンス URL に使用するセッション ID | 必須 |
| `drmContextId` | DRM コンテキスト ID | 必須 |
| `movieId` | コンテンツ ID (数値) | 参照用 |
| `links.license.href` | ライセンスリクエスト URL テンプレート | 必須 |
| `links.events.href` | イベントリポート URL テンプレート | 任意 |
| `auxiliaryManifestToken` | 補助マニフェスト用トークン | 場合による |

---

## 4. ライセンス取得フロー (FairPlay DRM)

### 4.1 エンドポイント

```
POST https://ios.prod.ftl.netflix.com/nq/iosplatform/pbo_license/~1.0.0/router
POST https://ios.prod.cloud.netflix.com/nq/iosplatform/pbo_license/~1.0.0/router
```

### 4.2 リクエスト種別 (X-Netflix.client.request.name 別)

| request.name | X-Netflix.pbobrahv | 目的 | Body サイズ |
|-------------|-------------------|------|------------|
| `releaseLicense` | 14 または 15 | 前セッションの DRM ライセンス解放 | ~2,321 bytes |
| `prefetch/license` | 9 | FairPlay SPC を含む標準ライセンス取得 (prefetch) | ~22,000〜24,500 bytes |
| `license` | 3 または 8 | 標準ライセンス取得 | ~2,386 bytes |

### 4.3 releaseLicense リクエスト

アプリ起動時・再生終了後に呼ばれる。MSL ラップ本体に deactivateLinks 情報を含む。

**リクエストヘッダー:**
```
X-Netflix.client.request.name: releaseLicense
X-Netflix.pbobrahv: 15
Content-Length: 2321
```

### 4.4 prefetch/license リクエスト (FairPlay SPC)

マニフェスト取得後、FairPlay CDM が生成した SPC (Server Playback Context) を含む。

**リクエストヘッダー:**
```
X-Netflix.client.request.name: prefetch/license
X-Netflix.pbobrahv: 9
Content-Length: 24514   # SPC を含むため大きい
```

**MSL デコード後の本体構造 (pbo_license ルーター):**

```json
{
  "url": "/license?licenseType=standard&playbackContextId={playbackContextId}&esn={PRV_ESN}&drmContextId={drmContextId}",
  "version": 2,
  "params": [
    {
      "videoTrackName": "V:2:1;2;;ce4;-1;none;-1;",
      "drmSessionId": "V:2:1;2;;ce4;-1;none;-1;",
      "challengeBase64": "eyJWRVJTSU9OIjoxLCJDSEFM...",
      "clientTime": 1775350117,
      "xid": "6565372417005361529"
    }
  ]
}
```

**フィールド解説:**

| フィールド | 内容 |
|----------|------|
| `url` | マニフェストの `links.license.href` から取得したライセンス URL |
| `playbackContextId` | マニフェストレスポンスから取得 |
| `esn` | PRV ESN (PXA ではなく) |
| `drmContextId` | マニフェストの `drmContextId` |
| `videoTrackName` | 再生中のビデオトラック識別子 |
| `drmSessionId` | `videoTrackName` と同じ値 |
| `challengeBase64` | **FairPlay SPC** (JSON base64 エンコード)。iOS の AVContentKeySession が生成 |
| `clientTime` | Unix timestamp (秒) |
| `xid` | セッションの xid |

### 4.5 FairPlay チャレンジ形式

`challengeBase64` は以下の JSON を base64 エンコードしたもの:

```json
{
  "VERSION": 1,
  "CHALLENGES": [
    {
      "ID": "F703639-C026-4BD2-A57C-16BC8998FC69",
      "PAYLOAD": "<SPC data base64>"
    }
  ]
}
```

### 4.6 ライセンスレスポンス (CKC)

レスポンスは MSL ラップで返される (gzip 圧縮, ~5,915 bytes)。  
デコード後の本体に CKC (Content Key Context) が含まれ、FairPlay CDM にインストールすることでコンテンツ鍵が利用可能になる。

### 4.7 syncDeactivateLinks

pbo_license エンドポイントは再生セッション終了時に `/syncDeactivateLinks` も処理する:

```json
{
  "url": "/syncDeactivateLinks",
  "params": [
    { "deactivateLinks": [] }
  ]
}
```

### 4.8 pbo_license vs pbo_tokens

- **pbo_license** (`/nq/iosplatform/pbo_license/~1.0.0/router`): FairPlay ライセンス取得専用エンドポイント
- **pbo_tokens** (Chrome/Android で使用): MSL セッション確立 (ALE Provisioning) 用エンドポイント

iOS では `pbo_tokens` の呼び出しはキャプチャで確認されていない。iOS の MSL セッション確立は appboot で行われる。

---

## 5. GraphQL エンドポイント

### 5.1 3つの GraphQL エンドポイント

| ホスト | 用途 | MSL ラップ | 認証 |
|--------|------|-----------|------|
| `ios.prod.ftl.netflix.com/graphql` | UI データ (カタログ, マイリスト, ユーザーアクション) | **なし** (Plain HTTP/JSON) | Cookie (NetflixId, SecureNetflixId) |
| `ios.prod.cloud.netflix.com/graphql` | ストリーミング関連 (GetHandles 等) | **MSL ラップ** (Content-Encoding: msl_v1) | Cookie |
| `ios.ngp.prod.cloud.netflix.com/graphql` | NGP (Next-Gen Platform) — SSO/ログアウト | **MSL ラップ** | Cookie |

### 5.2 FTL GraphQL (Plain HTTP)

```
POST https://ios.prod.ftl.netflix.com/graphql
Content-Type: application/json
Cookie: NetflixId=...; SecureNetflixId=...; nfvdid=...
```

**リクエストボディ例:**
```json
{
  "operationName": "myListActions",
  "variables": { "singleVideo": 81046193 },
  "query": "query myListActions($singleVideo: Int!) { videos(videoIds: [$singleVideo]) { __typename videoId playlistActions } }",
  "esn": "{PXA_ESN}",
  "pixelDensity": "2.0",
  "isTablet": "false",
  "idiom": "phone",
  "appVersion": "15.48.1",
  "iosVersion": "15.8.3",
  "osName": "iOS",
  "model": "saget",
  "modelType": "IPHONE9-1",
  "device_type": "NFAPPL-02-",
  "locale": "en-JP",
  "maxDeviceWidth": "375",
  "pathFormat": "graph",
  "responseFormat": "json",
  "odpAware": "true"
}
```

### 5.3 Cloud GraphQL (MSL ラップ)

```
POST https://ios.prod.cloud.netflix.com/graphql
Content-Encoding: msl_v1
X-Netflix.client.type: argo
```

MSL デコード後のボディ例:

```json
{
  "body": {
    "operationName": "GetHandles",
    "query": "query GetHandles { ... }"
  }
}
```

### 5.4 NGP GraphQL (MSL ラップ)

```
POST https://ios.ngp.prod.cloud.netflix.com/graphql
Content-Encoding: msl_v1
```

MSL デコード後のボディ例:

```json
{ "body": { "query": "mutation Operation { createSSOToken }" } }
{ "body": { "query": "mutation Operation($ssoToken: String!) { renewSSOToken(ssoToken: $ssoToken) { ... } }" } }
{ "body": { "query": "mutation Operation { streamingAppLogout { ... } }" } }
```

NGP はログイン/ログアウト・SSO 管理に使用される。20260406 キャプチャでは多くの NGP/Cloud GraphQL が `HTTP 500` を返していた (MSL セッション未確立のため)。

---

## 6. MSL プロトコル詳細

### 6.1 CBOR メッセージ数値キーマッピング (iOS 確認分)

| 数値キー | フィールド名 | 内容 |
|--------|-----------|------|
| `32` | header | MSL ヘッダー |
| `33` | key_response_data | セッション鍵レスポンス |
| `34` | entity_auth_data | エンティティ認証データ |
| `64` | payload_chunk | 暗号化ペイロードチャンク |
| `6` | ciphertext (payload内) | 暗号化データ本体 |
| `7` | iv | 初期化ベクタ |
| `8` | keyid | セッション鍵 ID |
| `9` | hmac | HMAC |
| `30` | scheme (entity_auth内) | 認証スキーム名 |
| `35` | auth_data | 認証データ |
| `10` | compressionalgos | 圧縮アルゴリズムリスト |
| `15` | capabilities | クライアントケイパビリティ |
| `16` | renewable | 更新可能フラグ |

### 6.2 セッション鍵 ID

MSL 通信では `keyid` = `{PRV_ESN}_3` のように ESN に `_3` のサフィックスが付く。  
この数字はセッション鍵のバージョン/インデックスを示すと考えられる。

### 6.3 複数ペイロードチャンク

マニフェストレスポンス等、大きなデータは複数のペイロードチャンク (`64: {...}`) に分割されて送られる。

### 6.4 暗号化スキーム

- **暗号化**: AES-128-CBC + HMAC-SHA256
- **鍵交換**: FAIRPLAY_MGK_APPID (appboot 経由)
- **署名**: ECDSA (kAppBootEccKey: ECDSA P-256) でサーバー署名を検証

---

## 7. テレメトリエンドポイント

### 7.1 logblob

```
POST https://ios.prod.cloud.netflix.com/msl/playapi/ios/logblob
X-Netflix.client.request.name: logblob
X-Netflix.pbobrahv: 5
X-Netflix.argo.nfnsm: 15
Content-Length: ~2,786 bytes
```

再生品質指標・バッファリングイベントをサーバーに送信する。

### 7.2 event

```
POST https://ios.prod.ftl.netflix.com/msl/playapi/ios/event
X-Netflix.client.request.name: events/start
X-Netflix.pbobrahv: 4
X-Netflix.argo.nfnsm: 11
Content-Length: ~3,618 bytes
```

再生開始・停止・位置情報をサーバーに送信する。

### 7.3 ichnaea (cl2)

```
POST https://ichnaea-web.netflix.com/cl2
Content-Type: application/json
Content-Length: ~19,959 bytes
Cookie: NetflixId=...; SecureNetflixId=...; nfvdid=...
```

クライアントアナリティクス (非 MSL)。

---

## 8. X-Netflix.pbobrahv 値マッピング

キャプチャから確認できた値:

| 値 | request.name | エンドポイント |
|----|------------|--------------|
| 3 | `license` | pbo_license |
| 4 | `events/start` | event |
| 5 | `logblob` | logblob |
| 6 | `manifest` または `prefetch/manifest` | manifest |
| 8 | `license` | pbo_license |
| 9 | `prefetch/license` | pbo_license |
| 14 | `releaseLicense` | pbo_license |
| 15 | `releaseLicense` | pbo_license |

---

## 9. Python 再現に必要なパラメータ一覧

### 9.1 事前に取得が必要な値

| パラメータ | 取得方法 | 例 |
|----------|---------|-----|
| **PXA ESN** | Frida フック (ESN 生成関数) または デバイスから抽出 | `NFAPPL-02-IPHONE9=1-PXA-0202...` |
| **PRV ESN** | appboot CBOR の `entityauthdata.authdata.esn` | `NFAPPL-02-IPHONE9=1-AD04...` |
| **NetflixId** | ログイン Cookie | `v%3D3%26ct%3D...` |
| **SecureNetflixId** | ログイン Cookie | `v%3D3%26mac%3D...%26dt%3D...` |
| **nfvdid** | appboot/healthcheck `Set-Cookie` | `BQFmAAEBE...` |
| **devicetoken** | appboot CBOR の `entityauthdata.authdata.devicetoken` | hex 文字列 |
| **appid** | appboot CBOR の `entityauthdata.authdata.appid` | UUID |
| **apphmac** | appboot CBOR の `entityauthdata.authdata.apphmac` | SHA-256 hex |
| **device_key_data** | Frida フック (Irdeto TFIT から抽出) | ~6,576 bytes |

### 9.2 動的に生成する値

| パラメータ | 生成方法 |
|----------|---------|
| `xid` | ランダム uint64 |
| `clientTime` | 現在の Unix timestamp (秒) |
| `X-Client-Request-Id` | ランダム uint64 |

### 9.3 各ステップの依存関係

```
[事前] デバイスから PXA/PRV ESN, devicetoken, device_key_data を取得
    ↓
[Step 1] appboot
  入力: PRV ESN, devicetoken, device_key_data, appid, apphmac, PXA ESN
  出力: nfvdid Cookie, x-netflix-deviceidtoken
    ↓
[Step 2] ログイン (外部)
  入力: ユーザー名/パスワード (または既存 Cookie)
  出力: NetflixId Cookie, SecureNetflixId Cookie
    ↓
[Step 3] MSL セッション確立
  入力: PRV ESN + appboot で得た鍵材料
  出力: AES-128-CBC セッション鍵, HMAC-SHA256 鍵
    ↓
[Step 4] manifest リクエスト
  入力: viewableId, MSL セッション鍵, nfvdid, PXA ESN
  出力: playbackContextId, drmContextId, CDN URLs, video/audio tracks
    ↓
[Step 5] pbo_license リクエスト (prefetch/license)
  入力: playbackContextId, PRV ESN, drmContextId, FairPlay SPC (challengeBase64)
  出力: CKC (FairPlay Content Key Context)
    ↓
[Step 6] FairPlay CDM に CKC をインストール → コンテンツ鍵取得
    ↓
[Step 7] CDN からセグメントをダウンロード
  入力: マニフェストの stream.urls[n].url
```

### 9.4 viewableId の取得

動画の `viewableId` (= `videoId`) は GraphQL (FTL) で取得可能:

```graphql
query { videos(videoIds: [81684733]) {
  videoId
  playlistActions
}}
```

または URL (netflix.com/watch/{viewableId}) から直接取得。

### 9.5 FairPlay SPC の生成

FairPlay SPC は iOS の `AVContentKeySession` API でのみ生成可能:

```swift
AVContentKeySession.makeContentKeyRequest(
  initializationData: contentID,
  completionHandler: { request in
    request.makeStreamingContentKeyRequestData(
      forApp: appCertificate,
      contentIdentifier: contentID
    ) // → SPC bytes
  }
)
```

Python からは直接生成できない。iOS デバイスまたはシミュレータが必要。

---

## 10. キャプチャデータ出所

| 日付 | ディレクトリ | 内容 |
|-----|------------|------|
| 2026-04-04 | `raws/ios/20260404/` | 最初のキャプチャ。マニフェストレスポンス (`0007_msl.api.response_*.json`) を含む完全なデータ |
| 2026-04-05 | `raws/ios/20260405/` | `msl.api.json` 形式の MSL デコード済みデータ多数。crypto/ ディレクトリに暗号操作ログ |
| 2026-04-06 | `raws/ios/20260406/` | appboot 成功キャプチャ。`headers/` と `raw/*.bin` を含む最新形式 |
