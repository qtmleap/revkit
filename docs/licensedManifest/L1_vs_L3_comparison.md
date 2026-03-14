# licensedManifest: Widevine L1 vs L3 比較

Device: Pixel 4a (5G) / bramble / Android 14
App: Netflix 9.57.0
Endpoint: `https://android14.prod.ftl.netflix.com/nq/androidui/samurai/~9.0.0/api`
URL: `/licensedManifest`

## 概要

同一デバイス (Pixel 4a) で、Widevine L1 (TEE) と L3 (ソフトウェア) の licensedManifest リクエストを比較。
リクエスト構造は同一だが、**profiles** と **challenge** の内容が異なる。

## リクエスト共通部分

以下のフィールドは L1/L3 で完全に同一:

| フィールド | 値 |
|---|---|
| version | 2 |
| url | /licensedManifest |
| languages | ["en-JP"] |
| method | licensedManifest |
| flavor | PRE_FETCH |
| drmType | widevine |
| manifestVersion | v2 |
| osName | android |
| osVersion | 34 |
| application | samurai |
| clientVersion | 9.57.0 |
| uiVersion | 9.57.0 |
| uiPlatform | android |
| player | streaming |
| hardware | lito |
| licenseType | limited |
| cellularCap | auto |
| netType | wifi |
| supportsWatermark | true |
| supportsPreReleasePin | true |
| supportsAdBreakHydration | true |
| liveAdsCapability | dynamic |
| supportsUnequalizedDownloadables | true |
| requestEligibleABTests | true |
| useBetterTextUrls | true |
| useHttpsStreams | true |
| contentPlaygraph | ["v2"] |
| supportsAuxiliaryManifestDeduplication | true |
| liveMetadataFormat | INDEXED_SEGMENT_TEMPLATE |
| maxSupportedLanguages | -1 |
| supportsPartialHydration | true |
| prefersVerticalVideo | false |
| supportsVideoTrackSwitching | false |
| supportsNetflixMediaEvents | true |

## 差分1: Profiles

### L1 (36 profiles)

HEVC HDR + 高解像度H.264 + VP9を含む全プロファイル:

```
none-h264mpl30-dash
playready-h264mpl30-dash
none-h264mpl31-dash              ← L3にはない
playready-h264mpl31-dash         ← L3にはない
none-h264mpl40-dash              ← L3にはない
playready-h264mpl40-dash         ← L3にはない
hevc-hdr-main10-L30-dash-cenc-prk     ← L3にはない (HEVC HDR)
hevc-hdr-main10-L30-dash-cenc-prk-do  ← L3にはない
hevc-hdr-main10-L31-dash-cenc-prk     ← L3にはない
hevc-hdr-main10-L31-dash-cenc-prk-do  ← L3にはない
hevc-hdr-main10-L40-dash-cenc-prk     ← L3にはない
hevc-hdr-main10-L40-dash-cenc-prk-do  ← L3にはない
hevc-hdr-main10-L41-dash-cenc-prk     ← L3にはない
hevc-hdr-main10-L41-dash-cenc-prk-do  ← L3にはない
hevc-hdr-main10-L30-dash-cenc-live    ← L3にはない
hevc-hdr-main10-L31-dash-cenc-live    ← L3にはない
hevc-hdr-main10-L40-dash-cenc-live    ← L3にはない
hevc-hdr-main10-L41-dash-cenc-live    ← L3にはない
iso_23001_18-dash-live
playready-h264hpl22-dash
h264hpl22-dash-playready-live
playready-h264hpl30-dash
h264hpl30-dash-playready-live
playready-h264hpl31-dash         ← L3にはない
h264hpl31-dash-playready-live    ← L3にはない
playready-h264hpl40-dash         ← L3にはない
h264hpl40-dash-playready-live    ← L3にはない
vp9-profile0-L21-dash-cenc
vp9-profile0-L30-dash-cenc
vp9-profile0-L31-dash-cenc       ← L3にはない
vp9-profile0-L40-dash-cenc       ← L3にはない
heaac-2-dash
xheaac-dash
imsc1.1
nflx-cmisc
BIF320
```

### L3 (14 profiles)

基本的なコーデックのみ。HEVC HDR なし、高解像度 H.264/VP9 なし:

```
none-h264mpl30-dash
playready-h264mpl30-dash
iso_23001_18-dash-live
playready-h264hpl22-dash
h264hpl22-dash-playready-live
playready-h264hpl30-dash
h264hpl30-dash-playready-live
vp9-profile0-L21-dash-cenc
vp9-profile0-L30-dash-cenc
heaac-2-dash
xheaac-dash
imsc1.1
nflx-cmisc
BIF320
```

### Profile 差分まとめ

| カテゴリ | L1 | L3 |
|---|---|---|
| H.264 Main Profile | L30, L31, L40 | L30のみ |
| H.264 High Profile | L22, L30, L31, L40 | L22, L30のみ |
| HEVC HDR Main10 | L30, L31, L40, L41 (prk, prk-do, live) | なし |
| VP9 Profile0 | L21, L30, L31, L40 | L21, L30のみ |
| Audio/Subtitle/Other | heaac-2, xheaac, imsc1.1, nflx-cmisc, BIF320 | 同一 |
| **合計** | **36** | **14** |

L3 では高解像度ビデオ (L31以上) と HEVC HDR が全て除外される。
H.264基準では最大L30 (720p) だが、VP9 L30 (最大1080p) は含まれる。
実際に返却されるストリーム品質はサーバー側の manifest レスポンスによる。

## 差分2: Challenge (Widevine License Request)

Challenge はデバイスの Widevine CDM が生成する protobuf バイナリ (Base64エンコード)。
デバイス証明書と OEMCrypto 情報を含む。

### L1 Challenge 内の Client Identification

```
application_name: com.netflix.mediaclient
origin: (empty)
package_certificate_hash_bytes: KAvwDZh6ZPI16jT59NO7L5XUj7ME5e6KKx0eXz0Zz9A=
company_name: Google
model_name: Pixel 4a (5G)
architecture_name: arm64-v8a
device_name: bramble
product_name: bramble
build_info: google/bramble/bramble:14/UP1A.231005.007/10754064:user/release-keys
widevine_cdm_version: 17.0.0
oem_crypto_security_patch_level: 0
oem_crypto_build_information: Build Information: API_Version: 16.3 LibOEMCrypto_Version: 1.56 TA_Version: 1.1382
```

### L3 Challenge 内の Client Identification

```
application_name: com.netflix.mediaclient
origin: (empty)
package_certificate_hash_bytes: KAvwDZh6ZPI16jT59NO7L5XUj7ME5e6KKx0eXz0Zz9A=
company_name: Google
model_name: Pixel 4a (5G)
architecture_name: arm64-v8a
device_name: bramble
product_name: bramble
build_info: google/bramble/bramble:14/UP1A.231005.007/10754064:user/release-keys
widevine_cdm_version: 17.0.0
oem_crypto_security_patch_level: 0
oem_crypto_build_information: OEMCrypto Level3 Code May 20 2022 21:36:54
```

### Challenge 差分まとめ

| フィールド | L1 | L3 |
|---|---|---|
| oem_crypto_build_information | `Build Information: API_Version: 16.3 LibOEMCrypto_Version: 1.56 TA_Version: 1.1382` | `OEMCrypto Level3 Code May 20 2022 21:36:54` |
| RSA公開鍵 | 異なる (TEE内の鍵) | 異なる (ソフトウェア鍵) |
| DRM Session Provider Certificate | 異なる | 異なる |
| challengeBase64 長さ | ~3456文字 | ~3192文字 |

L1 の challenge は TEE (Trusted Execution Environment) 内で生成され、TA (Trusted Application) バージョン情報を含む。
L3 の challenge はソフトウェアで生成され、OEMCrypto Level3 のビルド日時を含む。

## 差分3: viewableId

両方とも params 配列に3つの viewableId を含むが、viewableId 自体は同一:

| params[n] | viewableId |
|---|---|
| params[0] | 81639724 |
| params[1] | 81756595 |
| params[2] | 80243261 |

## Cookies

MSL リクエストは `gsid` cookie で認証される。以下の cookie が使用される:

| Cookie | 説明 |
|---|---|
| `nfvdid` | Netflix Virtual Device ID |
| `flwssn` | Flow Session ID |
| `NetflixId` | メイン認証 cookie |
| `SecureNetflixId` | セキュア認証 cookie (HMAC付き) |
| `gsid` | Global Session ID (MSLリクエスト用) |

実際のcookie値は [cookies.txt](cookies.txt) を参照。

## Headers

MSL リクエストは Cronet HTTP クライアント経由で送信される。
主要ヘッダー:

| Header | 値 |
|---|---|
| Content-Type | application/json |
| User-Agent | Dalvik/2.1.0 (Linux; U; Android 14; Pixel 4a (5G) Build/UP1A.231005.007) |

## まとめ

| 項目 | L1 (TEE) | L3 (Software) |
|---|---|---|
| **最大画質** | 4K HDR | 720p (H.264) / 1080p (VP9) ※要レスポンス確認 |
| **Profiles数** | 36 | 14 |
| **HEVC HDR** | あり (L30-L41) | なし |
| **H.264 最大Level** | L40 (1080p+) | L30 (720p) |
| **VP9 最大Level** | L40 (4K) | L30 (1080p) |
| **OEMCrypto** | TEE (TA_Version: 1.1382) | Software (Level3 Code) |
| **セキュリティ** | ハードウェア保護 | ソフトウェアのみ |
| **リクエスト構造** | 同一 | 同一 |
| **Cookie** | 同一 | 同一 |

L1/L3 の違いは **challenge** と **profiles** のみ。リクエスト構造、cookie、ヘッダーは完全に同一。
Netflix サーバーは challenge 内の OEMCrypto 情報からセキュリティレベルを判定し、
返却するマニフェスト (利用可能なストリーム品質) を決定する。
