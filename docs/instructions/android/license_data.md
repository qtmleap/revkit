# Netflix Widevine DRM License Exchange - Reference Data

> Android アプリ (v9.57.0 / build 63928) から MSL 経由で取得した実データ。
> 2026-03-13 にキャプチャ。デバイス: Pixel 4a (5G) / Android 14 / Widevine CDM v17.0.0
> **環境**: L3 (ソフトウェア) 強制。レスポンスは Widevine decrypt → CBOR → GZIP → JSON で復元。

---

## 概要

Netflix Android アプリは **Widevine CDM** DRM を使用してコンテンツを保護している。
iOS 版と異なり、マニフェスト取得と初回ライセンス取得が `/licensedManifest` として統合されている:

1. **licensedManifest (PRE_FETCH)** → ストリーム一覧 + CDN URL + 初回 Widevine ライセンス (limited) を一括取得
2. **License Request (standard)** → 再生開始時に standard ライセンスを取得 (Widevine CDM protobuf チャレンジ)
3. **License Response** → Widevine ライセンスバイナリを受信、コンテンツ鍵を取得
4. **Release License** → 再生終了時にライセンスを解放

ライセンスリクエスト/レスポンスはすべて **Widevine CryptoContext** で暗号化された MSL ペイロードとして送信される。以下のデータはアプリ内部で MSL 暗号化される前/復号後の平文。

---

## エンドポイント

```
POST /nq/androidui/samurai/~9.0.0/api
```

MSL URL としては:
```
/licensedManifest  (マニフェスト + 初回ライセンス一括)
/license?licenseType={standard|limited}&playbackContextId={id}&esn={esn}&drmContextId={id}
```

### URL パラメータ

| パラメータ | 説明 |
|---|---|
| `licenseType` | `standard` (再生開始時) or `limited` (PRE_FETCH / LDL) |
| `playbackContextId` | licensedManifest レスポンスで取得した再生セッション ID (Base64url-like) |
| `esn` | Netflix デバイス ESN。`NFANDROID1-PRV-P-{L3}-{MODEL}-{userId}-{fingerprint}` 形式 |
| `drmContextId` | DRM コンテキスト ID (数値)。licensedManifest レスポンスの `packageId` と対応 |

---

## 1. licensedManifest Request (PRE_FETCH)

コンテンツ選択時に送信される。iOS の `/manifest` + `/license` を統合した Android 固有の API。
バッチリクエストにより複数 viewableId を同時に指定可能。

```json
{
  "version": 2,
  "url": "/licensedManifest",
  "languages": ["en-JP"],
  "common": {
    "challenge": "<共通 Widevine CDM protobuf>"
  },
  "params": [
    {
      "viewableId": "81756595",
      "method": "licensedManifest",
      "flavor": "PRE_FETCH",
      "drmType": "widevine",
      "manifestVersion": "v2",
      "licenseType": "limited",
      "challenges": {
        "primary": [{
          "challengeBase64": "<Widevine CDM protobuf>",
          "drmSessionId": 1,
          "clientTime": 1773373148
        }]
      },
      "profiles": ["playready-h264mpl30-dash", "playready-h264hpl22-dash", "..."],
      "profileGroups": [{"name": "primary", "profiles": ["..."]}]
    }
  ]
}
```

### iOS との違い

| 項目 | iOS (`/manifest` + `/license`) | Android (`/licensedManifest`) |
|---|---|---|
| API パス | 分離 (2 リクエスト) | 統合 (1 リクエスト) |
| バッチ | 1 viewableId / リクエスト | 複数 viewableId / リクエスト |
| DRM チャレンジ | FairPlay SPC (個別) | `common.challenge` + 個別 `challenges.primary` |
| DRM タイプ | `fairplay` | `widevine` |
| チャレンジ形式 | FairPlay SPC (JSON: CHALLENGES[].PAYLOAD) | Widevine CDM protobuf (バイナリ) |

---

## 2. licensedManifest Response

L3 Widevine decrypt → CBOR (key 62) → GZIP 展開で復元。8 チャンク、合計 456KB。

```json
{
  "id": 1,
  "version": 2,
  "serverTime": 1773373149628,
  "result": [
    {
      "movieId": "81756595",
      "packageId": "2596051",
      "duration": 8523000,
      "drmContextId": "2596051",
      "playbackContextId": "E3-Bgj5tevc...",
      "video_tracks": [{"..."}],
      "audio_tracks": [{"..."}],
      "timedtexttracks": [{"..."}],
      "servers": [{"..."}],
      "links": {
        "events": {"href": "/events?playbackContextId=...&esn=..."},
        "ldl": {"href": "/license?licenseType=limited&..."},
        "license": {"href": "/license?licenseType=standard&..."}
      }
    }
  ]
}
```

### result フィールド解説

| フィールド | 型 | 説明 |
|---|---|---|
| `movieId` | string | コンテンツ ID |
| `packageId` | string | DRM パッケージ ID (`drmContextId` と対応) |
| `duration` | number | 再生時間 (ミリ秒)。`8523000` = 2時間22分3秒 |
| `drmContextId` | string | DRM コンテキスト ID |
| `playbackContextId` | string | 再生セッション ID (後続の `/license`, `/events` URL に埋め込み) |
| `video_tracks` | array | 映像トラック一覧 (複数ビットレート/解像度) |
| `audio_tracks` | array | 音声トラック一覧 (多言語 × 複数ビットレート) |
| `timedtexttracks` | array | 字幕トラック一覧 (IMSC 1.1) |
| `servers` | array | CDN サーバー一覧 (Open Connect Appliance) |
| `links` | object | 後続 API エンドポイント (`events`, `ldl`, `license`) |

### video_tracks の構造

```json
{
  "trackType": "PRIMARY",
  "new_track_id": "V:2:1;2;;primary;-1;none;-1;",
  "dimensionsLabel": "2D",
  "streams": [
    {
      "content_profile": "playready-h264hpl30-dash",
      "bitrate": 1050,
      "peakBitrate": 2250,
      "res_w": 960,
      "res_h": 540,
      "framerate_value": 24000,
      "framerate_scale": 1001,
      "size": 1181780966,
      "downloadable_id": "1496730611",
      "vmaf": 87,
      "isDrm": true
    }
  ]
}
```

L3 環境での最大解像度は **960x540** (SD)。7 ストリーム (80〜1050 kbps)。

### servers の構造

```json
{
  "id": 140368,
  "name": "c062.osa001.ix.nflxvideo.net",
  "rank": 1,
  "type": "OPEN_CONNECT_APPLIANCE",
  "dns": {
    "host": "ipv4-c062-osa001-ix.1.oca.nflxvideo.net",
    "ipv4": "45.57.82.139",
    "ipv6": null
  }
}
```

3 台の Open Connect Appliance (大阪: osa001, osa003)。`rank` でフェイルオーバー優先度を指定。

### iOS manifest レスポンスとの比較

| 項目 | iOS (`/manifest`) | Android (`/licensedManifest`) |
|---|---|---|
| レスポンス取得 | **未取得** | **復元済み** (L3 decrypt 経由) |
| result 構造 | 単一オブジェクト (推定) | 配列 (バッチ対応) |
| links | events, license (推定) | events, ldl, license |
| servers | CDN URL 一覧 (推定) | Open Connect Appliance (id, name, rank, dns) |
| video_tracks | 不明 | streams[] (bitrate, res, vmaf, downloadable_id) |

---

## 3. Standard License Request

再生開始時に送信される。licensedManifest レスポンスの `links.license.href` を使用。

```json
{
  "version": 2,
  "url": "/license?licenseType=standard&playbackContextId=E3-Bgj5tevc...&esn=NFANDROID1-PRV-P-L3-GOOGLPIXEL%3D4A%3D%3D5G%3D-22594-...&drmContextId=2596051",
  "params": {
    "clientTime": 1773373168,
    "challengeBase64": "<Widevine CDM protobuf, ~3.4KB>",
    "xid": "7616579701369171345"
  },
  "languages": ["en-JP"]
}
```

### params フィールド解説

| フィールド | 型 | 説明 |
|---|---|---|
| `clientTime` | number | クライアント時刻 (Unix epoch, seconds) |
| `challengeBase64` | string | Base64 エンコードされた Widevine CDM protobuf ライセンスチャレンジ |
| `xid` | string | リクエスト ID (トランザクション ID) |

### challengeBase64 の内容

iOS の FairPlay SPC が JSON (`CHALLENGES[].PAYLOAD`) であるのに対し、Widevine は **protobuf バイナリ**。
内部に以下の情報が含まれる:

| フィールド | 値 | 説明 |
|---|---|---|
| `esn` | `NFANDROID1-PRV-P-L3-GOOGLPIXEL=4A==5G=-22594-...` | デバイス ESN (L3 マーカー含む) |
| `movieid` | `"81756595"` | コンテンツ ID |
| `issuetime` | `1773373148` | 発行時刻 |
| `salt` | `"35982634558192635..."` | ランダムソルト |
| `oem_crypto_build_information` | `"OEMCrypto Level3 Code"` | OEMCrypto セキュリティレベル |
| `widevine_cdm_version` | `"17.0.0"` | CDM バージョン |
| `device_name` | `"bramble"` | デバイスコードネーム |
| `architecture_name` | `"arm64-v8a"` | CPU アーキテクチャ |

---

## 4. Standard License Response

```json
{
  "id": 1,
  "version": 2,
  "serverTime": 1773373169221,
  "result": {
    "licenseResponseBase64": "<Base64-encoded Widevine license protobuf>",
    "secureStopExpected": false,
    "links": {
      "releaseLicense": {
        "rel": "releaseLicense",
        "href": "/releaseLicense?drmLicenseContextId=E3-Bgj5tevc...;EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED;STANDARD;1773373169202"
      }
    },
    "drmGroupId": "132",
    "licenseType": "standard",
    "expiration": 1773373168000
  },
  "common": {},
  "from": "playapi"
}
```

### result フィールド解説

| フィールド | 型 | 説明 |
|---|---|---|
| `licenseResponseBase64` | string | Base64 エンコードされた Widevine ライセンスバイナリ (protobuf)。`provideKeyResponse()` に渡す |
| `secureStopExpected` | boolean | Secure Stop (再生終了通知) が必要か |
| `links.releaseLicense.href` | string | ライセンス解放用 URL。再生終了時にこの URL にリクエストを送る |
| `drmGroupId` | string | DRM グループ ID。`"132"` (iOS は `"191-192"` のようにハイフン区切り) |
| `licenseType` | string | `"standard"` |
| `expiration` | number | ライセンス有効期限 (Unix epoch, milliseconds) |

### licenseResponseBase64 の内容

iOS の FairPlay CKC が JSON (`VERSION`, `MEDIASESSIONID`, `RESPONSES[].PAYLOAD`) であるのに対し、
Widevine のライセンスレスポンスは **protobuf バイナリ**。内部には:

- **暗号化されたコンテンツ鍵**: Widevine CDM のセッション鍵で暗号化
- **埋め込み JSON**: `version`, `esn`, `issuetime`, `movieid`, `salt`
- **鍵 ID**: `CE66E4B447F964AC19000000000000000`
- **ライセンスメタデータ**: security_level, expiry_duration

`android.media.MediaDrm.provideKeyResponse(sessionId, licenseResponseBase64)` に渡すことで
コンテンツ復号鍵が Widevine CDM にインストールされる。

---

## 5. Release License (再生終了)

再生終了時、サーバーに通知する。`links.releaseLicense.href` を使用。

iOS と同じく、レスポンスは空の `actions` オブジェクト (推定):

```json
{
  "result": [
    {
      "actions": {}
    }
  ],
  "id": 1,
  "common": {},
  "from": "playapi",
  "serverTime": 1773373xxx000,
  "version": 2
}
```

---

## 6. drmSessionId / videoTrackName フォーマット

```
V:2:1;2;;primary;-1;none;-1;
```

セミコロン区切り。推定される構造:
- `V:2:1` — ビデオトラック識別 (V=Video, 以降はインデックス)
- `2` — DRM グループ数
- (空) — 予約
- `primary` — プロファイルグループ (iOS は `ce4` = HEVC)
- `-1` — 品質レベル (-1 = auto)
- `none` — HDR タイプ (none = SDR)
- `-1` — 予約

---

## 7. ESN (Entertainment Service Name) フォーマット

```
NFANDROID1-PRV-P-L3-GOOGLPIXEL=4A==5G=-22594-3E369F1C9B189ED664E13DEEEE9BACB67684B4FE6283537D1A67810BFE73E371
```

- `NFANDROID1` — Netflix Android プラットフォーム (iOS は `NFAPPL`)
- `PRV` — プロビジョニングタイプ
- `P` — 製品タイプ
- `L3` — Widevine セキュリティレベル (L3=ソフトウェア、L1=TEE)。iOS には存在しない
- `GOOGLPIXEL=4A==5G=` — デバイスモデル (Pixel 4a (5G)、`=` は `,` のエスケープ)
- `22594` — ユーザー ID
- 末尾 64 文字 — デバイス固有ハッシュ (SHA-256)

### iOS ESN との比較

| 項目 | iOS | Android |
|---|---|---|
| プレフィックス | `NFAPPL` | `NFANDROID1` |
| DRM バージョン | `02` (FairPlay v2) | なし |
| セキュリティレベル | なし | `L3` or `L1` |
| モデル | `IPHONE9=1` | `GOOGLPIXEL=4A==5G=` |
| ユーザー ID | なし | あり (`22594`) |

---

## 8. データの関連性まとめ

```
licensedManifest Response
  ├─ playbackContextId ──→ /license Request URL
  ├─ drmContextId / packageId ──→ /license Request URL
  ├─ video_tracks / audio_tracks ──→ CDN ストリーム URL
  ├─ servers[] ──→ CDN サーバー (Open Connect Appliance)
  └─ links
       ├─ events ──→ /events URL (再生イベント報告)
       ├─ ldl ──→ /license?licenseType=limited (LDL)
       └─ license ──→ /license?licenseType=standard

License Request
  └─ challengeBase64 (Widevine protobuf) ──→ License Response.licenseResponseBase64

License Response
  ├─ licenseResponseBase64 ──→ MediaDrm.provideKeyResponse() → コンテンツ鍵
  ├─ links.releaseLicense.href ──→ Release License Request URL
  └─ expiration ──→ standard: ライセンス有効期限
```
