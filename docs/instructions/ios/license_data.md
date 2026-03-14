# Netflix FairPlay DRM License Exchange - Reference Data

> iOS アプリ (CLIENT-15.48.1) から MSL 経由で取得した実データ。
> 2026-03-12 にキャプチャ。デバイス: iPhone 7 (iPhone9,1) / iOS 15.8.3

---

## 概要

Netflix iOS アプリは **FairPlay Streaming (FPS)** DRM を使用してコンテンツを保護している。
ライセンス交換は MSL (Message Security Layer) の上で行われ、以下のフローで進む:

1. **Manifest 取得** → 再生可能なストリーム一覧 + `playbackContextId` を取得
2. **License Request (standard)** → 初回の FairPlay SPC (Server Playback Context) を送信
3. **License Response** → CKC (Content Key Context) を受信、復号鍵を取得
4. **License Request (limited)** → 再生中にビットレート切り替え等で追加ライセンスを取得
5. **Release License** → 再生終了時にライセンスを解放

ライセンスリクエスト/レスポンスはすべて **AES-128-CBC + HMAC-SHA256** で暗号化された MSL ペイロードとして送信される。以下のデータはアプリ内部で MSL 暗号化される前の平文。

---

## エンドポイント

```
POST /nq/iosplatform/pbo_license/~1.0.0/router
```

MSL URL としては:
```
/license?licenseType={standard|limited}&playbackContextId={id}&esn={esn}&drmContextId={id}
```

### URL パラメータ

| パラメータ | 説明 |
|---|---|
| `licenseType` | `standard` (初回) or `limited` (追加/ビットレート変更時の LDL) |
| `playbackContextId` | Manifest レスポンスで取得した再生セッション ID (Base64url-like) |
| `esn` | Netflix デバイス ESN。`NFAPPL-02-{MODEL}-{HASH}` 形式 |
| `drmContextId` | DRM コンテキスト ID (数値) |

---

## 1. Standard License Request (初回)

再生開始時に送信される。Manifest 取得直後、2つの FairPlay SPC チャレンジを含む。

```json
{
  "mslTimeout": 19,
  "preferredlanguages": {
    "appselectedlanguages": ["en-JP", "en"],
    "platformselectedlanguages": ["en-JP"]
  },
  "url": "/license?licenseType=standard&playbackContextId=E3-Bgj5tevc...&esn=NFAPPL-02-IPHONE9%3D1-5CB1D229...&drmContextId=2596051",
  "params": [
    {
      "drmSessionId": "V:2:1;2;;ce4;-1;none;-1;",
      "xid": "7118417868969003867",
      "clientTime": 1773331407,
      "videoTrackName": "V:2:1;2;;ce4;-1;none;-1;",
      "challengeBase64": "<Base64-encoded JSON, see below>"
    }
  ]
}
```

### params フィールド解説

| フィールド | 型 | 説明 |
|---|---|---|
| `drmSessionId` | string | DRM セッション識別子。`V:2:1;2;;ce4;-1;none;-1;` のようなセミコロン区切りフォーマット。ビデオトラック情報を含む |
| `xid` | string | リクエスト ID (トランザクション ID) |
| `clientTime` | number | クライアント時刻 (Unix epoch, seconds) |
| `videoTrackName` | string | `drmSessionId` と同値。再生対象のビデオトラック識別子 |
| `challengeBase64` | string | Base64エンコードされた JSON。FairPlay SPC を含む (後述) |

### challengeBase64 のデコード結果

```json
{
  "CHALLENGES": [
    {
      "ID": "18C92565-21D0-4AAF-93C2-A306AB1565AD",
      "PAYLOAD": "<Base64-encoded FairPlay SPC binary, 10348 chars = ~7760 bytes>"
    },
    {
      "ID": "EEF401EF-2D78-4065-80C8-EB607EA4279D",
      "PAYLOAD": "<Base64-encoded FairPlay SPC binary, 9240 chars = ~6928 bytes>"
    }
  ]
}
```

- **CHALLENGES**: 配列。通常2つのチャレンジを含む (ビデオ/オーディオのDRMグループに対応)
- **ID**: UUID。レスポンスの RESPONSES と対応する
- **PAYLOAD**: FairPlay SPC (Server Playback Context) バイナリ。先頭4バイトは `00000001` (magic number)。Apple CDM が生成する不透明なバイナリデータで、コンテンツキーのリクエストを含む

---

## 2. Standard License Response

```json
{
  "result": [
    {
      "licenseResponseBase64": "<Base64-encoded JSON, see below>",
      "secureStopExpected": false,
      "links": {
        "releaseLicense": {
          "rel": "releaseLicense",
          "href": "/releaseLicense?drmLicenseContextId=E3-Bgj5tevc...;29701FE4-...;STANDARD;1773331408336"
        }
      },
      "drmGroupId": "191-192",
      "licenseType": "standard",
      "expiration": 1773374608348
    }
  ],
  "id": 1,
  "common": {},
  "from": "playapi",
  "serverTime": 1773331408353,
  "version": 2
}
```

### result フィールド解説

| フィールド | 型 | 説明 |
|---|---|---|
| `licenseResponseBase64` | string | Base64エンコードされた JSON。FairPlay CKC を含む (後述) |
| `secureStopExpected` | boolean | Secure Stop (再生終了通知) が必要か |
| `links.releaseLicense.href` | string | ライセンス解放用 URL。再生終了時にこのURLにリクエストを送る |
| `drmGroupId` | string | DRM グループ ID。`"191-192"` のようにハイフン区切り |
| `licenseType` | string | `"standard"` |
| `expiration` | number | ライセンス有効期限 (Unix epoch, milliseconds)。standard は約12時間 |

### licenseResponseBase64 のデコード結果

```json
{
  "VERSION": 1,
  "MEDIASESSIONID": "G3iR0pT5pxY=",
  "RESPONSES": [
    {
      "ID": "18C92565-21D0-4AAF-93C2-A306AB1565AD",
      "PAYLOAD": "<Base64-encoded FairPlay CKC binary, 2088 chars = ~1566 bytes>"
    },
    {
      "ID": "EEF401EF-2D78-4065-80C8-EB607EA4279D",
      "PAYLOAD": "<Base64-encoded FairPlay CKC binary, 1724 chars = ~1293 bytes>"
    }
  ]
}
```

- **VERSION**: プロトコルバージョン (常に `1`)
- **MEDIASESSIONID**: Base64エンコードされたメディアセッション識別子
- **RESPONSES**: 配列。CHALLENGES の各 ID に対応する CKC を含む
  - **ID**: Challenge の ID と一致する UUID
  - **PAYLOAD**: FairPlay CKC (Content Key Context) バイナリ。Apple CDM に渡すことでコンテンツ復号鍵が得られる

---

## 3. Limited Duration License (LDL) Request

再生中のビットレート変更、チャプター切り替え時等に追加ライセンスを取得する。
構造は Standard と同じだが `licenseType=limited`。

```json
{
  "mslTimeout": null,
  "url": "/license?licenseType=limited&playbackContextId=E3-Bgj5tevc...&esn=NFAPPL-02-IPHONE9%3D1-...&drmContextId=2596051",
  "params": [
    {
      "drmSessionId": "V:2:1;2;;ce4;-1;none;-1;",
      "videoTrackName": "V:2:1;2;;ce4;-1;none;-1;",
      "xid": "7118765455155927307",
      "clientTime": 1773331477,
      "challengeBase64": "<Base64-encoded JSON>"
    }
  ]
}
```

Standard との差異:
- `mslTimeout`: `null` (タイムアウトなし)
- `licenseType`: `limited`
- `playbackContextId`: 異なるコンテキストIDの場合あり (別エピソードへの切り替え等)

### LDL challengeBase64 デコード結果

```json
{
  "CHALLENGES": [
    {
      "ID": "9B3BEEFC-B11A-4019-9966-F238CF4070BD",
      "PAYLOAD": "<FairPlay SPC, 11096 chars = ~8322 bytes>"
    },
    {
      "ID": "A41B0EA1-EECC-483C-A79A-237E5BD2E65A",
      "PAYLOAD": "<FairPlay SPC, 10496 chars = ~7872 bytes>"
    }
  ]
}
```

---

## 4. Limited Duration License Response

```json
{
  "result": [
    {
      "licenseResponseBase64": "<Base64-encoded JSON>",
      "secureStopExpected": false,
      "links": {
        "releaseLicense": {
          "rel": "releaseLicense",
          "href": "/releaseLicense?drmLicenseContextId=...;LIMITED_DURATION;1773331477178"
        }
      },
      "drmGroupId": "191-192",
      "licenseType": "limited_duration",
      "expiration": 1773331537178
    }
  ],
  "id": 1,
  "common": {},
  "from": "playapi",
  "serverTime": 1773331477194,
  "version": 2
}
```

Standard との差異:
- `licenseType`: `"limited_duration"`
- `expiration`: 有効期限が非常に短い (約60秒)。再生中に定期的に更新される

### LDL licenseResponseBase64 デコード結果

```json
{
  "VERSION": 1,
  "MEDIASESSIONID": "znvDeutRb/4=",
  "RESPONSES": [
    {
      "ID": "9B3BEEFC-B11A-4019-9966-F238CF4070BD",
      "PAYLOAD": "<FairPlay CKC, 1552 chars = ~1164 bytes>"
    },
    {
      "ID": "A41B0EA1-EECC-483C-A79A-237E5BD2E65A",
      "PAYLOAD": "<FairPlay CKC, 1532 chars = ~1149 bytes>"
    }
  ]
}
```

---

## 5. Release License (再生終了)

再生終了時、サーバーに通知する。レスポンスは空の `actions` オブジェクト:

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
  "serverTime": 1773331482636,
  "version": 2
}
```

---

## 6. 再生イベントログから見るタイミング

`startplayevents` ログの `eventlist` から、各イベントの相対タイミング (UIPresented=0 基準, ms):

```
PlaybackRequested       : -4343ms
ManifestRequestStart    : -4330ms
MovieHeaderDownloadStart: -4011ms
ManifestRequestEnd      : -4049ms
PlaylistBuildStart      : -3987ms
MovieHeaderDownloadEnd  : -3990ms
PlaylistBuildEnd        : -3930ms
LicenseChallengeRequested: -3925ms
LicenseChallengeReceived : -3925ms
SPLDLicenseRequestStart : -3876ms
FirstLDLTry             : -3575ms
SPLDLicenseRequestEnd   : -3594ms
Variant-A-Begin-1       : -3485ms
Variant-A-End-1         : -3481ms
V-Start-433             : -3482ms
V-Stop-433              : -3477ms
Variant-V-Begin-1       : -3482ms
Variant-V-End-1         : -3477ms
V-Start-1637            : -3290ms
V-Stop-1637             : -3285ms
Variant-V-Begin-2       : -3290ms
Variant-V-End-2         : -3285ms
UIPresented             : 0ms
PlayerUIPresented       : 0ms
PlaybackStarted         : +169ms
```

注目ポイント:
- Manifest取得からLicenseChallenge生成まで約400ms
- LicenseRequest (SPLDLicenseRequestStart→End) は約280ms
- UIPresented から PlaybackStarted まで約170ms
- 全体で Playback Request → Playback Started は約4.5秒

### licenseAudit

```json
{
  "licenseAudit": {
    "ldl": [282],
    "": [250]
  }
}
```

- `ldl`: Limited Duration License の取得時間 (282ms)
- `""`: Standard License の取得時間 (250ms)

---

## 7. drmSessionId / videoTrackName フォーマット

```
V:2:1;2;;ce4;-1;none;-1;
```

セミコロン区切り。推定される構造:
- `V:2:1` — ビデオトラック識別 (V=Video, 以降はインデックス)
- `2` — DRM グループ数
- (空) — 予約
- `ce4` — コーデック識別 (HEVC = ce4)
- `-1` — 品質レベル (-1 = auto)
- `none` — HDR タイプ (none = SDR)
- `-1` — 予約

---

## 8. ESN (Entertainment Service Name) フォーマット

```
NFAPPL-02-IPHONE9=1-5CB1D229FE1FC4DBA556753BB3D84634599DF9C15AD474BAFBFD37965D4162EC
```

- `NFAPPL` — Netflix Apple プラットフォーム
- `02` — DRM バージョン (FairPlay v2)
- `IPHONE9=1` — デバイスモデル (iPhone 7 = iPhone9,1、`=` は `,` のエスケープ)
- 末尾 64文字 — デバイス固有ハッシュ (SHA-256)

---

## 9. データの関連性まとめ

```
Manifest Response
  └─ playbackContextId ──→ License Request URL
  └─ video_tracks / audio_tracks ──→ drmSessionId / videoTrackName

License Request
  └─ challengeBase64.CHALLENGES[].ID ──→ License Response.RESPONSES[].ID (1:1 対応)
  └─ CHALLENGES[].PAYLOAD (FairPlay SPC) ──→ RESPONSES[].PAYLOAD (FairPlay CKC)

License Response
  └─ links.releaseLicense.href ──→ Release License Request URL
  └─ expiration ──→ standard: ~12h, limited_duration: ~60s
```
