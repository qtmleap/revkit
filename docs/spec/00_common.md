# Netflix MSL クライアント共通仕様

プラットフォーム共通の MSL プロトコル、マニフェスト構造、セグメントダウンロード、復号の仕様。
プラットフォーム固有の認証・エンドポイント・DRM は各プラットフォーム別仕様を参照。

---

## 1. MSL メッセージ暗号化

### 1.1 エンベロープ構造

MSL レスポンスは複数の JSON オブジェクトが連結された形式:

```
{headerdata, signature, mastertoken}{payload, signature}{payload, signature}...
```

- 1つ目: ヘッダー (mastertoken 含む)
- 2つ目以降: ペイロードチャンク

### 1.2 ペイロード暗号化フォーマット

各ペイロードチャンクの `payload` を base64 デコードすると:

```json
{
  "ciphertext": "<base64(AES-CBC encrypted data)>",
  "sha256": "<base64(HMAC-SHA256)>",
  "keyid": "{ESN}_{sequence}",
  "iv": "<base64(16-byte IV)>"
}
```

### 1.3 復号手順

1. `iv` を base64 デコード (16バイト IV)
2. `ciphertext` を base64 デコード (暗号文)
3. MSL セッションの `encryption_key` (AES-128) と IV で AES-CBC 復号
4. PKCS7 パディング除去
5. 結果は JSON: `{data, messageid, compressionalgo, sequencenumber}`
6. `data` を base64 デコード → 圧縮されたペイロード本体
7. 圧縮展開 (gzip または LZW) → JSON

### 1.4 圧縮方式

| `compressionalgo` | 方式 | 使用プラットフォーム |
|-------------------|------|-------------------|
| (gzip magic `1f8b`) | gzip | StreamFab, Android |
| `LZW` | LZW | Chrome |

### 1.5 iOS CBOR MSL (JSON 形式との差異)

iOS は JSON ではなく **CBOR** (数値キー) でエンコードする。
詳細: [ios_msl_decrypt_pipeline.md](ios_msl_decrypt_pipeline.md)

主な差異:

- **IV**: JSON MSL では `"iv"` フィールドに格納。CBOR MSL では **ciphertext の先頭 16 bytes に prepend** (IV フィールドは空)
- **復号後 (リクエスト)**: CBOR bstr(9) ヘッダー + gzip 圧縮 JSON (Base64 経由なし)
- **復号後 (レスポンス)**: `00 00` ヘッダー + raw deflate 圧縮 JSON
- **鍵交換**: JSON MSL は `ASYMMETRIC_WRAPPED (JWK_RSA)`、CBOR MSL は **Scheme 3 (DH ベース)**

---

## 2. マニフェストレスポンス構造

### 2.1 トップレベル

```json
{
  "id": 1775356074,
  "version": 2,
  "serverTime": 1775356074742,
  "result": {
    "movieId": 81756595,
    "duration": 8523000,
    "drmType": "widevine",
    "drmVersion": 25,
    "drmContextId": "2596051",
    "playbackContextId": "E3-Bgilt-vcAxKKB...",
    "expiration": 1775399301816,
    "video_tracks": [...],
    "audio_tracks": [...],
    "timedtexttracks": [...],
    "servers": [...],
    "links": {
      "license": { "href": "/license?licenseType=standard&playbackContextId=...&esn=...&drmContextId=..." },
      "ldl": { "href": "/license?licenseType=limited&playbackContextId=...&esn=...&drmContextId=..." },
      "events": { "href": "/events?playbackContextId=...&esn=..." }
    }
  },
  "common": { "cadToken": "C1-Bgjtt-vcAxKMAQX..." },
  "from": "playapi"
}
```

`links.license.href` はライセンスチャレンジ時にそのまま使用する相対パス。

### 2.2 ビデオトラック

```json
{
  "trackType": "PRIMARY",
  "maxWidth": 1920,
  "maxHeight": 1080,
  "drmHeader": {
    "bytes": "AAAANHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABQIARIQAAAAAAloudsAAAAAAAAAAA==",
    "keyId": "AAAAAAloudsAAAAAAAAAAA==",
    "drmHeaderId": "000000000968b9db0000000000000000",
    "resolution": { "height": 540, "width": 960 }
  },
  "streams": [...]
}
```

- `drmHeader.bytes`: **PSSH ボックス** (base64)。Widevine CDM の `generateRequest` に渡す `initData`
- `drmHeader` は track レベルに 1 つだが、**KID 境界は stream レベル** (SD 鍵 / HD 鍵)

### 2.3 ビデオストリーム

```json
{
  "content_profile": "av1-main-L40-dash-cbcs-prk",
  "bitrate": 1412,
  "peakBitrate": 9675,
  "res_w": 1920,
  "res_h": 1080,
  "framerate_value": 24000,
  "framerate_scale": 1001,
  "size": 1511911636,
  "startByteOffset": 67372,
  "vmaf": 97,
  "drmHeaderId": "000000000968b9de0000000000000000",
  "downloadable_id": "1500103607",
  "isDrm": true,
  "moov": { "offset": 116, "size": 992 },
  "sidx": { "offset": 1108, "size": 33140 },
  "ssix": { "offset": 34248, "size": 33124 },
  "urls": [
    { "url": "https://{cdn_host}/?o=1&v=21&e={expiration}&t={token}", "cdn_id": 140752 }
  ]
}
```

| フィールド | 説明 |
|-----------|------|
| `content_profile` | コーデック + 暗号化スキーム識別子 |
| `drmHeaderId` | この stream の DRM Key ID (hex 32文字) |
| `downloadable_id` | Netflix 内部ストリーム ID |
| `urls[].url` | CDN ダウンロード URL (署名付き、有効期限あり) |
| `moov/sidx/ssix` | MP4 ボックスオフセット (セグメントインデックスに必要) |
| `startByteOffset` | メディアデータ開始位置 |
| `size` | 全セグメント合計サイズ (bytes) |

### 2.4 DRM スキーム対応表

| content_profile パターン | 暗号化スキーム | 暗号化方式 | 使用コーデック |
|-------------------------|--------------|-----------|-------------|
| `*-playready-*` | `cenc` | AES-128-CTR (全サンプル) | H.264 |
| `*-cenc-*` | `cenc` | AES-128-CTR (全サンプル) | HEVC |
| `*-cbcs-*` | `cbcs` | AES-128-CBC (サブサンプル 1/10) | AV1 |

**コーデックごとに異なる KID ペアが割り当てられる。** コーデック切り替え時はライセンス再取得が必要。

### 2.5 KID 境界 (実測)

同一コーデック内で 2 つの KID が使い分けられる:
- **SD** (540p 以下): SD 用 Key ID
- **HD** (720p 以上): HD 用 Key ID

### 2.6 オーディオトラック

| ソース | プロファイル | チャンネル | ビットレート |
|--------|------------|-----------|------------|
| licensedmanifest | `ddplus-5.1-dash`, `ddplus-5.1hq-dash` | 5.1 | 192, 256, 384, 448, 640 kbps |
| manifest API | `xheaac-dash` | 2.0 | 32, 64, 96, 192 kbps |

licensedmanifest は 19 言語で 5.1ch を提供。manifest API は 2.0ch のみ。

### 2.7 CDN サーバー

```json
{
  "dns": { "host": "...", "ipv6": "...", "ipv4": "..." },
  "id": 140752,
  "rank": 1,
  "type": "OPEN_CONNECT_APPLIANCE",
  "name": "c014.tyo013.ix.nflxvideo.net"
}
```

`rank` が低いほど優先。`urls[].cdn_id` と `servers[].id` で対応付ける。

---

## 3. セグメントダウンロード

### 3.1 CDN URL 構造

```
https://{cdn_host}/?o=1&v={version}&e={expiration_unix}&t={signature_token}
```

| パラメータ | 説明 |
|-----------|------|
| `o` | 常に 1 |
| `v` | CDN バージョン (21, 22 等) |
| `e` | URL 有効期限 (Unix timestamp) |
| `t` | 署名トークン (base64url) |

### 3.2 DASH セグメントダウンロード手順

1. `Range: bytes=0-{moov.offset + moov.size - 1}` で初期化セグメントを取得
2. `sidx` をパースしてセグメント一覧 (バイトレンジ + 時間) を構築
3. 各セグメントを `Range` リクエストで取得

---

## 4. 復号

### 4.1 復号フロー

```
encrypted_segment + content_key(KID) → decrypted_segment
```

1. セグメントの `moof` ボックスから `tenc` (Track Encryption Box) を読み取り
2. `senc` (Sample Encryption Box) から各サンプルの IV を取得
3. Key ID に対応するコンテンツ鍵で AES-CTR (cenc) または AES-CBC (cbcs) 復号

### 4.2 Widevine ライセンスフロー (共通)

1. マニフェストの `drmHeader.bytes` (PSSH, base64) をデコード
2. Widevine CDM `generateRequest("cenc", psshBytes)` → `license-request` (protobuf, ~4000 bytes)
3. MSL 経由で `/pbo_licenses/router` に POST
4. レスポンスから `license-response` (protobuf, ~1000 bytes) 取得
5. CDM `update(licenseResponse)` でコンテンツ鍵インストール

---

## 5. 有効期限

| 項目 | フィールド | 典型値 |
|------|-----------|-------|
| マニフェスト | `expiration` | ~8 時間 (`manifestExpirationDuration`) |
| CDN URL | `e` パラメータ | ~12 時間 (`urlExpirationDuration`) |
| Cookie | セッション依存 | 数日〜数週間 |
