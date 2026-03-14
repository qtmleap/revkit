# Netflix Android 9.57.0 — HTTP ヘッダー & Cookie リファレンス

Frida `hook_headers.js` (Cronet フック) により 1,274 リクエストをキャプチャして整理。

---

## 通信経路

| 経路 | 用途 | ライブラリ |
|---|---|---|
| Cronet (メイン) | 通常 HTTP (API, config, GraphQL, logs) | `org.chromium.net.impl.CronetUrlRequest` |
| OkHttp | WebSocket 接続のみ | `okhttp3.internal.connection.RealCall` |

---

## Cookie 一覧

| Cookie 名 | 出現頻度 | 説明 |
|---|---|---|
| `nfvdid` | 1,271/1,274 | Netflix Virtual Device ID。Base64url エンコードされたバイナリ |
| `flwssn` | 1,271/1,274 | Flow Session ID。UUID v4 形式 |
| `gsid` | 1,166/1,274 | GraphQL Session ID。UUID v4 形式。ログイン後に付与 |
| `NetflixId` | 105/1,274 | ユーザー認証 Cookie。未ログイン時は送信されない |
| `SecureNetflixId` | 105/1,274 | HMAC 署名付き認証 Cookie。NetflixId と常にペア |

### Cookie 値の構造

```
nfvdid=BQFmAAEBEEPj84LzHGpQ_ldxaVuQv8tgIBE9VAe3w-WeF5En4w5goMB6eLYVXqxblfzh23QC62wkeecr...
  → Base64url エンコードされたバイナリトークン

flwssn=183a999e-9ce9-4f29-ac9f-3f8b3982c817
  → UUID v4 (セッション単位で変化)

gsid=d4779eb6-16d4-4179-89af-a069f7f1fc07
  → UUID v4 (ログイン後に生成)

NetflixId=v%3D3%26ct%3DBgjHlOvcAxKoAo...
  → URL エンコード済み。デコードすると: v=3&ct=<base64url>&pg=<profile_guid>&ch=<checksum>

SecureNetflixId=v%3D3%26mac%3DAQEAEQABABTPJ-U_...%26dt%3D1773402757629
  → URL エンコード済み。デコードすると: v=3&mac=<hmac>&dt=<epoch_ms>
```

### Cookie の送信パターン

| エンドポイント種別 | nfvdid | flwssn | gsid | NetflixId | SecureNetflixId |
|---|---|---|---|---|---|
| appboot | - | - | - | - | - |
| config (GET, 未ログイン) | ✓ | ✓ | - | ✓ | ✓ |
| graphql (ftl, 未ログイン) | ✓ | ✓ | - | ✓ | ✓ |
| pathEvaluator | ✓ | ✓ | - | ✓ | ✓ |
| cl/2 (ログ) | ✓ | ✓ | - | ✓ | ✓ |
| graphql (MSL 暗号化) | ✓ | ✓ | ✓ | - | - |
| config (POST, MSL) | ✓ | ✓ | ✓ | - | - |
| logblob | ✓ | ✓ | ✓ | - | - |

**パターン**: MSL 暗号化 (`Content-Encoding: msl_v1`) リクエストでは `NetflixId`/`SecureNetflixId` が省略され、代わりに `gsid` が付与される。平文リクエストではその逆。

---

## ヘッダー一覧

### 共通ヘッダー (ほぼ全リクエストに存在)

| ヘッダー | 値の例 | 説明 |
|---|---|---|
| `X-Netflix.Request.Client.Context` | `{"appState":"background","appView":"login"}` | アプリ状態の JSON |
| `X-Netflix.zuul.brotli.allowed` | `true` | Brotli 圧縮許可 |
| `X-Netflix.Request.Attempt` | `1` | リトライ番号 |
| `X-Netflix.Request.Id` | `afa97a02e3a349807ca65a0517e386c7` | リクエスト一意 ID (hex) |
| `X-Netflix.Client.Request.Name` | `FetchConfigDataWebRequest` | リクエスト種別名 |

### デバイス識別ヘッダー

| ヘッダー | 値 | 説明 |
|---|---|---|
| `X-Netflix.clientType` | `samurai` | クライアント種別 (Android = samurai) |
| `X-Netflix.deviceMemoryLevel` | `HIGH` | メモリレベル |
| `X-Netflix.appVer` | `9.57.0` | アプリバージョン |
| `X-Netflix.esnPrefix` | `NFANDROID1-PRV-P-L3-` | ESN プレフィックス (PRV) |
| `X-Netflix.androidApi` | `34` | Android API レベル |
| `X-Netflix.esn` | `NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-...` | フル PXA ESN |
| `X-Netflix.deviceFormFactor` | `PHONE` | フォームファクタ |

### セッション・コンテキストヘッダー

| ヘッダー | 値の例 | 説明 |
|---|---|---|
| `X-Netflix.session.id` | `1773552898264781980` | セッション ID (数値) |
| `x-netflix.client.current-profile-guid` | `ZEULH5S2GNGCRAABCSG6J2EGGA` | 現在のプロファイル GUID |
| `X-Netflix.request.uuid` | UUID v4 | リクエスト UUID |
| `X-Netflix.request.toplevel.uuid` | UUID v4 | トップレベルリクエスト UUID |
| `X-Netflix.tracing.cl.userActionId` | UUID v4 | ユーザーアクション追跡 ID |

### コンテキストヘッダー (`x-netflix.context.*`)

| ヘッダー | 値 | 説明 |
|---|---|---|
| `x-netflix.context.os-version` | `34` | OS バージョン |
| `x-netflix.context.app-version` | `9.57.0` | アプリバージョン |
| `x-netflix.context.locales` | `en-US` or `en-JP` | ロケール |
| `x-netflix.context.ui-flavor` | `android` | UI プラットフォーム |
| `x-netflix.context.form-factor` | `phone` | デバイス形状 |
| `x-netflix.context.android.installer-source` | `com.android.vending` | インストール元 |
| `x-netflix.context.operation-name` | `CurrentCountryQuery` | GraphQL オペレーション名 |
| `x-netflix.context.feature-capabilities` | `supportsStudioBranding` | 機能フラグ |
| `x-netflix.context.hawkins-version` | `5.13.0` | Hawkins バージョン |

### MSL 関連ヘッダー

| ヘッダー | 値 | 説明 |
|---|---|---|
| `Content-Encoding` | `msl_v1` | MSL 暗号化ボディ |
| `x-netflix.client.android.mslrequest` | `true` | MSL リクエストフラグ |
| `x-netflix.client.request.transport` | `http` | トランスポート種別 |

### その他

| ヘッダー | 値 | 説明 |
|---|---|---|
| `X-Netflix-Internal-Volley-Priority` | `NORMAL` / `HIGH` / `null` | Volley 優先度 |
| `x-netflix.playback.main-content-viewable-id` | `81650338` | 再生中コンテンツ ID |
| `X-Netflix.Request.Routing` | JSON | ルーティング設定 |
| `X-Netflix.Request.NqTracking` | リクエスト名 | NQ 追跡用 |
| `debugRequest` | `true` | デバッグフラグ (ログ系) |
| `x-netflix.request.clcs.bucket` | `high` | CLCS バケット |

---

## エンドポイント一覧

### 1. appboot (POST)
```
POST https://android14.appboot.netflix.com/appboot/NFANDROID1-PRV-P-L3-?keyVersion=1&suspended=false
Content-Type: application/x-www-form-urlencoded
Cookies: なし
```
アプリ起動時の初期化。ESN プレフィックスが URL パスに含まれる。Cookie なし。

### 2. config (GET)
```
GET https://android14.prod.ftl.netflix.com/nq/androidui/samurai/v1/config?method=get&path=...
Cookies: nfvdid, flwssn, NetflixId, SecureNetflixId
```
デバイス設定・機能フラグ取得。URL クエリに大量のデバイス情報を含む。

### 3. samurai API (POST)
```
POST https://android14.prod.ftl.netflix.com/nq/androidui/samurai/~9.0.0/api?method=get&...
Cookies: nfvdid, flwssn (+ NetflixId/SecureNetflixId or gsid)
```
メイン API エンドポイント。再生マニフェスト取得 (`licensedManifest`) 等。

### 4. GraphQL — ftl (POST)
```
POST https://android14.prod.ftl.netflix.com/graphql
Content-Type: application/json
Cookies: nfvdid, flwssn, NetflixId, SecureNetflixId
```
GraphQL API (平文)。`CurrentCountryQuery` 等。

### 5. GraphQL — cloud (POST, MSL)
```
POST https://android.prod.cloud.netflix.com/graphql
Content-Encoding: msl_v1
Content-Type: application/json
Cookies: flwssn, nfvdid, gsid
```
GraphQL API (MSL 暗号化)。`InterstitialHook`, `AccountQuery` 等。

### 6. pathEvaluator (POST)
```
POST https://android.prod.cloud.netflix.com/nq/aui/endpoint/^1.0.0-mobile/pathEvaluator
Cookies: nfvdid, flwssn, NetflixId, SecureNetflixId
```
UI パス評価。Falcor ベースのデータフェッチ。

### 7. cl/2 ログ (POST)
```
POST https://android14.logs.netflix.com/log/android/cl/2?TAG=LOG_CLV2
Content-Type: application/json
Cookies: nfvdid, flwssn, NetflixId, SecureNetflixId
```
クライアントログ送信 (平文)。

### 8. logblob (POST, MSL)
```
POST https://android14.logs.netflix.com/log/android/logblob/1
Content-Encoding: msl_v1
Cookies: flwssn, nfvdid, gsid
```
バイナリログ送信 (MSL 暗号化)。

---

## cURL 例

### config 取得 (全ヘッダー付き)
```bash
curl -X GET \
  "https://android14.prod.ftl.netflix.com/nq/androidui/samurai/v1/config?method=get&responseFormat=json" \
  -H "X-Netflix.clientType: samurai" \
  -H "X-Netflix.appVer: 9.57.0" \
  -H "X-Netflix.esnPrefix: NFANDROID1-PRV-P-L3-" \
  -H "X-Netflix.esn: NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-..." \
  -H "X-Netflix.androidApi: 34" \
  -H "X-Netflix.deviceFormFactor: PHONE" \
  -H "X-Netflix.deviceMemoryLevel: HIGH" \
  -H "X-Netflix.session.id: 7994808" \
  -H "X-Netflix.zuul.brotli.allowed: true" \
  -H "X-Netflix.Request.Attempt: 1" \
  -H "X-Netflix.Request.Id: $(uuidgen | tr -d '-')" \
  -H "X-Netflix.Client.Request.Name: FetchConfigDataWebRequest" \
  -H "X-Netflix.Request.Client.Context: {\"appState\":\"foreground\",\"appView\":\"home\"}" \
  -H "x-netflix.context.os-version: 34" \
  -H "x-netflix.context.app-version: 9.57.0" \
  -H "x-netflix.context.locales: en-US" \
  -H "x-netflix.context.ui-flavor: android" \
  -H "x-netflix.context.form-factor: phone" \
  -H "x-netflix.context.android.installer-source: com.android.vending" \
  -b "nfvdid=<NFVDID>; flwssn=<UUID>; NetflixId=<NETFLIX_ID>; SecureNetflixId=<SECURE_NETFLIX_ID>"
```

### GraphQL (MSL 暗号化)
```bash
curl -X POST \
  "https://android.prod.cloud.netflix.com/graphql" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: msl_v1" \
  -H "X-Netflix.clientType: samurai" \
  -H "X-Netflix.appVer: 9.57.0" \
  -H "X-Netflix.esnPrefix: NFANDROID1-PRV-P-L3-" \
  -H "X-Netflix.androidApi: 34" \
  -H "X-Netflix.deviceFormFactor: PHONE" \
  -H "X-Netflix.deviceMemoryLevel: HIGH" \
  -H "X-Netflix.zuul.brotli.allowed: true" \
  -H "x-netflix.client.android.mslrequest: true" \
  -H "x-netflix.context.operation-name: AccountQuery" \
  -H "X-Netflix.Client.Request.Name: AccountQuery" \
  -H "X-Netflix.Request.Attempt: 1" \
  -H "X-Netflix.Request.Id: $(uuidgen | tr -d '-')" \
  -H "accept: multipart/mixed;deferSpec=20220824, application/graphql-response+json, application/json" \
  -b "flwssn=<UUID>; nfvdid=<NFVDID>; gsid=<UUID>" \
  -d '<MSL_ENCRYPTED_BODY>'
```

---

## ESN の送信箇所 (HTTP ヘッダー経由)

| ヘッダー | 値の種類 | 出現頻度 |
|---|---|---|
| `X-Netflix.esn` | フル PXA ESN | 707/1,274 |
| `X-Netflix.esnPrefix` | PRV プレフィックス (`NFANDROID1-PRV-P-L3-`) | 1,210/1,274 |
| URL パス (appboot) | PRV プレフィックス | appboot のみ |

**注**: `X-Netflix.esn` は PXA (Proxy) ESN が送られる。PRV (Private) ESN はプレフィックスのみ。
