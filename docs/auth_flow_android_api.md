# Netflix Android 認証フロー: API 詳細

> [auth_flow_android.md](auth_flow_android.md) のフロー概要と合わせて参照。

---

## 1. Phase 1: リクエスト送信

### 1.1 Appboot

デバイス登録と `nfvdid` Cookie の発行。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL Path | `{BaseESN}` | デバイス Base ESN (`NFANDROID1-PRV-P-L3-...`) |
| URL Query | `keyVersion` | デバイス鍵バージョン (`1`) |
| URL Query | `suspended` | アカウント停止フラグ (`false`) |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Header | `Content-Type` | `application/x-msl+json` |
| Header | `x-netflix-deviceidtoken` | デバイス ID トークン (324 bytes) |
| Header | `x-netflix.nfstatus` | Netflix ステータスコード (`1_1`) |
| Cookie | `nfvdid` | デバイス ID Cookie (更新) |
| Body | — | MSL JSON ペイロード |

> `x-netflix-deviceidtoken` は appboot レスポンスで発行されるが、後続の HTTP リクエストで送信される様子は観測されていない。MSL ペイロード内部またはローカル保持と推定される。

---

### 1.2 getProxyEsn (MSL)

新しい PXA ESN をサーバーから取得する。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.ftl` → `/nq/androidui/samurai/~9.0.0/api` |
| Body (MSL) | `url` | `/getProxyEsn` |

**レスポンス (MSL 復号後):**

| 場所 | フィールド | 説明 |
|---|---|---|
| Body | `result.esn` | 新しい PXA ESN (`NFANDROID1-PXA-P-L3-...`) |
| Body | `serverTime` | サーバータイムスタンプ |
| Body | `from` | レスポンス元 (`playapi`) |

> レスポンスは `proxyEsn.response` イベントで取得。アプリは `result.esn` を `proxyEsn.onKnown` でキャッシュに保存する。

---

### 1.3 aleProvision #1 (MSL)

ALE (Application Level Encryption) のための RSA 鍵交換。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.ftl` → `/nq/androidui/samurai/~9.0.0/api` |
| Body (MSL) | `url` | `/aleProvision` |
| Body (MSL) | `params.provisionRequest.keyx.scheme` | `RSA-OAEP-256` — 鍵交換アルゴリズム |
| Body (MSL) | `params.provisionRequest.keyx.data.pubkey` | RSA 公開鍵 (2048-bit, Base64) |
| Body (MSL) | `params.provisionRequest.scheme` | `A128GCM` — セッション暗号化方式 |
| Body (MSL) | `params.provisionRequest.type` | `SOCKETROUTER` — プロビジョニング種別 |
| Body (MSL) | `params.netflixClientPlatform` | `androidNative` |
| Body (MSL) | `params.appVer` | `63928` |
| Body (MSL) | `params.mId` | `GOOGLPIXEL=4A==5G=S` — Model ID |
| Body (MSL) | `params.ffbc` | `phone` — Form Factor |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Body | — | MSL 暗号化 (A128GCM セッション鍵を RSA-OAEP-256 で暗号化して返すと推定) |

---

### 1.4 RenewSSOToken (MSL → GraphQL)

SSO トークンの更新。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.cloud` → `/graphql` |
| Body (MSL) | `operationName` | `RenewSSOToken` |
| Body (MSL) | `variables.ssoToken` | 既存の SSO トークン (`BgiHtuvcAxL4AYwX...`) |
| Body (MSL) | `extensions.persistedQuery.id` | `a4d00303-b02d-47c9-a53f-776b6a63b001` |
| Body (MSL) | `extensions.persistedQuery.version` | `102` |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Body | — | MSL 暗号化 (SSO トークン更新結果) |

> `ssoToken` はこの API でのみ使用される。他の API で再利用される様子は観測されていない。

---

### 1.5 CurrentCountryQuery

国情報取得と認証 Cookie の発行。Non-MSL GraphQL。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.ftl` → `/graphql` |
| Cookie | `nfvdid` | デバイス識別子 |
| Body | — | GraphQL JSON (平文) |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Header | `Content-Type` | `application/json;charset=UTF-8` |
| Cookie | `NetflixId` | ユーザー認証 Cookie (新規発行) |
| Cookie | `SecureNetflixId` | セキュア認証 Cookie (HTTPS only, 新規発行) |
| Body | — | 国情報 JSON |

> 起動フローで最初に `NetflixId` / `SecureNetflixId` Cookie を発行するレスポンス。

---

### 1.6 InterstitialForProfileGate / InterstitialForLolomo (MSL → GraphQL)

プロフィール選択画面・ホーム画面のインタースティシャル (中間画面) チェック。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.cloud` → `/graphql` |
| Body (MSL) | `operationName` | `InterstitialForProfileGate` / `InterstitialForLolomo` |
| Body (MSL) | `variables.format` | `HTML` |
| Body (MSL) | `variables.resolutionMode` | `ANDROID_XHDPI` |
| Body (MSL) | `variables.imageFormat` | `PNG` |
| Body (MSL) | `variables.commonParameters.isConsumptionOnly` | `true` |
| Body (MSL) | `extensions.persistedQuery.id` | `18f3ae27-a0f1-45c9-88e6-c6bd39159ecb` (ProfileGate) |
| Body (MSL) | `extensions.persistedQuery.version` | `102` |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Body | — | MSL 暗号化 (インタースティシャル表示の要否) |

---

## 2. Phase 3: 追加リクエスト

### 2.1 AccountQuery (MSL → GraphQL)

アカウント基本情報の取得。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.cloud` → `/graphql` |
| Body (MSL) | `operationName` | `AccountQuery` |
| Body (MSL) | `extensions.persistedQuery.id` | `4043dd89-0ed5-4d7f-ac5c-40c7ffcec7ae` |
| Body (MSL) | `extensions.persistedQuery.version` | `102` |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Body | — | MSL 暗号化 (アカウント情報: プラン、プロフィール等) |

---

### 2.2 aleProvision #2 (MSL)

再鍵交換。#1 と同一の RSA 公開鍵を使用。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.ftl` → `/nq/androidui/samurai/~9.0.0/api` |
| Body (MSL) | — | aleProvision #1 と同一構造 (同一 RSA pubkey) |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Body | — | MSL 暗号化 (新セッション鍵 + PXA ESN) |

> このレスポンスの直後に `proxyEsn.response` → `proxyEsn.onKnown` で新 PXA ESN が確定・キャッシュされる。

---

### 2.3 PromoProfileGateVideoDataQuery

プロフィール画面データの取得。Non-MSL GraphQL。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.ftl` → `/graphql` |
| Cookie | `nfvdid` | デバイス識別子 |
| Cookie | `NetflixId` | ユーザー認証 Cookie |
| Cookie | `SecureNetflixId` | セキュア認証 Cookie |
| Body | — | GraphQL JSON (平文) |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Header | `Content-Type` | `application/json;charset=UTF-8` |
| Cookie | `NetflixId` | ユーザー認証 Cookie (リフレッシュ) |
| Cookie | `SecureNetflixId` | セキュア認証 Cookie (リフレッシュ) |
| Body | — | プロフィール画面データ JSON |

---

## 3. Phase 4: 遅延リクエスト

起動から約 30 秒後にバックグラウンドで送信される。

### 3.1 FetchConfigData (MSL → Samurai)

デバイス・ストリーミング設定の一括取得。

**リクエスト:**

| 場所 | フィールド | 説明 |
|---|---|---|
| URL | エンドポイント | `prod.ftl` → `/nq/androidui/samurai/v1/config` |
| Body (MSL) | `method` | `get` |
| Body (MSL) | `path` | `["deviceConfig"]`, `["hendrixConfig"]`, `["networkScoreConfig"]`, `["accountConfig"]` 等 |
| Body (MSL) | `appType` | `samurai` |

**レスポンス:**

| 場所 | フィールド | 説明 |
|---|---|---|
| Body | — | MSL 暗号化 (設定データ) |

---

### 3.2 AccountQuery #2 (MSL → GraphQL)

Phase 3 の AccountQuery と同一。キャッシュ更新のための再取得。

---

## 4. GraphQL Persisted Query パターン

Netflix Android は GraphQL の **Persisted Query** を使用する。クエリ本文は送信せず、事前登録済みの ID のみを指定する。

### 4.1 確認済みクエリ一覧

| operationName | persistedQuery ID | version | プロトコル | エンドポイント |
|---|---|---|---|---|
| `RenewSSOToken` | `a4d00303-b02d-47c9-a53f-776b6a63b001` | 102 | MSL | prod.cloud |
| `InterstitialForProfileGate` | `18f3ae27-a0f1-45c9-88e6-c6bd39159ecb` | 102 | MSL | prod.cloud |
| `InterstitialForLolomo` | *(未取得)* | 102 | MSL | prod.cloud |
| `AccountQuery` | `4043dd89-0ed5-4d7f-ac5c-40c7ffcec7ae` | 102 | MSL | prod.cloud |
| `CurrentCountryQuery` | *(未取得)* | — | non-MSL | prod.ftl |
| `PromoProfileGateVideoDataQuery` | *(未取得)* | — | non-MSL | prod.ftl |

### 4.2 MSL GraphQL vs Non-MSL GraphQL

| 特性 | MSL GraphQL | Non-MSL GraphQL |
|---|---|---|
| エンドポイント | `prod.cloud/graphql` | `prod.ftl/graphql` |
| ボディ暗号化 | MSL (CBOR → GZIP → JSON) | なし (平文 JSON) |
| 認証 | MSL Master Token | `NetflixId` / `SecureNetflixId` Cookie |
| レスポンス Cookie | `nfvdid` のみ | `nfvdid` + `NetflixId` + `SecureNetflixId` |

---

## 5. 完全タイムライン

| # | イベント | エンドポイント | API / 操作 | 備考 |
|---|---|---|---|---|
| 1 | `proxyEsn.forceExpired` | — | PXA ESN 期限チェック | Frida が強制失効 |
| 2 | `http.request` | appboot | `POST /appboot/{BaseESN}` | `keyVersion=1` |
| 3 | `proxyEsn.requestHeaders` | — | ヘッダー準備 | |
| 4 | `proxyEsn.request` | — | `/getProxyEsn` | |
| 5 | `msl.api` | prod.ftl | `/getProxyEsn` | MSL 平文 |
| 6 | `http.request` | prod.ftl | `samurai/~9.0.0/api` | MSL 暗号文 |
| 7 | `msl.api` | prod.ftl | `/aleProvision` #1 | RSA-OAEP-256 |
| 8 | `http.request` | prod.ftl | `samurai/~9.0.0/api` | MSL 暗号文 |
| 9 | `msl.api` | prod.cloud | `RenewSSOToken` | GraphQL Mutation |
| 10 | `http.request` | prod.cloud | `/graphql` | MSL 暗号文 |
| 11 | `http.request` | prod.ftl | `/graphql` | CurrentCountryQuery |
| 12 | `msl.api` | prod.cloud | `InterstitialForProfileGate` | |
| 13 | `msl.api` | prod.cloud | `InterstitialForLolomo` | |
| 14 | `http.request` | prod.cloud | `/graphql` | MSL 暗号文 |
| 15 | `http.request` | prod.cloud | `/graphql` | MSL 暗号文 |
| 16 | `http.response` | prod.ftl | CurrentCountryQuery | **+NetflixId [Cookie]** |
| 17 | `http.response` | prod.ftl | getProxyEsn | |
| 18 | `http.response` | prod.ftl | aleProvision #1 | |
| 19 | `msl.api` | prod.cloud | `AccountQuery` | |
| 20 | `http.request` | prod.cloud | `/graphql` | MSL 暗号文 |
| 21 | `http.response` | appboot | appboot | **+nfvdid [Cookie]** + DeviceIdToken |
| 22 | `http.response` | prod.cloud | RenewSSOToken | |
| 23 | `http.response` | prod.cloud | InterstitialForLolomo | |
| 24 | `http.response` | prod.cloud | InterstitialForProfileGate | |
| 25 | `http.response` | prod.cloud | AccountQuery | |
| 26 | `msl.api` | prod.ftl | `/aleProvision` #2 | 同一 RSA pubkey |
| 27 | `http.request` | prod.ftl | `samurai/~9.0.0/api` | MSL 暗号文 |
| 28 | `http.response` | prod.ftl | aleProvision #2 | |
| 29 | `proxyEsn.response` | — | 新 PXA ESN 受信 | |
| 30 | `proxyEsn.onKnown` | — | ESN キャッシュ保存 | `sn=8572399748193023` |
| 31 | `http.request` | prod.ftl | `/graphql` | PromoProfileGate |
| 32 | `http.response` | prod.ftl | PromoProfileGate | +NetflixId [Cookie] |
| 33 | `msl.api` | prod.ftl | FetchConfigData | Samurai config |
| 34 | `msl.api` | prod.cloud | `AccountQuery` #2 | |
| 35 | `http.request` | prod.ftl | `samurai/v1/config` | MSL 暗号文 |
| 36 | `http.request` | prod.cloud | `/graphql` | MSL 暗号文 |
| 37 | `http.response` | prod.cloud | AccountQuery #2 | |
| 38 | `http.response` | prod.ftl | FetchConfigData | |
