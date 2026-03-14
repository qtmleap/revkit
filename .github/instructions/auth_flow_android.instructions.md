---
applyTo: 'hook_netflix_android.js,hook_msl.js,run_android.sh,docs/auth_flow_android*.md'
---

## Android 認証フロー (LLM 向け)

### ドキュメント構成

| ファイル | 内容 |
|---|---|
| `docs/auth_flow_android.md` | フロー概要・Mermaid 図・鍵交換・Cookie フロー・ProxyESN ライフサイクル・セキュリティ観察 |
| `docs/auth_flow_android_api.md` | 全 API のリクエスト/レスポンス詳細 (Header/Cookie/Body 表)・Persisted Query 一覧・完全タイムライン |

### 認証フロー要約

1. **Phase 0:** `ProxyEsn.$init` で PXA ESN の TTL チェック。期限切れなら再取得フラグ ON
2. **Phase 1:** 7 リクエストを並列送信 (appboot, getProxyEsn, aleProvision#1, RenewSSOToken, CurrentCountryQuery, Interstitial×2)
3. **Phase 2:** レスポンス受信。CurrentCountryQuery で `NetflixId`/`SecureNetflixId` Cookie 発行、appboot で `nfvdid` Cookie 更新
4. **Phase 3:** AccountQuery, aleProvision#2 (→PXA ESN 確定), PromoProfileGateVideoDataQuery
5. **Phase 4:** 約 30 秒後に FetchConfigData, AccountQuery#2

### エンドポイント

| 略称 | ホスト | 用途 |
|---|---|---|
| appboot | `android14.appboot.netflix.com` | デバイス登録 |
| prod.ftl | `android14.prod.ftl.netflix.com` | MSL API + non-MSL GraphQL |
| prod.cloud | `android14.prod.cloud.netflix.com` | MSL GraphQL |

### 認証方式の二重構造

- **MSL API** (`prod.cloud`, `prod.ftl` の MSL エンドポイント): Master Token + User Auth Data で認証。Cookie 不要
- **Non-MSL GraphQL** (`prod.ftl/graphql`): `NetflixId` / `SecureNetflixId` Cookie で認証

### 鍵交換

- アルゴリズム: RSA-OAEP-256 (鍵交換) + A128GCM (セッション暗号化)
- aleProvision は 2 回呼ばれる。#1 は起動直後、#2 は getProxyEsn レスポンス後
- 同一 RSA-2048 公開鍵を使用。サーバーが新セッション鍵を発行

### Frida フック固有の注意

- `hook_msl.js` が `ProxyEsn.$init` で `expired=true` を強制。通常は TTL が有効ならキャッシュ使用
- キャプチャ内の PXA ESN 再取得は Frida による強制失効の結果
