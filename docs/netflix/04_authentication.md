# 4. 認証フロー

[← 目次に戻る](specification.md)

---

## 4.1 Android 起動時認証フロー

アプリ起動時に以下の 4 フェーズで認証・プロビジョニングが行われる。起動時間を最小化するため、Phase 1 の全リクエストは**並列に送信**される。

```mermaid
%%{init: {'theme':'dark'}}%%
sequenceDiagram
    participant App as Netflix App
    participant AB as appboot
    participant FTL as prod.ftl<br/>(MSL API)
    participant Cloud as prod.cloud<br/>(GraphQL)

    Note over App: 起動
    App->>App: ProxyESN 期限チェック

    rect rgba(180, 100, 50, 0.2)
        Note over App,Cloud: Phase 1: リクエスト並列送信
        App->>AB: POST /appboot/{BaseESN}
        App->>FTL: [MSL] /getProxyEsn
        App->>FTL: [MSL] /aleProvision #1 (RSA鍵交換)
        App->>Cloud: [MSL] RenewSSOToken
        App->>FTL: CurrentCountryQuery
        App->>Cloud: [MSL] InterstitialForProfileGate
        App->>Cloud: [MSL] InterstitialForLolomo
    end

    rect rgba(50, 180, 80, 0.2)
        Note over App,Cloud: Phase 2: レスポンス受信
        FTL-->>App: CurrentCountryQuery → +NetflixId, SecureNetflixId [Cookie]
        FTL-->>App: getProxyEsn → MSL レスポンス
        FTL-->>App: aleProvision #1 → MSL レスポンス
        Cloud-->>App: RenewSSOToken → 200 OK
        AB-->>App: appboot → nfvdid [Cookie] + DeviceIdToken
        Cloud-->>App: InterstitialForLolomo → 200 OK
        Cloud-->>App: InterstitialForProfileGate → 200 OK
    end

    rect rgba(60, 120, 200, 0.2)
        Note over App,Cloud: Phase 3: 追加リクエスト
        App->>Cloud: [MSL] AccountQuery
        Cloud-->>App: AccountQuery → 200 OK
        App->>FTL: [MSL] /aleProvision #2 (RSA鍵交換)
        FTL-->>App: aleProvision #2 → 新 PXA ESN 発行
        App->>App: proxyEsn.onKnown (新ESN保存)
        App->>FTL: PromoProfileGateVideoDataQuery
        FTL-->>App: 200 OK + NetflixId, SecureNetflixId [Cookie]
    end

    rect rgba(150, 150, 150, 0.15)
        Note over App,Cloud: Phase 4: 遅延リクエスト (~30秒後)
        App->>FTL: [MSL] FetchConfigData
        App->>Cloud: [MSL] AccountQuery #2
        FTL-->>App: 200 OK
        Cloud-->>App: 200 OK
    end
```

## 4.2 Cookie フロー

```mermaid
%%{init: {'theme':'dark'}}%%
sequenceDiagram
    participant App as Netflix App
    participant AB as appboot
    participant FTL as prod.ftl
    participant Cloud as prod.cloud

    Note over App: 起動時: nfvdid (既存) のみ保持

    App->>AB: POST /appboot (nfvdid Cookie なし)
    App->>FTL: CurrentCountryQuery
    App->>Cloud: [MSL] RenewSSOToken

    FTL-->>App: set-cookie: NetflixId=..., SecureNetflixId=...
    Note over App: ← 認証 Cookie 取得

    AB-->>App: set-cookie: nfvdid=... (更新)<br/>x-netflix-deviceidtoken: ...
    Note over App: ← デバイス Cookie 更新 + Device ID Token 取得

    App->>FTL: PromoProfileGateVideoDataQuery
    Note over App: NetflixId / SecureNetflixId Cookie を送信
    FTL-->>App: set-cookie: NetflixId=..., SecureNetflixId=...
    Note over App: ← 認証 Cookie リフレッシュ
```

| Cookie 名 | 発行元 | 用途 | 発行タイミング |
|---|---|---|---|
| `nfvdid` | appboot | デバイス識別 | appboot レスポンス (`set-cookie`) |
| `NetflixId` | prod.ftl | ユーザー認証 | CurrentCountryQuery レスポンス |
| `SecureNetflixId` | prod.ftl | セキュア認証 (HTTPS only) | CurrentCountryQuery レスポンス |

**重要な観察:**
- MSL リクエストは Cookie に依存しない (MSL 独自の MasterToken + UserIdToken で認証)
- Non-MSL GraphQL は Cookie (`NetflixId` / `SecureNetflixId`) で認証する
- `nfvdid` は全リクエストに付与されるが、認証には直接使われない (デバイストラッキング用と推定される)

## 4.3 ログインフロー

```mermaid
%%{init: {'theme':'dark'}}%%
sequenceDiagram
    participant User as ユーザー
    participant App as Netflix App
    participant Server as Netflix Server

    App->>Server: RenewSSOToken
    Server-->>App: SSO トークン更新

    App->>App: InterstitialHook (ログイン画面初期化)

    User->>App: メールアドレス入力
    App->>Server: InterstitialScreenUpdate<br/>(email + reCAPTCHA)
    Note over Server: reCAPTCHA サイトキー:<br/>6LeWeOoUAAAAAJB9vW-<br/>OBEYmBwbF9R7PILe6U_ML

    Server-->>App: MFA OTP 要求 (4桁)
    User->>App: OTP 入力
    App->>Server: InterstitialScreenUpdate (OTP)

    App->>Server: MSL userauthdata (NETFLIXID)
    Note over App,Server: ← 初回認証

    Server-->>App: MasterToken + UserIdToken 発行

    App->>Server: AccountQuery (仮プロファイル)
    App->>Server: InterstitialSendFeedback (完了)
    App->>Server: AccountQuery (最終プロファイル確認)

    Note over App: /profiles に遷移
```

## 4.4 トークンライフサイクル

```mermaid
%%{init: {'theme':'dark'}}%%
graph LR
    subgraph Tokens["トークン管理"]
        MT["MasterToken<br/>有効期限: 不明<br/>(暗号化データ内)"]
        UIT["UserIdToken<br/>有効期限: 14日間"]
        PXA["PXA ESN<br/>TTL=0 (無期限)"]
    end

    MT -->|renewable + keyrequestdata| MT_NEW["自動更新"]
    UIT -->|サーバー自動更新<br/>(15回の更新を観測)| UIT_NEW["新 UIT"]
    PXA -->|masterTokenSerialNumber<br/>変更時のみ| PXA_NEW["再取得"]

    style MT fill:#e94560,stroke:#fff
    style UIT fill:#0f3460,stroke:#16213e
    style PXA fill:#533483,stroke:#16213e
```

| トークン | 有効期限 | 更新方式 |
|---|---|---|
| MasterToken | 不明 (暗号化されたデータ内) | `renewable` フラグ + `keyrequestdata` で自動更新 |
| UserIdToken | 14 日間 | サーバーが自動更新 (15 回の更新イベントを観測) |
| PXA ESN | 無期限 (TTL=0) | `masterTokenSerialNumber` 変更時のみ再取得 |

---

[← 前章: ESN 体系](03_esn.md) | [次章: API エンドポイント →](05_api_endpoints.md)
