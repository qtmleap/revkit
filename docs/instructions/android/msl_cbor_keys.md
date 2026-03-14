# MSL CBOR 整数キーマッピング — リファレンス

MSL プロトコルの CBOR エンコード時に使用される固定整数キー。
JSON の文字列キーをサイズ削減のため整数に置換する仕組みで、`MslEncoderFactory` にハードコードされている。

353 件の暗号化前 MessageHeader + 403 件の PayloadChunk の CBOR 解析により確定。

---

## 全整数キー一覧

| CBOR キー | JSON フィールド名 | 使用コンテキスト |
|---|---|---|
| `11` | `issuedate` | UserIdToken.tokendata |
| `12` | `mtserialnum` | UserIdToken.tokendata |
| `13` | `expiration` | UserIdToken.tokendata |
| `14` | `sequencenumber` | PayloadChunk |
| `15` | `tokendata` | MasterToken, UserIdToken, keyrequestdata (共通) |
| `16` | `signature` | MasterToken, UserIdToken, keyrequestdata (共通) |
| `17` | `mastertoken` | MessageHeader |
| `18` | `useridtoken` | MessageHeader |
| `19` | `renewable` | MessageHeader |
| `20` | `sender` | MessageHeader |
| `21` | `handshake` | MessageHeader |
| `22` | `messageid` | MessageHeader, PayloadChunk |
| `24` | `timestamp` | MessageHeader |
| `25` | `serialnumber` | MasterToken.tokendata, UserIdToken.tokendata |
| `26` | `renewable` | MasterToken.tokendata |
| `27` | `issuer` | MasterToken.tokendata |
| `28` | `identity` | MasterToken.tokendata |
| `29` | `userdata` | UserIdToken.tokendata |
| `30` | `scheme` | keyrequestdata, userauthdata |
| `31` | `keydata` | keyrequestdata |
| `35` | `authdata` | userauthdata |
| `36` | `capabilities` | MessageHeader |
| `37` | `compressionalgos` | capabilities |
| `38` | `languages` | capabilities |
| `39` | `encoders` | capabilities |
| `40` | `peer` | MessageHeader |
| `41` | `nonreplayableid` | MessageHeader |
| `42` | `keyrequestdata` | MessageHeader |
| `43` | `sequencenumber` | MasterToken.tokendata |
| `44` | `compressionalgo` | PayloadChunk |
| `47` | `userauthdata` | MessageHeader |
| `50` | `cdmsg` | keyrequestdata.keydata (Widevine) |
| `56` | `netflixid` | userauthdata.authdata (NETFLIXID) |
| `60` | `securenetflixid` | userauthdata.authdata (NETFLIXID) |
| `62` | `data` | PayloadChunk |
| `63` | `endofmsg` | PayloadChunk |

## 文字列キー (整数マッピングなし)

| キー | 使用コンテキスト |
|---|---|
| `maxpayloadchunksize` | capabilities |
| `profileid` | UserIdToken.tokendata |
| `duid` | keyrequestdata.keydata |

---

## MessageHeader 構造

```
MessageHeader (暗号化前 headerdata):
├─ 17: mastertoken        → list[ {15: tokendata, 16: signature} ]
├─ 18: useridtoken         → {15: tokendata, 16: signature}
├─ 19: renewable           → bool
├─ 20: sender              → string (ESN)
├─ 21: handshake           → bool
├─ 22: messageid           → int
├─ 24: timestamp           → int (Unix秒)
├─ 36: capabilities
│   ├─ 37: compressionalgos → list
│   ├─ 38: languages        → list
│   ├─ 39: encoders         → list
│   └─ maxpayloadchunksize  → int
├─ 40: peer                → bool
├─ 41: nonreplayableid     → int
├─ 42: keyrequestdata      → list[ {30: scheme, 31: keydata} ]
└─ 47: userauthdata        → {30: scheme, 35: authdata}
```

## PayloadChunk 構造

```
PayloadChunk (暗号化前):
├─ 14: sequencenumber  → int
├─ 22: messageid       → int
├─ 44: compressionalgo → string ("GZIP")
├─ 62: data            → bytes (GZIP圧縮ペイロード)
└─ 63: endofmsg        → bool
```

## MasterToken tokendata 構造

```
MasterToken.tokendata (key 17[].15 を CBORデコード):
├─ 25: serialnumber    → int
├─ 26: renewable       → bool
├─ 27: issuer          → string ("sf", "cad")
├─ 28: identity        → bytes (暗号化済み)
└─ 43: sequencenumber  → int
```

## UserIdToken tokendata 構造

```
UserIdToken.tokendata (key 18.15 を CBORデコード):
├─ 11: issuedate       → int (Unix秒)
├─ 12: mtserialnum     → int (紐づくMasterTokenシリアル)
├─ 13: expiration      → int (Unix秒, 発行から14日後)
├─ 25: serialnumber    → int
├─ 29: userdata        → bytes (暗号化済み)
└─ profileid           → string (プロファイルGUID)
```

## userauthdata 構造 (NETFLIXID スキーム)

```
userauthdata (key 47):
├─ 30: scheme   → "NETFLIXID"
└─ 35: authdata
    ├─ 56: netflixid       → string (URLエンコード)
    │   例: v=3&mac=AQEAEQABABQxZyPp7r91RNj4pmPTIatYcL3jjIUVbvQ.&dt=1773392547767
    └─ 60: securenetflixid → string (URLエンコード)
        例: v=3&ct=<暗号化トークン>&pg=<プロファイルGUID>&ch=<HMAC>
```

### netflixid のパラメータ

| パラメータ | 説明 |
|---|---|
| `v` | バージョン (`3`) |
| `mac` | HMAC 署名 |
| `dt` | デバイスタイムスタンプ (Unix ms) |

### securenetflixid のパラメータ

| パラメータ | 説明 |
|---|---|
| `v` | バージョン (`3`) |
| `ct` | 暗号化認証トークン (protobuf base64url) |
| `pg` | プロファイル GUID |
| `ch` | チャネル HMAC |

---

## ユーザー認証フロー

1. **初回認証 (1回)**: key 47 (`userauthdata`) に NETFLIXID スキームで netflixId + secureNetflixId を送信
2. **サーバー応答**: UserIdToken を発行 (有効期間 14日)
3. **以降のリクエスト (348回観測)**: key 18 (`useridtoken`) で認証。userauthdata は送信しない

353件の MSL ヘッダーのうち userauthdata を含むのは **1件のみ** (0.3%)。
apiRequest の第5引数 (`UserAuthenticationData`) は常に null — MslControl 層が内部で設定する。

---

## キャプチャ実データ

### Phase 1: 初回ハンドシェイク (Widevine 鍵交換)

ソース: `crypto/0002_msl.widevine.encrypt.json` (2026-03-13T09:00:02.108Z)

userauthdata なし、useridtoken なし。Widevine 鍵交換のみ。

```
MessageHeader:
  key 17 (mastertoken): list (len=1)
    [0].15 (tokendata): <bytes 153>
    [0].16 (signature): <bytes 44>
  key 19 (renewable): false
  key 20 (sender): ""
  key 21 (handshake): true
  key 22 (messageid): 5608206180487888
  key 24 (timestamp): 1773392401
  key 36 (capabilities):
    37 (compressionalgos): []
    38 (languages): ["GZIP", "LZW"]
    39 (encoders): ["CBOR"]
    maxpayloadchunksize: -1
  key 40 (peer): false
  key 42 (keyrequestdata): list (len=1)
    [0].30 (scheme): "WIDEVINE"
    [0].31 (keydata): {duid: <bytes 32>, 50 (cdmsg): <bytes 2577>}
```

### Phase 2: userauthdata 送信 (NETFLIXID 認証, 1回のみ)

ソース: `android14.prod.ftl.netflix.com/0052_msl.widevine.encrypt.json` (2026-03-13T09:02:28.168Z)

```
MessageHeader:
  key 17 (mastertoken): list (len=1)
  key 19 (renewable): false
  key 20 (sender): ""
  key 21 (handshake): true
  key 22 (messageid): 2491352839960294
  key 24 (timestamp): 1773392548
  key 36 (capabilities): {37: [], 38: ["GZIP","LZW"], 39: ["CBOR"], maxpayloadchunksize: -1}
  key 40 (peer): true
  key 41 (nonreplayableid): 10
  key 42 (keyrequestdata): list (len=1)
    [0].30 (scheme): "WIDEVINE"
  key 47 (userauthdata):
    30 (scheme): "NETFLIXID"
    35 (authdata):
      56 (netflixid): "v=3&mac=AQEAEQABABQxZyPp7r91RNj4pmPTIatYcL3jjIUVbvQ.&dt=1773392547767"
      60 (securenetflixid): "v=3&ct=BgjHlOvcAxLcA5Nned7dv-Iq5m2f7a5MNrKy8VAkRdBzSXaHjTsiFmEI
        -etnBrrNnCGzam9tRfUqnfVpjLaK3eFk79_6Jcsspf05U_HMC9CnJ3vy0tUhQatCl9ma2mrGqIWMm6fBWX11
        CofiJwnM-OpAzHO3fO5AJwHFSMwa7pCucoXbyjee_5tLcNdykJrEGPRnjJRc6DPfaYAJN4sDgCJptsO1Ssfw
        A0CTujgVhkf4r7S-HloF7BOktKT_dwzw2ULtuZXg5uC0XySU6Phk9y-jRjqQ9LvpVD-E9mXrKMAH23yxAI5
        Ku-YRnmTOEMhk92gJBVTwnHJAe13NihHhF-aHxXDfBcMkWPHDT6-raPJ3HClitacWIoWQ2AH0q5WRrm1XBMg
        A4KuNIepWOfJV9AGRVAfGoKpxbLjU6ajSx1KiD9o5KkaZ1yvEvlxtAxbISivsKhVocRN7Lt12W_9jsuUZbL-f
        urw4jGezz5lHUNLSkh4suuiVYdAMMkhyPnbC1pTKE-fRxd2stJ0uuOAord3hrUbKyDK5g_nbvRSXZFW1sLb22
        691pj5FnCxhkJquZtoW67Iwa7hVo9Jg5cUVSNvbuVLC0hmRotilPJujiaLz-XQty0SUaWv-WArtj-aEXjYKa3
        DuGAYiDgoMGowgnSHIWWhHgSZz&pg=ZEULH5S2GNGCRAABCSG6J2EGGA&ch=AQEAEAABABTp79nN9l_2MuRh
        qTXl0-SjAqcm83QU8vw."
```

#### netflixid デコード

```
v=3
mac=AQEAEQABABQxZyPp7r91RNj4pmPTIatYcL3jjIUVbvQ.
dt=1773392547767
```

#### securenetflixid デコード

```
v=3
ct=BgjHlOvcAxLcA5Nned7dv-Iq5m2f7a5MNrKy8VAk...  (672文字, 暗号化認証トークン)
pg=ZEULH5S2GNGCRAABCSG6J2EGGA                    (プロファイル GUID)
ch=AQEAEAABABTp79nN9l_2MuRhqTXl0-SjAqcm83QU8vw. (チャネル HMAC)
```

### Phase 3: 通常リクエスト (UserIdToken 認証, 348回)

ソース: `android14.prod.cloud.netflix.com/0002_msl.widevine.encrypt.json` (2026-03-13T09:00:02.415Z)

```
MessageHeader:
  key 17 (mastertoken): list (len=2)
  key 18 (useridtoken):
    15 (tokendata): <bytes 296>
    16 (signature): 01010081000101204005d2ae93a88d111b34aecb30b911f634e542d41c97f8f8a305af3850d3e9a22de3595d
  key 19 (renewable): false
  key 20 (sender): ""
  key 21 (handshake): false
  key 22 (messageid): 491822966207012
  key 24 (timestamp): 1773392402
  key 36 (capabilities): {37: [], 38: ["GZIP","LZW"], 39: ["CBOR"], maxpayloadchunksize: -1}
  key 40 (peer): false
```

#### UserIdToken tokendata (CBOR decoded)

```
  11 (issuedate):    1773420422  (2026-03-13T16:47:02+00:00)
  12 (mtserialnum):  8079134327147185
  13 (expiration):   1774601222  (2026-03-27T08:47:02+00:00)  ← 発行から14日後
  25 (serialnumber): 5970945423176003
  29 (userdata):     <bytes 217> (暗号化済み)
  profileid:         "ZEULH5S2GNGCRAABCSG6J2EGGA"
```

---

## ログインフロー キャプチャ実データ

セッション `android_20260313` で実際に観測されたログイン〜認証完了までの全リクエスト。
ドメインが `android.prod.cloud.netflix.com` (MSL v14 ではない旧ドメイン) の場合は `userId: null` で未認証状態。

### Step 1: RenewSSOToken (既存セッション更新の試行)

```
ts: 2026-03-13T09:00:02.245Z
domain: android14.prod.cloud.netflix.com
userId: ZEULH5S2GNGCRAABCSG6J2EGGA
userauthdata: null
```

```json
{
  "operationName": "RenewSSOToken",
  "variables": {
    "ssoToken": "BgiHtuvcAxL4AWLUqSE7W14gsbHZBDGMle4StHvRnr70_-VHofvb_wqAIEYDS3SmOscABWcD-0O-ibsEZPZYT3R7kUeCsJ14vV6crTlZY5DozcjvtZbtjykI8sqaQzMNtrOq1Af9lZemVLhi5FqnmNp7uy2RpwwiCqojwvVWzmKRzeOKStqUHDSIdzAofrErd6kAsfoJZleWTV87eSx2gyAa9mIauY_A51-rE2lOaTj19CeVaTeqSrWZMqWzuZ0OaYfqVZkuUf7CZ1bW1NTtlxS3mo17dmxIhpIfX8CFf26dp1Ggui93k_2dNbOF4_8e_whkxNBpTNh1RMmalk11gJocGAYiDgoMYoDsMZdYw3vL-Wdq"
  },
  "extensions": {
    "persistedQuery": {
      "version": 102,
      "id": "a4d00303-b02d-47c9-a53f-776b6a63b001"
    }
  }
}
```

### Step 2: InterstitialHook (ログイン画面初期化)

```
ts: 2026-03-13T09:01:29.542Z
domain: android.prod.cloud.netflix.com
userId: null  ← 未認証
userauthdata: null
```

```json
{
  "operationName": "InterstitialHook",
  "variables": {
    "flowName": "loginMobile",
    "format": "HTML",
    "resolutionMode": "ANDROID_XHDPI",
    "imageFormat": "PNG",
    "parameters": null,
    "commonParameters": {
      "isConsumptionOnly": true,
      "isNetflixPreloaded": false,
      "channelId": "",
      "androidInstallType": "regular"
    }
  },
  "extensions": {
    "persistedQuery": {
      "version": 102,
      "id": "bb592c79-c026-44e3-a989-ddba298d5eaf"
    }
  }
}
```

### Step 3: InterstitialScreenUpdate — メールアドレス送信 + reCAPTCHA

```
ts: 2026-03-13T09:02:12.214Z
domain: android.prod.cloud.netflix.com
userId: null  ← 未認証
userauthdata: null
```

```json
{
  "operationName": "InterstitialScreenUpdate",
  "variables": {
    "serverState": {
      "realm": "growth",
      "name": "IDENTIFICATION",
      "clcsSessionId": "74a682e9-d991-4d03-a2e4-aa130cdd1623",
      "sessionContext": {
        "session-breadcrumbs": { "funnel_name": "loginMobile" },
        "MobileLoginSessionContext": {}
      },
      "hellfireSessionId": "d1141445-134a-37ae-b91f-efe6902155e1"
    },
    "serverScreenUpdate": {
      "realm": "custom",
      "name": "growthProcessLogin",
      "metadata": {
        "recaptchaSiteKey": "6LeWeOoUAAAAAJB9vW-OBEYmBwbF9R7PILe6U_ML"
      },
      "loggingAction": "Submitted",
      "loggingCommand": "SubmitCommand"
    },
    "inputFields": [
      { "name": "userLoginId",           "value": { "stringValue": "lemonandchan+5@gmail.com" } },
      { "name": "countryCode",           "value": { "stringValue": "81" } },
      { "name": "countryIsoCode",        "value": { "stringValue": "JP" } },
      { "name": "password",              "value": { "stringValue": "" } },
      { "name": "recaptchaResponseTime", "value": { "intValue": 1231 } },
      { "name": "recaptchaResponseToken","value": { "stringValue": "<reCAPTCHA token ~4KB>" } }
    ]
  },
  "extensions": {
    "persistedQuery": {
      "version": 102,
      "id": "d1a0c5d5-2c35-4b98-8b9c-11d8e7706148"
    }
  }
}
```

> **注**: `password` は空文字列。パスワードレスログイン (MFA OTP) が使用されている。
> `recaptchaSiteKey`: `6LeWeOoUAAAAAJB9vW-OBEYmBwbF9R7PILe6U_ML` (Google reCAPTCHA v3)

### Step 4: InterstitialScreenUpdate — MFA OTP 送信

```
ts: 2026-03-13T09:02:27.251Z
domain: android.prod.cloud.netflix.com
userId: null  ← まだ未認証
userauthdata: null
```

```json
{
  "operationName": "InterstitialScreenUpdate",
  "variables": {
    "serverState": {
      "realm": "growth",
      "name": "MFA_COLLECT_OTP_EMAIL_INPUT",
      "clcsSessionId": "74a682e9-d991-4d03-a2e4-aa130cdd1623",
      "sessionContext": {
        "session-breadcrumbs": { "funnel_name": "loginMobile" },
        "MobileLoginSessionContext": {}
      },
      "hellfireSessionId": "d1141445-134a-37ae-b91f-efe6902155e1"
    },
    "serverScreenUpdate": {
      "realm": "custom",
      "name": "growthVerifyMfaChallenge",
      "metadata": { "validateLength": 4 },
      "loggingAction": "Submitted",
      "loggingCommand": "SubmitCommand"
    },
    "inputFields": [
      { "name": "challengeOtp", "value": { "stringValue": "8104" } }
    ]
  },
  "extensions": {
    "persistedQuery": {
      "version": 102,
      "id": "d1a0c5d5-2c35-4b98-8b9c-11d8e7706148"
    }
  }
}
```

> **注**: MFA OTP は 4 桁 (`validateLength: 4`)。メールに送信された OTP `8104` を入力。

### Step 5: InterstitialSendFeedback — ログイン完了、プロフィール画面へ遷移

```
ts: 2026-03-13T09:02:30.453Z
domain: android.prod.cloud.netflix.com
userId: ZEULH5S2GNGCRAABCSG6J2EGGA  ← 認証完了
userauthdata: null
```

```json
{
  "operationName": "InterstitialSendFeedback",
  "variables": {
    "serverState": {
      "realm": "growth",
      "name": "MFA_COLLECT_OTP_EMAIL_INPUT",
      "clcsSessionId": "74a682e9-d991-4d03-a2e4-aa130cdd1623"
    },
    "serverFeedback": {
      "name": "system.inAppNavigation",
      "metadata": { "loggingCommand": "Navigating to /profiles" }
    },
    "inputFields": []
  },
  "extensions": {
    "persistedQuery": {
      "version": 102,
      "id": "4718d209-37d8-4b43-ae43-858cd07c6c0b"
    }
  }
}
```

### Step 6: AccountQuery (認証後, userId 確定)

```
ts: 2026-03-13T09:02:29.644Z
domain: android14.prod.cloud.netflix.com
userId: TEMP_PROFILE_ID  ← 一時プロファイル

ts: 2026-03-13T09:02:31.123Z
domain: android14.prod.cloud.netflix.com
userId: ZEULH5S2GNGCRAABCSG6J2EGGA  ← 確定プロファイル
```

### Step 7: userauthdata (NETFLIXID) 送信 — MSL 層で初回ユーザー認証

```
ts: 2026-03-13T09:02:28.168Z  ← Step 4〜5 の間
domain: android14.prod.ftl.netflix.com
```

→ Phase 2 のデータ参照 (前述)。ログイン完了直後に MslControl が netflixId + secureNetflixId を MSL MessageHeader に埋め込み。

### ログインフロー時系列まとめ

| 時刻 | ステップ | userId | ドメイン | 内容 |
|---|---|---|---|---|
| 09:00:02 | RenewSSOToken | `ZEULH5S..` | android14.prod.cloud | 既存セッションの SSO トークン更新 |
| 09:01:29 | InterstitialHook | null | android.prod.cloud | ログイン画面初期化 (`loginMobile`) |
| 09:02:12 | InterstitialScreenUpdate | null | android.prod.cloud | メールアドレス送信 + reCAPTCHA (`IDENTIFICATION`) |
| 09:02:27 | InterstitialScreenUpdate | null | android.prod.cloud | MFA OTP `8104` 送信 (`MFA_COLLECT_OTP_EMAIL_INPUT`) |
| 09:02:28 | **MSL userauthdata** | — | android14.prod.ftl | **NETFLIXID 認証** (netflixId + secureNetflixId) |
| 09:02:29 | AccountQuery | `TEMP_PROFILE_ID` | android14.prod.cloud | 一時プロファイルでアカウント照会 |
| 09:02:30 | InterstitialSendFeedback | `ZEULH5S..` | android.prod.cloud | ログイン完了 → `/profiles` 遷移 |
| 09:02:31 | AccountQuery | `ZEULH5S..` | android14.prod.cloud | 確定プロファイルでアカウント照会 |

---

## 実際の Cookie とリクエストヘッダー

2026-03-13 キャプチャから取得した実データ。

### Cookie 一覧

3 つの Cookie が送信される:

| Cookie 名 | 説明 | サンプル値 |
|---|---|---|
| `nfvdid` | Netflix デバイス ID | `BQFmAAEBEEPj84LzHGpQ_ldxaVuQv8tg...` (Base64, 約130文字) |
| `NetflixId` | メイン認証トークン | `v=3&ct=BgjHlOvc...&pg=ZEULH5S2GNG...&ch=AQEAEAABABTp79nN...` (約600文字) |
| `SecureNetflixId` | セキュア認証トークン (HMAC) | `v=3&mac=AQEAEQABABSdkuDd...&dt=1773391620952` |

### NetflixId の構造

```
v=3
ct=BgjHlOvcAxLcA6sY6f_QqKsJWi9efmzU7gW0d6XdGtEbMELNpOs-Ws2jKWjrRgmY8LTraOV1L5gpMfa5YJ63VaUYZrzppkA0wm-r_7A_XkrygJ4mEYMVax3K5POwTnVKZK-k2h5ITFTGYp3sHXwBQy3BbuBTJ8rD4nQOXGgRbm3RilTMKcOCHYyahc4YSmE-E3CPdoASBsLzpHAszy7XN8Mwc4iGr198Hac49DdcXpLhUaP6LGm8j9_3nI0R2gg8B-ntAZIKumUrbQXSsb_zMv71GxZYcKnjNVfwFAKppf3gydKKhcvzuFKw7jZvebCSYp83l56MRB88yd_vUjmXsDUdZS1AXjYMk9zVfHoARiF-2-c0FSfS3zb2SQWQkUcgTR_SabzN5u6_w6zXgffoYlVJDPsmy8Z9pDGYFzOGL3Xqc_UNIz4KdEPCDkSGmQC9nhVOJXwXYb-LBhVC7qE1Cz1vpZ98mYEwE7LomPN3-34eGIWBeeMR8E4VXfQJnL4iBnO6hBfRmy8xNRgDA7VlAjJiYYolnK_x4_gTu2-x7A5AK1WYqobiCkcOClMQIioAC8ZlH17Wf_eN2lFfOEP6G50KJpYPhUezIpPzfV5osQT9Q0AsfUrzRF3MWXDM9ukNDmHiYfN0GAYiDgoMSvU3vVSCd907UQKa
pg=ZEULH5S2GNGCRAABCSG6J2EGGA
ch=AQEAEAABABTp79nN9l_2MuRhqTXl0-SjAqcm83QU8vw.
```

- `v`: バージョン (3)
- `ct`: 暗号化トークン本体 (Base64url)
- `pg`: プロファイル GUID
- `ch`: チャンネル/チェックサム

### SecureNetflixId の構造

```
v=3
mac=AQEAEQABABSdkuDdxX0gGJU2IJOTCYiVHmFkqRtHQj0.
dt=1773391620952
```

- `v`: バージョン (3)
- `mac`: HMAC 署名 (Base64url)
- `dt`: タイムスタンプ (epoch ms)

---

## cURL 形式リクエスト例

### 共通ヘッダー

```
User-Agent: com.netflix.mediaclient/63928 (Linux; U; Android 14; en; Pixel 4a (5G); Build/UP1A.231005.007)
X-Netflix-ProxyEsn: NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-0202Q7INAHS2TKI5GTQESPDEHTFK7MG1BKUU7QAPUQP2QMI641A8HN08CE40C5H2K4J15NCLBC5DGJI0M03TMV0VGS1ER8VACIG0257E
```

### 1. Push 通知 WebSocket 接続

```bash
curl -v \
  -H 'Origin: http://www.netflix.com' \
  -H 'User-Agent: com.netflix.mediaclient/63928 (Linux; U; Android 14; en; Pixel 4a (5G); Build/UP1A.231005.007)' \
  -H 'X-Netflix-ProxyEsn: NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-0202Q7INAHS2TKI5GTQESPDEHTFK7MG1BKUU7QAPUQP2QMI641A8HN08CE40C5H2K4J15NCLBC5DGJI0M03TMV0VGS1ER8VACIG0257E' \
  -H 'Upgrade: websocket' \
  -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Extensions: permessage-deflate' \
  -b 'nfvdid=BQFmAAEBEEPj84LzHGpQ_ldxaVuQv8tgIBE9VAe3w-WeF5En4w5goMB6eLYVXqxblfzh23QC62wkeecrOuKtsfIRNC5GkWZ80HdbCeAoFLJ8LL5stGc-h87ykqdvoTT1Vg5jhdcHity8mbE5rciYfRNlegiejB_j; NetflixId=v%3D3%26ct%3DBgjHlOvcAxLcA6sY6f_QqKsJWi9efmzU7gW0d6XdGtEbMELNpOs-Ws2jKWjrRgmY8LTraOV1L5gpMfa5YJ63VaUYZrzppkA0wm-r_7A_XkrygJ4mEYMVax3K5POwTnVKZK-k2h5ITFTGYp3sHXwBQy3BbuBTJ8rD4nQOXGgRbm3RilTMKcOCHYyahc4YSmE-E3CPdoASBsLzpHAszy7XN8Mwc4iGr198Hac49DdcXpLhUaP6LGm8j9_3nI0R2gg8B-ntAZIKumUrbQXSsb_zMv71GxZYcKnjNVfwFAKppf3gydKKhcvzuFKw7jZvebCSYp83l56MRB88yd_vUjmXsDUdZS1AXjYMk9zVfHoARiF-2-c0FSfS3zb2SQWQkUcgTR_SabzN5u6_w6zXgffoYlVJDPsmy8Z9pDGYFzOGL3Xqc_UNIz4KdEPCDkSGmQC9nhVOJXwXYb-LBhVC7qE1Cz1vpZ98mYEwE7LomPN3-34eGIWBeeMR8E4VXfQJnL4iBnO6hBfRmy8xNRgDA7VlAjJiYYolnK_x4_gTu2-x7A5AK1WYqobiCkcOClMQIioAC8ZlH17Wf_eN2lFfOEP6G50KJpYPhUezIpPzfV5osQT9Q0AsfUrzRF3MWXDM9ukNDmHiYfN0GAYiDgoMSvU3vVSCd907UQKa%26pg%3DZEULH5S2GNGCRAABCSG6J2EGGA%26ch%3DAQEAEAABABTp79nN9l_2MuRhqTXl0-SjAqcm83QU8vw.; SecureNetflixId=v%3D3%26mac%3DAQEAEQABABSdkuDdxX0gGJU2IJOTCYiVHmFkqRtHQj0.%26dt%3D1773391620952' \
  'https://android14.push.prod.netflix.com/ws'
```

### 2. PlayExchange WebSocket 接続

```bash
curl -v \
  -H 'Origin: http://www.netflix.com' \
  -H 'User-Agent: com.netflix.mediaclient/63928 (Linux; U; Android 14; en; Pixel 4a (5G); Build/UP1A.231005.007)' \
  -H 'X-Netflix-ProxyEsn: NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-0202Q7INAHS2TKI5GTQESPDEHTFK7MG1BKUU7QAPUQP2QMI641A8HN08CE40C5H2K4J15NCLBC5DGJI0M03TMV0VGS1ER8VACIG0257E' \
  -H 'x-netflix.socketrouter.schema.version: 2' \
  -H 'X-Netflix.Request.Client.Context: {"appstate":"foreground"}' \
  -H 'x-netflix.socketrouter.group.name: Test80913.Cell2|Test80897.Cell2|Test80905.Cell2' \
  -H 'Upgrade: websocket' \
  -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Extensions: permessage-deflate' \
  -b 'nfvdid=BQFmAAEBEEPj84LzHGpQ_ldxaVuQv8tgIBE9VAe3w-WeF5En4w5goMB6eLYVXqxblfzh23QC62wkeecrOuKtsfIRNC5GkWZ80HdbCeAoFLJ8LL5stGc-h87ykqdvoTT1Vg5jhdcHity8mbE5rciYfRNlegiejB_j; NetflixId=v%3D3%26ct%3DBgjHlOvc...%26pg%3DZEULH5S2GNGCRAABCSG6J2EGGA%26ch%3DAQEAEAABABTp79nN9l_2MuRhqTXl0-SjAqcm83QU8vw.; SecureNetflixId=v%3D3%26mac%3DAQEAEQABABSdkuDdxX0gGJU2IJOTCYiVHmFkqRtHQj0.%26dt%3D1773391620952' \
  'https://android14.ws.prod.cloud.netflix.com/playexchange'
```

### 3. MSL API リクエスト (Samurai API)

MSL API は WebSocket 上の MSL プロトコルで送信される。HTTP レベルでは上記 WebSocket 接続のみ。
MSL メッセージ内部で以下のエンドポイントにルーティングされる:

```
https://android14.prod.ftl.netflix.com/nq/androidui/samurai/~9.0.0/api
https://android14.prod.ftl.netflix.com/nq/androidui/samurai/v1/config
https://android14.prod.ftl.netflix.com/playapi/android/event/1
https://android14.prod.cloud.netflix.com/graphql
https://android.prod.cloud.netflix.com/graphql
https://android14.logs.netflix.com/log/android/logblob/1
```

> **注意**: MSL メッセージボディは CBOR エンコード → Widevine CryptoContext で暗号化されるため、
> cURL で直接再現するには暗号化済みバイナリを POST する必要がある。
> Cookie は HTTP トランスポート層で送信され、MSL レイヤーの `userauthdata` (CBOR key 47) にも
> 同じ `netflixId`/`secureNetflixId` が埋め込まれる（二重送信）。

### ESN (デバイス識別子) の構造

```
NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-0202Q7INAHS2TKI5GTQESPDEHTFK7MG1BKUU7QAPUQP2QMI641A8HN08CE40C5H2K4J15NCLBC5DGJI0M03TMV0VGS1ER8VACIG0257E
```

| セグメント | 値 | 意味 |
|---|---|---|
| プラットフォーム | `NFANDROID1` | Netflix Android |
| セキュリティ | `PXA-P` | ProGuard eXtended Authentication - Production |
| DRM レベル | `L3` | Widevine Level 3 |
| デバイスモデル | `GOOGLPIXEL=4A==5G=` | Google Pixel 4a (5G) |
| Widevine System ID | `22594` | CDM System ID |
| デバイス固有 ID | `0202Q7INA...0257E` | ハードウェア固有識別子 |

---

## ESN 送信箇所の全体マップ

2026-03-13 キャプチャデータの分析結果。ESN は複数の場所・形式で送信される。

### 2 種類の ESN

同一デバイスに対して **2 種類の ESN** が使い分けられている:

| 種別 | プレフィックス | 用途 | デバイス固有ID |
|---|---|---|---|
| **PXA (ProxyEsn)** | `NFANDROID1-PXA-P-L3-` | HTTP ヘッダー (`X-Netflix-ProxyEsn`) | `0202Q7INA...0257E` |
| **PRV (Private)** | `NFANDROID1-PRV-P-L3-` | ライセンス要求、DRM、再生イベント | `3E369F1C...E371` |

- `PXA` = ProGuard eXtended Authentication。WebSocket 接続時のデバイス識別に使用。
- `PRV` = Private。DRM ライセンスおよびコンテンツ再生関連で使用。
- デバイスモデル部分 (`GOOGLPIXEL=4A==5G=`) と Widevine System ID (`22594`) は共通。
- デバイス固有 ID 部分は種別ごとに異なる。

### ESN が送信される全箇所

| # | 送信箇所 | ESN 種別 | レイヤー | フック可能性 |
|---|---|---|---|---|
| 1 | `X-Netflix-ProxyEsn` HTTP ヘッダー | PXA | HTTP (OkHttp) | OkHttp `Request.newBuilder()` で差し替え |
| 2 | `/license` URL クエリパラメータ `esn=` | PRV (完全) | MSL API パラメータ | `apiRequest` body 書き換え |
| 3 | `/events` URL クエリパラメータ `esn=` | PRV (完全) | MSL API パラメータ | `apiRequest` body 書き換え |
| 4 | `challengeBase64` (Widevine CDM protobuf) | PRV (完全) | DRM (MediaDrm) | `MediaDrm.getProvisionRequest` / `setPropertyString` |
| 5 | `logblob` ボディ内 | 短縮 (`NFANDROID1-GOOGLPIXEL=...`) | MSL API パラメータ | `apiRequest` body 書き換え |
| 6 | MSL MessageHeader `sender` (CBOR key 20) | **空文字列** | MSL CBOR | 使われていない（書き換え不要） |

### 各箇所の詳細

#### 1. X-Netflix-ProxyEsn (HTTP ヘッダー)

WebSocket 接続 (`/ws`, `/playexchange`) 時に送信される。

```
X-Netflix-ProxyEsn: NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-0202Q7INAHS2TKI5GTQESPDEHTFK7MG1BKUU7QAPUQP2QMI641A8HN08CE40C5H2K4J15NCLBC5DGJI0M03TMV0VGS1ER8VACIG0257E
```

**フック方法**: OkHttp `RealCall.getResponseWithInterceptorChain` 内で `request.newBuilder().removeHeader().addHeader()` で差し替え。

#### 2-3. /license, /events URL クエリパラメータ

MSL API ペイロード内の URL パスに `esn=` として埋め込まれる。

```
/license?licenseType=standard&playbackContextId=E3-...&esn=NFANDROID1-PRV-P-L3-GOOGLPIXEL%3D4A%3D%3D5G%3D-22594-3E369F1C9B189ED664E13DEEEE9BACB67684B4FE6283537D1A67810BFE73E371&drmContextId=2596051
```

**フック方法**: `ApiHandlerImpl.apiRequest` の body (arguments[1]) を書き換え。または ESN 提供元をフックすればアプリが自動的に新 ESN で URL を組み立てる。

#### 4. challengeBase64 (Widevine CDM protobuf)

DRM ライセンス要求の `challengeBase64` フィールドに含まれる Widevine CDM protobuf 内に ESN が埋め込まれている。

```json
{
  "challengeBase64_contents": {
    "device_certificate": {
      "esn": "NFANDROID1-PRV-P-L3-GOOGLPIXEL=4A==5G=-22594-3E369F1C9B189ED664E13DEEEE9BACB67684B4FE6283537D1A67810BFE73E371",
      "movieid": "81756595",
      "issuetime": 1773373148,
      "salt": "3598263455819263519576642966605"
    },
    "oem_crypto_build_information": "OEMCrypto Level3 Code May 20 2022 21:36:54",
    "widevine_cdm_version": "17.0.0",
    "device_name": "bramble",
    "architecture_name": "arm64-v8a"
  }
}
```

この protobuf は `MediaDrm` CDM が生成するため、**直接書き換えが最も難しい箇所**。

**フック方法 (候補)**:
- `MediaDrm.setPropertyString("esn", ...)` をフックして差し替え — CDM が protobuf 生成前に ESN を取得する段階で介入
- `MediaDrm.getProvisionRequest()` の戻り値 (byte[]) 内を文字列置換 — protobuf 構造が壊れるリスクあり
- CDM より上流の ESN 提供クラス (SharedPreferences / DeviceInfo) をフック — CDM に渡る前に差し替えるため protobuf 構造は保持される

> **注意**: `challengeBase64` 内の ESN は Widevine サーバー側で検証される可能性がある。
> ESN を差し替えても CDM の `device_certificate` 署名と不整合が生じると、
> ライセンス取得がエラーになる場合がある。

#### 5. logblob ボディ (テレメトリ)

テレメトリログ送信時に短縮 ESN が含まれる:

```
NFANDROID1-GOOGLPIXEL=4A==5G=S-3269A5B59F399B066558C80DCB36AE97F9A8B477F8854DFED2C14C8453D6F556
```

セキュリティ種別 (`PXA`/`PRV`) を含まない短縮形式。デバイス固有 ID も PXA/PRV とは異なる第3の値。

#### 6. MSL MessageHeader sender (CBOR key 20)

キャプチャした全 353 ヘッダーで **sender は空文字列 `""`** だった。
Android 版では MSL MessageHeader の sender フィールドは使われておらず、ESN は上記 1-5 の経路で送信される。

### ESN 書き換え戦略まとめ

```
最上流 (推奨)
  ├── SharedPreferences / DeviceInfo → ESN 文字列の保持元
  │     └── ここを書き換えれば #1, #2, #3, #5 は自動的に反映
  │
  ├── MediaDrm.setPropertyString("esn") → CDM への ESN 設定
  │     └── ここを書き換えれば #4 (challengeBase64) にも反映
  │
最下流 (個別対応)
  ├── OkHttp Request.newBuilder() → #1 のみ
  ├── apiRequest body replace → #2, #3, #5
  └── protobuf byte[] replace → #4 (構造破壊リスク)
```

**理想的なアプローチ**: ESN の提供元 (SharedPreferences / EsnManager 相当クラス) と `MediaDrm.setPropertyString` の 2 箇所をフックすれば、全箇所に波及する。
