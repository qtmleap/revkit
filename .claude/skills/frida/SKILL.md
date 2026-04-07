# Netflix Android Cookie + ESN キャプチャ (Frida)

Frida を使い、root 済み Android 端末上の Netflix アプリから Cookie と PRV ESN をキャプチャするスキル。
キャプチャしたデータは Nagisa の Netflix プロバイダ (`get_widevine_keys`) で DRM キー取得に使用される。

## トリガー条件

- ユーザーが Netflix Android の Cookie / ESN キャプチャについて聞いたとき
- Frida フックスクリプトの作成・修正を依頼されたとき
- `cookies.l3.txt` / `cookies.l1.txt` の生成・検証を依頼されたとき
- MSL の `entity mismatch` エラーなどの Cookie/ESN 関連トラブルシューティング

## 背景

Netflix MSL プロトコルでは Cookie が PRV ESN にバインドされている。不一致だと `205032 entity mismatch` エラーになるため、**同一セッション**で Cookie と ESN を同時にキャプチャする必要がある。

## 関連ドキュメント

| ドキュメント | 内容 |
|-------------|------|
| `docs/instructions/android/http_headers_cookies.md` | HTTP ヘッダー・Cookie の完全リファレンス (Cronet フック 1,274 リクエスト分析) |
| `docs/instructions/android/license_data.md` | Widevine DRM ライセンス交換データ |
| `docs/instructions/android/msl_cbor_keys.md` | MSL CBOR キーマッピング |
| `docs/instructions/pxa_esn_llm.md` | PXA ESN の取得プロトコル・構造 |

## キャプチャ対象

### 1. PRV ESN (必須)

MSL の `sender` フィールドに含まれるデバイス識別子。

```
NFANDROID1-PRV-P-{L1|L3}-{MODEL}-{SYSTEM_ID}-{FINGERPRINT}
```

- `NFANDROID1-PRV-P-` で始まること
- Fingerprint は 64 文字の大文字 hex
- System ID は数値 (L3 は通常 22594 等)

**取得方法** (優先順):
1. MSL `MessageHeader` の CBOR key 20 (`sender`) をフック
2. `SharedPreferences` の `nf_esn` キーを読み取り
3. ESN 生成クラス (`EsnPrefixConfig` / ProGuard 難読化名) をフック

### 2. Cookie (5 種、必須)

| Cookie 名 | フォーマット | 取得タイミング |
|-----------|-------------|--------------|
| `nfvdid` | Base64url バイナリ | `appboot` レスポンスの `Set-Cookie` |
| `flwssn` | UUID v4 | アプリ起動時 |
| `gsid` | UUID v4 | ログイン後 |
| `NetflixId` | URL エンコード済みトークン | MSL 認証後の `Set-Cookie` |
| `SecureNetflixId` | URL エンコード済み HMAC 署名 | MSL 認証後の `Set-Cookie` |

**取得方法**: Cronet (`org.chromium.net.impl.CronetUrlRequest`) の `addHeader()` で `Cookie` ヘッダーを監視。

**重要**: `NetflixId` / `SecureNetflixId` は URL エンコード済み状態で取得すること。

## Frida フック対象

### Hook 1: HTTP Cookie

Netflix Android は HTTP スタックに Cronet を使用。`CronetUrlRequest.addHeader()` で `Cookie` ヘッダーを監視し、`*.netflix.com` ドメインのみフィルタ。

全 Cookie が揃うタイミング: `authenticate` リクエスト (再生トリガー後)。

### Hook 2: PRV ESN

MSL ペイロードの CBOR エンコード時に `sender` フィールド (CBOR key 20) をフック。または `SharedPreferences` の `nf_esn` を読み取り。

## 出力フォーマット

ファイル名: `cookies.l3.txt` (L3) / `cookies.l1.txt` (L1)。Netscape cookies.txt 形式。

```
# Netscape HTTP Cookie File
# Captured: {YYYY-MM-DD HH:MM:SS UTC}
# Device: {device_model} / {codename} / Android {api_level} / Netflix {app_version}
# ESN: {PRV_ESN}
# DRM Level: L{level}
.netflix.com	TRUE	/	TRUE	0	nfvdid	{value}
.netflix.com	TRUE	/	TRUE	0	flwssn	{value}
.netflix.com	TRUE	/	TRUE	0	gsid	{value}
.netflix.com	TRUE	/	TRUE	0	NetflixId	{url_encoded_value}
.netflix.com	TRUE	/	TRUE	0	SecureNetflixId	{url_encoded_value}
```

- `# ESN:` 行は **必須** (Nagisa がこの行から ESN を自動抽出する)
- Cookie 行はタブ区切り (Netscape cookies.txt 標準)
- `NetflixId` / `SecureNetflixId` は URL エンコード済みの値を記録

## キャプチャ手順

```
1. frida-server を端末で起動
2. frida -U -f com.netflix.mediaclient -l hook_netflix.js --no-pause
3. Netflix アプリ起動を待機
4. アプリ内で任意コンテンツの再生を開始 (authenticate がトリガーされる)
5. Frida コンソールから PRV ESN + 全 5 Cookie を収集
6. 上記フォーマットで cookies.l3.txt を生成
```

### 再生時のリクエスト順序

```
appboot → MSL Key Exchange → getProxyEsn → aleProvision
  → authenticate ← ここで全 Cookie + ESN が揃う
  → licensedManifest
```

## エラーと対処

| エラー | 原因 | 対処 |
|--------|------|------|
| `205032 entity mismatch` | Cookie と ESN が別セッション | 同一セッションで再キャプチャ |
| `205064 Invalid device state` | Cookie 期限切れ | 新しい Cookie を再キャプチャ |
| `205000 User must login again` | セッション完全失効 | アプリで再ログイン後にキャプチャ |
| `107016 incorrect key exchange data type` | Android ESN で Chrome KE を使用 | `scheme='android'` を指定 |
| `204055 Entity auth rate limit tripped` | 同一 ESN/IP で連続 KE | 時間を空けてリトライ |

## 配置先

```
secrets/
  cookies.l3.txt    ← L3 Cookie (優先)
  cookies.l1.txt    ← L1 Cookie (TEE 搭載端末のみ)
```

`secrets/` は `.gitignore` に含まれているため、コミットされない。
