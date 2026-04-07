# キャプチャデータ復号状況

キャプチャ日: 2026-04-06  
デバイス: iPhone 9, Argo 15.48.1

## エンドポイント別復号状況

| エンドポイント | 総ファイル数 | JSON 平文 | CBOR 暗号化 | CBOR 平文 | CBOR 鍵交換 | 復号不可 | 復号不可の理由 |
|--------------|-----------|----------|-----------|---------|-----------|---------|-------------|
| appboot | 2 | 0 | 1 | 1 | 0 | **1** | MSL セッション鍵なし (AES-128-CBC 暗号化) |
| iosui | 11 | 5 | 0 | 0 | 0 | **0** | — (全て平文 JSON) |
| graphql (FTL) | 23 (JSON) | 23 | 0 | 0 | 0 | **0** | — (全て平文 JSON) |
| graphql (Cloud/NGP) | 22 (CBOR) | 0 | 16 | 4 | 0 | **16** | MSL セッション鍵なし |
| pbo_license | 40 | 0 | 27 | 12 | 1 | **27** | MSL セッション鍵なし |
| ios_manifest | ~20 | 0 | ~15 | ~5 | 0 | **~15** | MSL セッション鍵なし |
| ios_logblob | ~15 | 0 | ~10 | ~5 | 0 | **~10** | MSL セッション鍵なし |
| msl (event 等) | 51 | 23 | 18 | 10 | 0 | **18** | MSL セッション鍵なし |
| other (speedtest) | 3 | 0 | 0 | 0 | 0 | **0** | OCA プローブ (バイナリ、復号不要) |
| other (残り) | 41 | 28 | 3 | 0 | 0 | **3** | MSL セッション鍵なし |

## 復号可能 / 復号不可の分類

### 復号済み (平文で取得できている)

| カテゴリ | 内容 | 形式 |
|---------|------|------|
| iosui API | healthcheck, user, warmer | HTTP/JSON (平文) |
| graphql (FTL) | FTL ホスト経由の GraphQL | HTTP/JSON (平文) |
| appboot (ヘッダー部) | MSL ヘッダー、entity auth、鍵交換パラメータ | CBOR (構造は見える) |
| CBOR メタデータ | MSL ヘッダー、sequence number、capabilities | CBOR (構造は見える) |
| Cookie | nfvdid, NetflixId, SecureNetflixId 等 | テキスト |
| HTTP ヘッダー | 全リクエスト/レスポンスの全ヘッダー | JSON |

### 復号不可 (暗号化されたペイロード)

| カテゴリ | 内容 | 暗号化方式 | 復号に必要なもの |
|---------|------|----------|---------------|
| appboot レスポンスペイロード | サーバー設定、trust store データ | AES-128-CBC + HMAC-SHA256 | MSL セッション鍵 (鍵交換で導出) |
| graphql (Cloud/NGP) | カタログ、SSO トークン等 | AES-128-CBC + HMAC-SHA256 | MSL セッション鍵 |
| pbo_license リクエスト | FairPlay SPC ペイロード | AES-128-CBC + HMAC-SHA256 | MSL セッション鍵 |
| pbo_license レスポンス | FairPlay ライセンス応答 | AES-128-CBC + HMAC-SHA256 | MSL セッション鍵 |
| ios_manifest リクエスト | マニフェスト要求パラメータ | AES-128-CBC + HMAC-SHA256 | MSL セッション鍵 |
| ios_manifest レスポンス | ストリーム URL、コーデック情報 | AES-128-CBC + HMAC-SHA256 | MSL セッション鍵 |
| ios_logblob | テレメトリデータ | AES-128-CBC + HMAC-SHA256 | MSL セッション鍵 |
| msl (event 等) | イベントデータ | AES-128-CBC + HMAC-SHA256 | MSL セッション鍵 |

## MSL セッション鍵の取得方法

暗号化ペイロードの復号には **MSL セッション鍵** (encryption key + HMAC key) が必要。

### 方法 1: Frida でセッション鍵をフック

MslClient / NFWebCrypto 内の鍵導出関数をフックして鍵を抽出:

- `IosMslClient` の鍵交換完了時にセッション鍵がメモリに保持される
- `NFWebCrypto::aesCbc` の引数から AES 鍵と IV を取得
- `NFWebCrypto::dhDerive` / `HKDF` の出力を取得

### 方法 2: Python MSL クライアントで鍵交換を再現

`src/netflix_msl/` の既存実装を拡張:

1. appboot CBOR リクエストを再現 (FAIRPLAY_MGK_APPID は iOS 固有のため困難)
2. ASYMMETRIC_WRAPPED (RSA) で鍵交換 (Chrome/Android 向けなら可能)
3. セッション鍵を取得して、キャプチャ済みデータを復号

### 方法 3: Frida で平文を直接キャプチャ

暗号化前/復号後のデータを Frida フックで取得:

- `SSL_write` / `SSL_read` — HTTP レベルの平文
- MSL の暗号化関数 (`aesCbc`) の入出力をフック

## 結論

| 項目 | 状態 |
|------|------|
| HTTP ヘッダー・Cookie | ✓ 全て取得済み |
| 平文 JSON レスポンス (iosui, FTL graphql) | ✓ 全て取得済み |
| MSL CBOR 構造 (ヘッダー、entity auth) | ✓ デコード済み |
| MSL 暗号化ペイロード | ✗ **セッション鍵がないため復号不可** |
| OCA スピードテスト | — 復号不要 (バイナリプローブ) |

**ボトルネック**: MSL セッション鍵の取得。ただし鍵交換データはキャプチャ済み。

## 補足: FairPlay と MSL 鍵交換は独立

FairPlay (`FAIRPLAY_MGK_APPID`) は **entity auth** (認証スキーム) であり、**MSL の鍵交換とは無関係**。

- Entity Auth (key 34): `FAIRPLAY_MGK_APPID` → デバイス認証 (apphmac, devicetoken, ESN)
- Key Exchange (key 33): スキーム ID `3` → セッション鍵の導出 (DH or RSA ラッピング)

鍵交換データは appboot の CBOR に含まれており:

- **リクエスト key 33.6**: 464 bytes (クライアント鍵交換データ)
- **レスポンス key 33.6**: 96 bytes (サーバー鍵交換レスポンス = ラップされたセッション鍵)
- **key 33.8**: ESN + suffix (identity)
- **key 33.9**: 16 bytes nonce

Python MSL クライアント (`src/netflix_msl/`) で ASYMMETRIC_WRAPPED 鍵交換を再現すれば、
FairPlay に依存せずセッション鍵を取得し、暗号化ペイロードを復号できる可能性がある。

iOS の CBOR スキーム ID `3` が JSON 形式の `ASYMMETRIC_WRAPPED` に対応するか、
別のスキーム (DIFFIE_HELLMAN 等) かは要調査。
