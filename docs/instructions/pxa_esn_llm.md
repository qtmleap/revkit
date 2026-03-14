# PXA ESN — LLM 向けリファレンス

## PXA ESN とは

Netflix Android アプリがサーバーから取得するデバイス識別子。ローカル生成の Base ESN (PRV) に対し、サーバーが fingerprint を付与して発行する。API リクエストの `X-Netflix.esn` ヘッダーで使用される。

## 取得プロトコル

- **経路:** MSL (Message Security Layer) over HTTPS
- **エンドポイント:** `/getProxyEsn`
- **取得方法:** Cookie ではなく、MSL レスポンスの JSON ボディで返される

### リクエスト

```json
{"url": "/getProxyEsn"}
```

MSL VolleyRequest のヘッダーに `router: getProxyEsn` が設定される。HTTP レベルのヘッダーは MSL 暗号化されるため外部からは見えない。

### レスポンス

```json
{
  "id": 1,
  "version": 2,
  "serverTime": 1773478742949,
  "result": {
    "esn": "NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-02028KVLM5OU1MSB..."
  },
  "common": {},
  "from": "playapi"
}
```

PXA ESN は `result.esn` に格納されている。

## 有効期限

- 設定値: `EsnHendrixConfig.refreshProxyEsnTimeInMs = 0`
- TTL が 0 のため **無期限キャッシュ**
- 一度取得したら SharedPreferences に永続化され、以下の場合のみ再取得:
  - 初回インストール
  - アプリデータクリア
  - SharedPreferences の消失
  - `masterTokenSerialNumber` の変更

## fingerprint の特性

- サーバー側で生成され、ローカルでは再現不可
- 同一デバイスでも取得ごとに異なる fingerprint が返される
- 実測で 3 回取得し、毎回異なることを確認

## ESN 構造

```
NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-0202{fingerprint}
```

| セグメント | 値 | 説明 |
|---|---|---|
| Platform | `NFANDROID1-` | Android プレフィックス |
| Type | `PXA` | Proxy (サーバー発行) |
| Category | `P` | Phone (T=Tablet, B=TV, C=ChromeOS, E=Display) |
| Security | `L3` | Widevine Security Level |
| Model | `GOOGLPIXEL=4A==5G=` | サニタイズ済みデバイスモデル |
| systemId | `22594` | Widevine systemId |
| fingerprint | `0202...` | サーバー発行 (毎回異なる) |

## 保存先

SharedPreferences に 2 つのキーで保存:

| キー | 型 | 内容 |
|---|---|---|
| `nf_drm_esn` | String | PXA ESN 文字列 |
| `nf_drm_proxy_esn` | String (JSON) | `{"esn":"...","ts":epoch_ms,"sn":serial_number}` |

## 使用箇所

| ヘッダー | 使用先 |
|---|---|
| `X-Netflix.esn` | GraphQL / Cronet リクエスト |
| `X-Netflix-ProxyEsn` | WebSocket / MSL リクエスト |

## コードパス

```
WidevineEntityAuthEsnProviderImpl.c(serialNumber)  -- 再取得が必要か判定
  → ProxyEsnMslRequest                             -- MSL リクエスト送信
    → body: {"url": "/getProxyEsn"}
    → Netflix playapi サーバー
  ← onSuccess(JSONObject)                           -- レスポンス受信
    → result.esn を抽出
  → ProxyEsn.onKnown(serialNumber, esn)            -- SharedPreferences に保存
```

## 関連クラス

| クラス | ファイルパス | 役割 |
|---|---|---|
| `ProxyEsnMslRequest` | `mslagent/impl/ProxyEsnMslRequest.java` | MSL リクエスト発行・レスポンス処理 |
| `ProxyEsn` | `esn/impl/ProxyEsn.java` | キャッシュ管理・永続化 |
| `WidevineEntityAuthEsnProviderImpl` | `esn/impl/WidevineEntityAuthEsnProviderImpl.java` | ESN 統合管理 |
| `EsnHendrixConfig` (`o.fkQ`) | `o/C13212fkQ.java` | TTL 設定 (`refreshProxyEsnTimeInMs`) |

## キャプチャ方法

`hook_msl.js` を使用。`ProxyEsn.$init` で expired フラグを強制 true にすることで、キャッシュの有無に関係なく `getProxyEsn` を発火させられる。

```bash
./run_android.sh hook_msl.js
```

出力イベント: `proxyEsn.forceExpired`, `proxyEsn.request`, `proxyEsn.requestHeaders`, `proxyEsn.response`, `proxyEsn.onKnown`, `proxyEsn.error`
