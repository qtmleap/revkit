# PXA ESN (Proxy ESN) — 取得フロー

> **対象:** Netflix Android v9.57.0 (build 63928)
> **取得方法:** Frida フック (`hook_msl.js` → `ProxyEsnMslRequest` / `ProxyEsn`)
> **検証日:** 2026-03-14

---

## 概要

PXA ESN はサーバーが発行するデバイス識別子。ローカル生成の Base ESN (PRV) と異なり、サーバー側で fingerprint を付与して返す。MSL 通信や GraphQL API で `X-Netflix.esn` / `X-Netflix-ProxyEsn` ヘッダーとして使用される。

---

## 取得フロー

### 1. トリガー

`WidevineEntityAuthEsnProviderImpl.c(Long serialNumber)` が呼ばれたとき、以下の条件で `getProxyEsn` が発行される:

```java
// WidevineEntityAuthEsnProviderImpl.c()
if (serialNumber == null) return true;           // serialNumber なし → 再取得
if (proxyEsn.c != serialNumber) return true;     // serialNumber 不一致 → 再取得
return proxyEsn.d;                               // expired フラグ → true なら再取得
```

### 2. キャッシュ有効期限

`ProxyEsn` コンストラクタで有効期限を判定:

```java
// ProxyEsn.$init()
long ttl = this.f;  // EsnHendrixConfig.refreshProxyEsnTimeInMs
if (ttl < 1) {
    this.d = false;  // expired = false → 無期限キャッシュ
    return;
}
boolean expired = C20986jOb.c(ttl, this.g);  // TTL ベースの期限判定
this.d = expired;
```

**実測値: `refreshProxyEsnTimeInMs = 0`**

TTL が 0 のため、**PXA ESN は一度取得したら無期限にキャッシュされる**。`getProxyEsn` が再発行されるのは以下のケースのみ:

- 初回インストール時
- アプリデータクリア時
- SharedPreferences が消えたとき
- `masterTokenSerialNumber` が変わったとき

### 3. MSL リクエスト

`ProxyEsnMslRequest` が MSL 経由で `/getProxyEsn` にリクエストを送信する。

**リクエストボディ:**

```json
{"url": "/getProxyEsn"}
```

**リクエストヘッダー:**

MSL 層で暗号化されるため、HTTP レベルでのヘッダーは空。MSL VolleyRequest のヘッダーとして `router: getProxyEsn` が設定される。

```java
// ProxyEsnMslRequest.getHeaders()
C20979jNv.e(d, "router", "getProxyEsn", true, true);
d.remove("x-netflix.nq-shadow.id");
d.remove("x-netflix.nq-shadow");
```

### 4. MSL レスポンス

サーバー (`playapi`) が PXA ESN を JSON で返す。

**レスポンス:**

```json
{
  "id": 1,
  "version": 2,
  "serverTime": 1773478742949,
  "result": {
    "esn": "NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-02028KVLM5OU1MSBUS4RUV6011TPPJVL5CS65GVMMH6PD5I6TSR8TMAC49OTSG3I4BJ3P78GD7ECQ6CVIIFHPN52CC20RJ2CPEE0A3FF"
  },
  "common": {},
  "from": "playapi"
}
```

| フィールド | 説明 |
|---|---|
| `id` | リクエスト ID |
| `version` | プロトコルバージョン |
| `serverTime` | サーバー時刻 (epoch ms) |
| `result.esn` | PXA ESN 本体 |
| `from` | 発行元サーバー (`playapi`) |

- Cookie ではない。MSL レスポンスの JSON ボディで返される。
- fingerprint 部分はサーバー側で生成されるため、ローカルでは再現不可。
- **起動ごとに異なる fingerprint が返される** (同一デバイスでも毎回異なる)。

### 5. 保存

`ProxyEsn.onKnown(Long serialNumber, String esn)` で SharedPreferences に永続化。

```java
// ProxyEsn.onKnown()
this.b = esn;
jNK.b(this.e, "nf_drm_esn", esn);             // PXA ESN 文字列
this.g = System.currentTimeMillis();
this.c = serialNumber;

JSONObject json = new JSONObject();
json.put("esn", this.b);
json.put("ts", this.g);                         // 取得時刻
json.put("sn", this.c);                         // masterTokenSerialNumber
jNK.b(this.e, "nf_drm_proxy_esn", json.toString());
```

**SharedPreferences キー:**

| キー | 値 | 例 |
|---|---|---|
| `nf_drm_esn` | PXA ESN 文字列 | `NFANDROID1-PXA-P-L3-GOOGLPIXEL=...` |
| `nf_drm_proxy_esn` | JSON メタデータ | `{"esn":"...","ts":1773478742949,"sn":8572399748193023}` |

### 6. 使用

取得後、以下のヘッダーで API リクエストに付与される:

| ヘッダー | 用途 |
|---|---|
| `X-Netflix.esn` | GraphQL / Cronet リクエスト |
| `X-Netflix-ProxyEsn` | WebSocket / MSL リクエスト |

---

## PXA ESN 構造

```
NFANDROID1-PXA-P-L3-GOOGLPIXEL=4A==5G=-22594-02028KVLM5OU1MSB...
│          │   │ │  │                   │      └─ サーバー発行 fingerprint (毎回異なる)
│          │   │ │  │                   └─ Widevine systemId
│          │   │ │  └─ sanitized model (Base ESN と同じ)
│          │   │ └─ Security Level (L3)
│          │   └─ Device Category (P=Phone)
│          └─ Type: PXA = Proxy (サーバー発行)
└─ Platform prefix
```

---

## タイムライン (実測)

```
08:41:58.240  ProxyEsn.$init()           expired=true (キャッシュなし or 期限切れ)
08:41:58.240  getHeaders()               router=getProxyEsn
08:41:58.248  getBodyForNq()             {"url":"/getProxyEsn"}
             ── MSL リクエスト送信 ──
08:41:59.567  onSuccess()                レスポンス受信 (約1.3秒後)
08:41:59.569  ProxyEsn.onKnown()         SharedPreferences に保存 (2ms後)
             ── 以後のAPIリクエストで PXA ESN を使用 ──
```

---

## 関連クラス

| クラス | 役割 |
|---|---|
| `ProxyEsnMslRequest` | `/getProxyEsn` MSL リクエスト発行 |
| `ProxyEsn` | PXA ESN のキャッシュ管理・永続化 |
| `WidevineEntityAuthEsnProviderImpl` | ESN プロバイダー (PRV/PXA 統合管理) |
| `EsnHendrixConfig` (`o.fkQ`) | `refreshProxyEsnTimeInMs` 設定値 |
| `InterfaceC13214fkS` | `onKnown` コールバック |

---

## キャプチャ方法

`hook_msl.js` で以下のフックが有効:

| フック | イベント名 | 内容 |
|---|---|---|
| `ProxyEsn.$init` | `proxyEsn.forceExpired` | expired を強制 true にして再取得を発火 |
| `ProxyEsnMslRequest.getBodyForNq` | `proxyEsn.request` | リクエストボディ |
| `ProxyEsnMslRequest.getHeaders` | `proxyEsn.requestHeaders` | リクエストヘッダー |
| `ProxyEsnMslRequest.onSuccess` | `proxyEsn.response` | レスポンス JSON |
| `ProxyEsnMslRequest.e` | `proxyEsn.error` | エラー |
| `ProxyEsn.onKnown` | `proxyEsn.onKnown` | 保存される ESN と serialNumber |

```bash
./run_android.sh hook_msl.js
```
