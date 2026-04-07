# Netflix iOS MSL CBOR 鍵交換解析

解析日: 2026-04-06  
対象ファイル:
- `raws/ios/20260406/raw/req_4_appboot_2026-04-06T09-42-43-664Z.bin` (8,675 bytes)
- `raws/ios/20260406/raw/res_4_appboot_2026-04-06T09-42-43-664Z.bin` (1,643 bytes)

---

## 1. CBOR メッセージトップレベル構造

### 1.1 appboot リクエスト

```
{
  34: bytes(7094)  ← entity_auth_data (FAIRPLAY_MGK_APPID)
  33: bytes(613)   ← key_request_data (鍵交換リクエスト)
  32: bytes(502)   ← header (capabilities)
  16: bytes(32)    ← message signature (HMAC-SHA256)
}
```

### 1.2 appboot レスポンス

```
{
  33: bytes(127)   ← key_response_data (鍵交換レスポンス)
  16: bytes(32)    ← message signature
  32: dict         ← header (capabilities, same as request)
}
```

通常 MSL リクエスト (manifest, logblob 等) は entity_auth_data (key 34) を含まず、
`{33, 32, 16}` のみ。全リクエストで master token (key 33 の sub-key 7) は空 bytes。

---

## 2. 鍵交換データ構造 (CBOR key 33)

### 2.1 リクエスト側 key 33 の sub-key マッピング

| sub-key | 値 | 説明 |
|---------|-----|------|
| 6 | bytes(464) | クライアント鍵交換データ (appboot) |
| 7 | bytes(0) | 前回 master token → 空 (新規セッション) |
| 8 | `'NFAPPL-02-IPHONE9=1-AD0455...FEB0B79E_3'` | identity (ESN + `_3` suffix) |
| 9 | bytes(16) `a97e47477522ab39e39b322bdf818031` | クライアント nonce |

### 2.2 レスポンス側 key 33 の sub-key マッピング

| sub-key | 値 | 説明 |
|---------|-----|------|
| 6 | bytes(96) | サーバーレスポンス (ラップされたセッション鍵) |
| 7 | bytes(1) `00` | status / フラグ |
| 8 | `'3'` | scheme ID (文字列 "3") |
| 9 | bytes(16) `e73104a8f4a9ed430d90a330d7978432` | サーバー nonce |

---

## 3. スキーム ID 3 の推定

### 3.1 根拠

- リクエスト key 8 の suffix `_3` と、レスポンス key 8 = `"3"` から、スキームは整数 **3** で識別される
- ヘッダー capabilities (key 32 → key 15 → key 14) = `3` — 全リクエスト共通
- `appboot_pinning_analysis.md` に記載の NFWebCrypto 関数: `dhKeyGen`, `dhDerive`, `HKDF`

### 3.2 既知スキームとの対応

Chrome/Android は `ASYMMETRIC_WRAPPED (JWK_RSA)` を使用。
iOS CBOR スキーム 3 は Netflix 独自の DH ベース鍵交換と推定される:

1. クライアントが DH (または ECDH) 鍵ペアを `dhKeyGen` で生成
2. DH 公開値を `kAppBootKey` (RSA-4096、NFWebCrypto.framework にハードコード) で暗号化してサーバーへ送信
3. サーバーレスポンスの署名を `kAppBootEccKey` (ECDSA P-256) で検証
4. DH 共有秘密から `HKDF` でセッション鍵を導出

---

## 4. リクエスト key 33.6 (464 bytes) の解析

### 4.1 バイト列特性

| 指標 | 値 |
|------|-----|
| サイズ | 464 bytes |
| エントロピー (全体) | 7.565 bits/byte |
| 先頭バイト | `0xf2` (high bit set) |
| 末尾 32 bytes エントロピー | 4.875 (やや低い) |
| ASN.1 DER SEQUENCE (0x30) | offset 23 のみ (単独) |
| CBOR デコード | CBORSimpleValue(18) → 有効な CBOR 構造でない |

### 4.2 フォーマット仮説

**仮説 A: DH 公開値 (カスタム 3712-bit グループ)**

- 3712 bit = 464 bytes の素数 p に対する g^x mod p
- 標準グループ (RFC 3526 group 14: 256B, 15: 384B, 16: 512B) に一致しない
- Netflix 独自の DH グループを使用している可能性

**仮説 B: RSA-4096 暗号化文の変形**

- RSA-4096 標準出力: 512 bytes
- 512 - 48 = 464 → nonce (key 9 = 16 bytes) + HMAC (32 bytes) = 48 bytes を分離?
- OAEP の標準的な分割ではないため、カスタム実装の可能性
- SHA-256 OAEP: maskedSeed=32B, maskedDB=479B → どの分割方法でも 464 にならない

**仮説 C: 複合構造**

通常 MSL key 6 (1168 bytes / 1216 bytes) との比較:

| サイズ | 式 | 整数倍 |
|--------|-----|--------|
| 464 (appboot) | 464 | — |
| 1168 (MSL) | 256 + 19 × 48 | ✓ |
| 1216 (MSL) | 256 + 20 × 48 | ✓ |

通常 MSL の場合: `(size - 256) % 48 == 0` が成立。
- 256 bytes = RSA-2048 で暗号化された DH 値 (仮)
- N × 48 bytes = 追加の device auth credential (各 48 bytes の構造化データ)

appboot の 464 bytes はこのパターンに当てはまらず、appboot 専用の別フォーマットの可能性がある。

### 4.3 エントロピー分布

```
bytes   0- 31 (32): entropy=4.88  f29fff0f763ea6d0
bytes  32- 63 (32): entropy=4.88  da21f6feff566e51
...
bytes 432-463 (32): entropy=4.00  22f79fef0e7bc144 (末尾は低い)
```

末尾 16 bytes のエントロピー (4.0) が特に低い。
暗号的にランダムなデータとしては低すぎるため、構造的なパディングまたは固定フィールドの可能性がある。

---

## 5. レスポンス key 33.6 (96 bytes) の解析

```
bb73317f907f7a5a3f924bece878d6a6  (bytes 0-15)
8db3b8f354d2207a224a323297523f58  (bytes 16-31)
2d72dfb28ea593b584d096c861561be8  (bytes 32-47)
b7d72ef4dc404e076943130aa0303200  (bytes 48-63)
af5d720284876f9b1c076aacc2ad7fc8  (bytes 64-79)
6b5a242b0cf9beb28b2a87ad00f3db38  (bytes 80-95)
```

### 5.1 96 bytes = 2 × 48 bytes (unit)

レスポンスサイズは **48 bytes の整数倍**:
- appboot レスポンス: 96 = **2 × 48**
- MSL レスポンス: 432 = **9 × 48**

### 5.2 最有力構造: `[CT(64B)][HMAC-SHA256(32B)]`

```
CT   (64 bytes): bb73317f907f7a5a...aa0303200
HMAC (32 bytes): af5d720284876f9b...00f3db38
```

- CT(64B) = AES-CBC 暗号文 (64 bytes = PKCS7 パディング付き 48 bytes の平文を暗号化)
- 平文 48 bytes: `enc_key (16 bytes) + hmac_key (32 bytes)` ← MSL セッション鍵
- HMAC(32B) = HMAC-SHA256 で CT を認証

この構造であれば、**セッション鍵 (enc_key + hmac_key) は CT(64B) に含まれている**。

### 5.3 代替構造: `[IV(16B)][CT(48B)][HMAC-SHA256(32B)]`

```
IV   (16 bytes): bb73317f907f7a5a3f924bece878d6a6
CT   (48 bytes): 8db3b8f354d2207a...aa0303200
HMAC (32 bytes): af5d720284876f9b...00f3db38
```

- CT(48B) → 平文 32 bytes: `enc_key (16 bytes) + hmac_key_part (16 bytes)` のみ?
- hmac_key が 16 bytes に短縮されている可能性

---

## 6. セッション鍵導出の制約

### 6.1 導出に必要な要素 (未取得)

| 要素 | 説明 | 取得可能性 |
|------|------|----------|
| `kAppBootKey` RSA-4096 秘密鍵 | Netflix サーバーサイドの秘密鍵 | **不可能** (サーバー管理) |
| DH 秘密鍵 `x` | クライアントのエフェメラル秘密鍵 | Frida フックで取得可能 |
| DH 共有秘密 | `g^(xy) mod p` または ECDH 座標 | `NFWebCrypto::dhDerive` 出力をフック |
| HKDF 出力 | セッション鍵 (enc + hmac) | `HKDF` 関数出力をフック |

### 6.2 捕捉データのみでの導出可否

**導出不可能**。理由:

1. key 33.6 (464 bytes) がどのフォーマットであれ、サーバーが `kAppBootKey` 秘密鍵で復号しなければ共有秘密は計算できない
2. レスポンス key 33.6 (96 bytes) の AES 復号鍵 = DH 共有秘密から HKDF で導出されたラッピングキー → 上記同様に取得不可

### 6.3 実現可能なアプローチ

**方法 1: Frida フック (推奨)**

```javascript
// NFWebCrypto::dhDerive の出力をフック
// または
// NFWebCrypto::aesCbc の AES 鍵引数をフック
```

`packages/frida/hook_netflix_ios.js` を拡張して以下をフック:
- `NFWebCrypto::dhDerive` — 共有秘密の出力
- HKDF 関数の出力 (AES-128 enc_key + HMAC-SHA256 sign_key)
- `NFWebCrypto::aesCbc` の第1引数 (AES 鍵)

**方法 2: MSL デコーダーで暗号化前データをキャプチャ**

`packages/mitmproxy/msl_decoder.py` を拡張し、SSL pinning バイパス後に平文 HTTP ボディを取得。

---

## 7. ヘッダー固定値 (参考)

### 7.1 capabilities key 16 (44 bytes, 全リクエスト共通)

```
010100810001012022b1205c03559bc416af500d517f2c15463fc04717f8fb38b40c5ddce4e24fe11cc01955
```

リクエスト・レスポンス双方に同一値が含まれる。変化しないため、MSL プロトコルバージョンまたは
device capability descriptor と推定される。

### 7.2 capabilities key 10 (393 bytes, 全リクエスト共通)

先頭: `0500800001011003c3c408c0...`  
エントロピー: 7.43 bits/byte (高い)  
変化なし → NFWebCrypto.framework にハードコードされた固定クレデンシャルまたはサーバー公開鍵候補。

### 7.3 capabilities key 11-14 (全リクエスト共通)

| key | 値 | 推定意味 |
|-----|-----|--------|
| 11 | `1775490174` | Unix timestamp = 2026-04-06 15:42:54 (セッション開始時刻) |
| 12 | `2195053559663813` | Message ID or Session ID (< 2^52) |
| 13 | `1776613374` | Unix timestamp = 2026-04-19 15:42:54 (セッション有効期限, 13日後) |
| 14 | `3` | 鍵交換スキーム ID (scheme 3) |

---

## 8. appboot と通常 MSL の差異

| 項目 | appboot | 通常 MSL |
|------|---------|---------|
| entity_auth_data (key 34) | あり (FAIRPLAY_MGK_APPID) | なし |
| key 33.6 サイズ | 464 bytes | 1168 または 1216 bytes |
| key 7 (master token) | 空 | 空 |
| レスポンス key 33.6 | 96 bytes | 432 bytes |
| レスポンス形式 | CBOR | gzip 圧縮 CBOR |
| エラー形式 | CBOR | JSON (errordata + entityauthdata) |

通常 MSL の key 33.6 が appboot より大きい (1168/1216 vs 464) のは、entity_auth_data を含まない代わりに device 認証情報を key 33.6 内に埋め込んでいる可能性がある。

---

## 9. 結論

| 項目 | 状態 |
|------|------|
| CBOR トップレベル構造 | ✓ 完全に解析済み |
| key 33 sub-key マッピング | ✓ 解析済み |
| スキーム ID 3 の正体 | 推定: DH/ECDH ベース (NFWebCrypto::dhKeyGen/dhDerive を使用) |
| key 33.6 (464B) のフォーマット | 未解明 (DH 公開値またはカスタム暗号文の変形) |
| key 33.6 レスポンス (96B) の構造 | 推定: `CT(64B)+HMAC(32B)` = ラップされたセッション鍵 |
| セッション鍵の導出 | **不可** (DH 共有秘密なしに復号不能) |

**ボトルネック**: `kAppBootKey` RSA-4096 秘密鍵 (サーバーサイド保有) または Frida による
`NFWebCrypto::dhDerive` / `HKDF` 出力のキャプチャが必要。
