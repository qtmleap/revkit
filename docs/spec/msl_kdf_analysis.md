# Netflix iOS MSL KDF (Key Derivation Function) 解析

解析日: 2026-04-08
ソース: Tweak `AppbootKeyExtract` v39 HMAC streaming hooks ログ

---

## 1. 概要

Netflix iOS アプリの MSL セッション鍵更新は、**標準 HKDF ではなく独自の HMAC-SHA256 チェーン** で実装されている。

OpenSSL の EVP HKDF API (`EVP_PKEY_CTX_set_hkdf_*`) は使用されておらず、
低レベルの `HMAC_Init_ex` / `HMAC_Update` / `HMAC_Final` を直接呼び出している。

---

## 2. KDF アルゴリズム (鍵更新)

### 2.1 入力パラメータ

| パラメータ | サイズ | 説明 |
|-----------|--------|------|
| PSK (Pre-Shared Key) | 16 bytes | マスター鍵。DH 鍵交換時に導出される (§3 参照) |
| enc_key | 16 bytes | 現在の AES-128-CBC 暗号化鍵 |
| sign_key | 32 bytes | 現在の HMAC-SHA256 署名鍵 |
| nonce | 16 bytes | サーバーレスポンス key 33.9 から取得 |

### 2.2 演算ステップ (6段階)

```
Step 1: session_check = HMAC-SHA256(PSK, enc_key || sign_key)
Step 2: session_bind  = HMAC-SHA256(session_check, nonce)
Step 3: enc_temp      = HMAC-SHA256(PSK, enc_key)
Step 4: new_enc_full  = HMAC-SHA256(enc_temp, nonce)
        new_enc_key   = new_enc_full[:16]
Step 5: sign_temp     = HMAC-SHA256(PSK, sign_key)
Step 6: new_sign_key  = HMAC-SHA256(sign_temp, nonce)
```

### 2.3 出力

| 出力 | ステップ | サイズ |
|------|---------|--------|
| new_enc_key | Step 4 の先頭 16 bytes | 16 bytes (AES-128) |
| new_sign_key | Step 6 の全 32 bytes | 32 bytes (HMAC-SHA256) |
| session_bind | Step 2 の全 32 bytes | 32 bytes (セッションバインド検証用?) |

### 2.4 検証データ

```
PSK      = 027617984f6227539a630b897c017d69
enc_key  = 0817065e29e6d1c8668473af9e13b3c2
sign_key = 91f752f76d7ab4c2dc6e5b3ec1c0e5a16864421fe449be5457459602e298ebc1
nonce    = 809f82a7addf548d3ea9dd067ff9bb91

Step 1: 19def2f90d06bc8dfd04a19dbd4588d4e7b8aa6ccacb200f9ae6acc49355917d
Step 2: add2d4c818426aee3dfbbbb783a85262ee7c8cc1936013b53d5f4cb53d6baee0
Step 3: e60e376f37d7d962512aea2f29a353c28b0fb95b1e77c43baf7459b21d1df649
Step 4: 97b99f4e88e8e73779aa20ac11877c5dfe06b76df3e1dfe1378d6d9223f5b511
Step 5: 58c4e3d1cc2ce7bd73e846a1c3b00a9986aa039302d7bbf1a5508d5f9a49120f
Step 6: d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0

new_enc_key  = 97b99f4e88e8e73779aa20ac11877c5d  ← Step 4[:16]
new_sign_key = d45443fa11efec622c83b27c55f7a73143bdfa0d51820ac597b9e3fb5c28dbb0
```

---

## 3. 初期鍵導出 (DH → セッション鍵) — 未解明

### 3.1 判明している事実

- DH パラメータ: 1024-bit, g=5, p は Netflix 固有値 (`9694e9d8...`)
- DH 共有秘密 = 128 bytes
- PSK `027617984f6227539a630b897c017d69` (16 bytes) の由来は不明

### 3.2 MSL Java 参照実装との差異

MSL Java 参照実装 (`DiffieHellmanExchange.java`) の KDF:

```java
// 1. correct_null_bytes: 先頭に 0x00 を1つだけ付与
// 2. SHA-384(shared_secret)
// 3. enc_key = hash[0:16], hmac_key = hash[16:48]
```

**iOS Scheme 5 はこれとは完全に異なる**:
- Java 参照: SHA-384 一発。ラップキーなし。両者が独立に計算
- iOS Scheme 5: HMAC-SHA256 チェーン (§2)。PSK を使用
- SHA-384(DH_shared_secret) の出力は PSK `0276...` とも既知セッション鍵とも一致しない

### 3.3 解決: PSK と nonce はバイナリにハードコードされた定数

**Tweak v42/v43 の実験で確定:**

1. アプリの Library/Caches/Preferences/odb 等のファイルをすべて削除 → PSK は変わらない
2. Keychain の全エントリを `SecItemDelete` で削除 (status=0 成功) → PSK は変わらない
3. NFWebCrypto.framework バイナリを検索 → **PSK と nonce がバイナリに連続して埋め込まれている**

```
Offset 0x1ac8f5: 02 76 17 98 4f 62 27 53 9a 63 0b 89 7c 01 7d 69  ← PSK (16B)
Offset 0x1ac905: 80 9f 82 a7 ad df 54 8d 3e a9 dd 06 7f f9 bb 91  ← nonce (16B)
Offset 0x1ac915: N7netflix14AppleWebCryptoE                         ← C++ mangled name
```

直後の C++ シンボル名 `netflix::AppleWebCrypto` から、このクラスの静的定数として
コンパイルされたことがわかる。

**結論**: PSK と nonce はデバイス固有ではなく、**同じバージョンの NFWebCrypto.framework を
持つ全デバイスで共通の固定値**。Python 実装にそのままハードコードできる。

---

## 4. レスポンスキー交換データ構造

### 4.1 key 33 (key_response_data) の sub-key

| sub-key | 型 | サイズ | 説明 |
|---------|-----|--------|------|
| 6 | bytes | 96 | 暗号化されたセッション鍵 |
| 7 | bytes | 1 | ステータスフラグ (`0x00`) |
| 8 | string | 1 | スキーム ID (`'5'`) |
| 9 | bytes | 16 | サーバー nonce (KDF 入力) |

### 4.2 key 33.6 (96 bytes) の推定構造

```
[IV: 16 bytes][CT: 48 bytes][HMAC: 32 bytes]
```

- IV (16B): AES-CBC 初期化ベクトル
- CT (48B): AES-CBC 暗号文 → 平文 = enc_key(16B) + sign_key(32B)
- HMAC (32B): HMAC-SHA256(PSK?, IV||CT) による認証

---

## 5. 鍵の使用パターン

v39 ログから観測された暗号化/署名パターン:

```
[AES_set_encrypt_key bits=128] key=0817065e...   ← セッション暗号化鍵
[AES_cbc_encrypt] dir=ENC len=336 iv=...         ← MSL ペイロード暗号化
[HMAC] key_len=32 key=91f752f7...                ← セッション署名鍵で署名
```

全メッセージが同じ enc_key / sign_key で暗号化・署名されている。
鍵更新の結果 (97b99f4e / d45443fa) は次のセッションで使用される。

---

## 6. Python 実装

```python
import hashlib
import hmac

def netflix_msl_kdf_renew(
    psk: bytes,        # 16 bytes
    enc_key: bytes,    # 16 bytes
    sign_key: bytes,   # 32 bytes
    nonce: bytes,      # 16 bytes
) -> tuple[bytes, bytes]:
    """Netflix MSL セッション鍵更新 KDF."""
    # Step 1-2: セッションバインド (検証用)
    session_check = hmac.new(psk, enc_key + sign_key, hashlib.sha256).digest()
    session_bind = hmac.new(session_check, nonce, hashlib.sha256).digest()

    # Step 3-4: 新しい暗号化鍵
    enc_temp = hmac.new(psk, enc_key, hashlib.sha256).digest()
    new_enc_key = hmac.new(enc_temp, nonce, hashlib.sha256).digest()[:16]

    # Step 5-6: 新しい署名鍵
    sign_temp = hmac.new(psk, sign_key, hashlib.sha256).digest()
    new_sign_key = hmac.new(sign_temp, nonce, hashlib.sha256).digest()

    return new_enc_key, new_sign_key
```
