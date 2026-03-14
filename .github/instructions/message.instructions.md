---
applyTo: 'ipa_extracted/**'
---

## MSL 解析手順 (LLM 向け)

### 静的解析

1. IPA を展開: `unzip -o Netflix-15.48.1.ipa -d ipa_extracted/`
2. MSL バイナリ: `ipa_extracted/Payload/Argo.app/Frameworks/MslClient.framework/MslClient` (arm64 Mach-O)
3. ObjC クラス抽出: `strings MslClient | grep -E '^\+\[|^\-\[' | sed 's/\[//;s/ .*//' | sort -u`
4. C++ シンボル抽出: `nm --demangle MslClient | grep 'netflix.*msl'`
5. JSON フィールド名・定数: `strings MslClient | grep -E '^(mastertoken|headerdata|payloadchunk|scheme|...)$'`

### 動的解析 (Frida)

`hook_netflix.js` を Frida Gadget 注入済み IPA で実行。`run.py` が `@@LOG@@{json}` をパースし `logs/{date}/{domain}/` に保存。

**Hook 関数と目的:**

| 関数 | Hook 対象 | 取得データ |
|---|---|---|
| `hookSSLPinning()` | `-[* URLSession:didReceiveChallenge:completionHandler:]` (NF/Netflix/Osprey) | SSL pinning 回避 |
| `hookSSL()` (無効) | `SSL_write` / `SSL_read` (libboringssl) | TLS 平文 (MSL 暗号文のまま) |
| `hookMSL()` | `IosMslClient -sendAPIRequest:extraHeaders:params:userAuthData:requestOptions:callback:` | **暗号化前の API パス (args[2]) とパラメータ (args[4])** |
| `hookMSL()` | `IosMdxCryptoContext -encrypt:` / `-decrypt:` | MDX 暗号化前後のデータ |
| `hookObjCTrace()` | `+[NSURL URLWithString:]` / `-[NSMutableURLRequest setHTTPBody:]` | URL と HTTP ボディ |
| `hookCrypto()` (無効) | `CCCrypt` / `SecKeyEncrypt` / `SecKeyRawSign` | CommonCrypto/Security 暗号処理 |
| `hookMslCrypto()` | `aesCbcEncrypt` / `aesCbcDecrypt` (MslClient) | AES-CBC 鍵・IV・平文・暗号文 |
| `hookMslCrypto()` | `signHmacSha256` (MslClient) | HMAC 鍵・署名対象・署名値 |
| `hookMslCrypto()` | `aesKwUnwrap` (MslClient) | KEK・ラップ鍵 → セッション鍵 |
| `hookMslCrypto()` | `dhComputeSharedSecret` (MslClient) | DH 秘密鍵・公開鍵・素数 → 共有鍵 |
| `hookMslCrypto()` | `rsaEncrypt` / `rsaDecrypt` (MslClient) | RSA 入出力 |

**C++ 引数の読み方:** `std::vector<uint8_t>` は `+0x00: __begin_` (ptr), `+0x08: __end_` (ptr)。size = end - begin。

**ObjC args オフセット:** args[0]=self, args[1]=_cmd, args[2]~ が実引数。

### ログイベント種別

| event | 内容 |
|---|---|
| `msl.api` | MSL API リクエスト (domain, url, params) |
| `msl.encrypt.input` / `msl.decrypt.output` | MDX 暗号化/復号データ |
| `msl.aesCbcEncrypt.*` / `msl.aesCbcDecrypt.*` | AES-CBC の key, iv, plaintext, ciphertext |
| `msl.hmacSha256.*` | HMAC の key, data, signature |
| `msl.aesKwUnwrap.*` | AES-KW の kek, wrappedKey, unwrappedKey |
| `msl.dh.*` | DH の privKey, pubKey, prime, sharedSecret |
| `url` | URL アクセス |
| `http.request` | HTTP リクエスト (method, url, content_type, body) |

### 詳細ドキュメント

MSL プロトコルの構造・暗号スタック・クラス構成の詳細は `docs/msl.md` を参照。
