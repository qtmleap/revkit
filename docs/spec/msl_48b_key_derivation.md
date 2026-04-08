# MSL 48-byte HMAC Key Derivation (nflxDhDerive)

## Summary

Netflix の MSL DH 鍵交換において、48 バイトの HMAC-SHA384 鍵がどのように導出されるかを
`NFWebCrypto.framework` (Netflix iOS 15.48.1, arm64) の静的解析により特定した。

**導出チェーン:**

```
native_key_bytes (XOR デコード済)
    ↓ SHA-384
48B HMAC key
    ↓ HMAC-SHA384(key=48B, msg=[0x00 || DH_shared_secret])
48B output → enc_key[0:16] + sign_key[16:48]
```

## 関数情報

| 項目 | 値 |
|------|-----|
| 関数名 | `netflix::AppleWebCrypto::nflxDhDerive` |
| アドレス | `0x0000FEEC` (vector variant, 1452 bytes) |
| HMAC 呼び出し | `0x000101A0` (`bl sym._HMAC`) |
| SHA384 呼び出し | `0x00010174` (`bl sym._SHA384`) |
| getBytes (XOR デコード) | `0x0000D7E0` |
| バイナリ | `NFWebCrypto.framework/NFWebCrypto` (3.4MB arm64 Mach-O) |

## 導出の詳細手順

### Step 1: DH 共有秘密の計算

```c
// peer の公開鍵を BIGNUM に変換
BIGNUM* pub_bn = BN_bin2bn(peer_pub_key, peer_pub_key_len, NULL);

// DH 公開鍵の検証
DH_check_pub_key(dh, pub_bn, &codes);

// DH 共有秘密を計算
int ss_len = DH_compute_key(shared_secret, pub_bn, dh);
```

### Step 2: 先頭 0x00 バイトの付加

```c
// MSL ワイヤフォーマット: 共有秘密の先頭バイトが 0 でなければ 0x00 を付加
if (shared_secret[0] != 0x00) {
    shared_secret.insert(begin, 0x00);
}
// → message = [0x00 || DH_shared_secret] (通常 129 バイト)
```

### Step 3: 48B HMAC 鍵の導出 (核心部分)

```c
// 1. DH 秘密鍵の生バイト列を取得 (XOR デコード)
shared_ptr<KeyByteArray> key_bytes = derivation_key->getBytes();  // 0x10160

// 2. SHA-384 ハッシュで 48 バイトの鍵を生成
SHA384(key_bytes.data(), key_bytes.size(), sha384_out);           // 0x10174
// sha384_out = 48 bytes
```

**AppleNativeKey::getBytes() (0xD7E0) の XOR デコード:**

```c
uint8_t mask = this->xor_byte;    // offset 0x0C の 1 バイト
for (size_t i = 0; i < key_len; i++) {
    output[i] = stored_key[i] ^ mask;
}
```

### Step 4: HMAC-SHA384 による最終導出

```c
// HMAC(EVP_sha384, SHA384(key_bytes), 0x30, [0x00||shared_secret], ss_len, out, NULL)
HMAC(
    EVP_sha384(),           // x0: ダイジェストアルゴリズム
    sha384_out,             // x1: 鍵 = SHA384(native_key_bytes) [48B]
    0x30,                   // w2: 鍵長 = 48
    shared_secret.data(),   // x3: メッセージ = [0x00 || DH_shared_secret]
    shared_secret.size(),   // x4: メッセージ長
    hmac_output,            // x5: 出力バッファ
    NULL                    // x6: 出力長 (不要)
);
// hmac_output = 48 bytes
```

### Step 5: 鍵の分割

```
hmac_output (48 bytes)
├── [0:16]   → enc_key   (AES-128-CBC 暗号化鍵, type=0x3, extractable=true)
├── [16:48]  → sign_key  (HMAC-SHA256 署名鍵, type=0xC, extractable=false)
└── [0:48]   → wrap_key  (HMAC-SHA384 ラップ鍵, type=0x70)
```

## 静的データ

HMAC 導出後、以下の 16 バイト定数が HKDF 的な鍵ラッピング操作に使用される:

| 名前 | アドレス | 値 (hex) |
|------|---------|----------|
| PSK (salt) | `0x1AC8F5` | `02 76 17 98 4f 62 27 53 9a 63 0b 89 7c 01 7d 69` |
| Nonce (info) | `0x1AC905` | `80 9f 82 a7 ad df 54 8d 3e a9 dd 06 7f f9 bb 91` |

## 呼び出しフロー図

```
nflxDhDerive(dh_key_handle, peer_pub_key, derivation_handle, ...)
│
├── BST lookup(dh_key_handle) → DH private key entry
├── DH_size(dh) → allocate shared_secret buffer
├── BN_bin2bn(peer_pub_key) → pub_bn
├── DH_check_pub_key(dh, pub_bn)
├── DH_compute_key(shared_secret, pub_bn, dh)
│     └── if shared_secret[0] != 0: prepend 0x00
│
├── BST lookup(derivation_handle) → derivation key entry
├── AppleNativeKey::getBytes()  [XOR decode, 0xD7E0]
│     └── output ^ mask_byte → raw key material
│
├── SHA384(raw_key_material, key_len, sha384_out)        ← 48B 鍵生成
├── HMAC(EVP_sha384, sha384_out, 48, shared_secret, ...) ← 最終導出
│
├── enc_key  = output[0:16]   → insertKey(type=AES)
├── sign_key = output[16:48]  → insertKey(type=HMAC_SHA256)
├── wrap_key = output[0:48]   → insertKey(type=HMAC_SHA384)
│
└── vtable call with PSK + Nonce → key registration / HKDF
```

## 解析ツール

- `tools/re/analyze_nflxDhDerive.py` -- radare2 (r2pipe) ベースの自動解析スクリプト
- `tools/re/decompile_nflxDhDerive.py` -- LIEF + Capstone ベースの擬似コード再構築スクリプト

## 検証方法

Frida フックで以下を確認可能:

1. `SHA384` の入力バイト列と出力 48 バイトをダンプ
2. `HMAC` の引数 (x1=key, w2=0x30, x3=message, x4=len) をダンプ
3. 出力 48 バイトの分割 (`[0:16]` = enc_key, `[16:48]` = sign_key) を検証

```javascript
// Frida hook example
Interceptor.attach(Module.findExportByName("NFWebCrypto", "SHA384"), {
    onEnter(args) {
        console.log("SHA384 input:", hexdump(args[0], { length: args[1].toInt32() }));
    },
    onLeave(retval) {
        if (!retval.isNull()) {
            console.log("SHA384 output (48B key):", hexdump(retval, { length: 48 }));
        }
    }
});
```
