# MSL Key 33.6 TFIT Encoding Analysis

NFWebCrypto.framework (Netflix iOS 15.48.1, arm64) の静的解析に基づく、
DH 公開鍵 (128B) から key 33.6 (352B) への TFIT エンコーディングの詳細。

## 概要

key 33.6 の生成パイプラインは以下の通り:

```
vendorDerivedESN (文字列)
       │
       ▼
  SHA-384(ESN) → 48 bytes ハッシュ
       │
       ├── bytes[0:16]  → TFIT-WB-AES-128-ECB → 暗号化済み 16B (MGK part 1)
       ├── bytes[16:32] → TFIT-WB-AES-128-ECB → 暗号化済み 32B (MGK part 2)
       └── bytes[32:48] → TFIT-WB-AES-128-ECB → 暗号化済み 32B (MGK part 2 続き)
       │
       ▼
  MGK = (16B vector, 32B vector)  ← Model Group Keys
       │
       ▼
  key 33.6 payload = 128B CBOR header ∥ TFIT(DH_pubkey) ∥ per-request data
       │
       ▼
  XOR with nonce (key 33.9) → 送信
```

## 1. genModelGroupKeys の擬似コード

```
Location: 0x1DB74
Signature: genModelGroupKeys(MGKType type, const std::string& esn)
           → pair<vector<u8>, vector<u8>>

pair<vector<u8>, vector<u8>> genModelGroupKeys(MGKType type, const string& esn) {
    // 1. ESN の SHA-384 ハッシュ (48 bytes)
    u8 hash[48];
    SHA384_CTX ctx;
    SHA384_Init(&ctx);
    SHA384_Update(&ctx, esn.data(), esn.size());
    SHA384_Final(hash, &ctx);

    // 2. result.first = 16 bytes (zero-initialized)
    result.first.assign(16, 0);

    // 3. hash[0:16] を TFIT-WB-AES-128-ECB で暗号化 → result.first
    encryptAes128Ecb(type, hash, result.first.data());

    // 4. result.second = 32 bytes (zero-initialized)
    result.second.assign(32, 0);

    // 5. hash[16:32] を暗号化 → result.second[0:16]
    encryptAes128Ecb(type, hash + 16, result.second.data());

    // 6. hash[32:48] を暗号化 → result.second[16:32]
    encryptAes128Ecb(type, hash + 32, result.second.data() + 16);

    return result;
}
```

## 2. encryptAes128Ecb の擬似コード

```
Location: 0x1DDB8
Signature: encryptAes128Ecb(MGKType type, u8* plaintext, u8* ciphertext)

void encryptAes128Ecb(MGKType type, u8* input, u8* output) {
    // 1. デフォルトで iPhone テーブルをロード
    u8 key_schedule[224];
    memcpy(key_schedule, TFIT_key_iAES11_mgkiPhone, 224);

    // 2. デバイスタイプに応じてテーブルを差し替え
    switch (type) {
        case 1:  // iPad
            memcpy(key_schedule, TFIT_key_iAES11_mgkiPad, 224);
            break;
        case 2:  // Apple TV
            memcpy(key_schedule, TFIT_key_iAES11_mgkATV, 224);
            break;
        default: // iPhone (already loaded)
            break;
    }

    // 3. 0xE4 bytes の WB-AES コンテキストを確保
    TFIT_ctx* ctx = new TFIT_ctx;  // 228 bytes, zero-initialized
    memset(ctx, 0, 0xE4);

    // 4. アラインメント調整 + key_schedule コピー
    u8* aligned = ctx + (ctx & 3);  // 4-byte alignment
    memcpy(aligned, key_schedule, 224);

    // 5. TFIT WB-AES-128 ECB 暗号化 (1 ブロック = 16 bytes)
    TFIT_wbaes_ecb_encrypt_iAES11(aligned, input, 16, output);

    delete ctx;
}
```

## 3. TFIT WB-AES-128 ECB 暗号化アルゴリズム

### 3.1 エントリポイント

```
TFIT_wbaes_ecb_encrypt_iAES11 @ 0x248C4
  → null チェック後、TFIT_wbaes_ecb_cipher_iAES11 にジャンプ

TFIT_wbaes_ecb_cipher_iAES11 @ 0x26C9C
  → サイズが 16 の倍数か検証
  → n_blocks = size >> 4
  → 各ブロックに対して TFIT_op_iAES11 を呼ぶ
```

### 3.2 TFIT_op_iAES11 (1 ブロック処理)

```
Location: 0x25CB0
Signature: TFIT_op_iAES11(TFIT_ctx* ctx, u8* input, u8* output)

uint32_t TFIT_op_iAES11(TFIT_ctx* ctx, u8 input[16], u8 output[16]) {
    // state[0..15] = 入力バイトをインデックス化
    // state[i] = (i * 0x100) | input[i]  (16-bit index: position ∥ byte value)
    uint32_t state[16];
    for (int i = 0; i < 16; i++) {
        state[i] = (i << 8) | input[i];
    }

    // ====== Round 0 (Initial AddRoundKey + SubBytes via LUT) ======
    // ctx のオフセット 0x10..0x1C に格納された key schedule の一部とXOR
    // rlut_0[state[i]] で T-table lookup
    uint32_t s0 = rlut_0[state[0]]  ^ ctx[0x10] ^ rlut_0[state[5]]
                ^ rlut_0[state[10]] ^ rlut_0[state[15]];
    uint32_t s1 = rlut_0[state[4]]  ^ ctx[0x14] ^ rlut_0[state[9]]
                ^ rlut_0[state[14]] ^ rlut_0[state[3]];
    uint32_t s2 = rlut_0[state[8]]  ^ ctx[0x18] ^ rlut_0[state[13]]
                ^ rlut_0[state[2]]  ^ rlut_0[state[7]];
    uint32_t s3 = rlut_0[state[12]] ^ ctx[0x1C] ^ rlut_0[state[1]]
                ^ rlut_0[state[6]]  ^ rlut_0[state[11]];

    // ====== Rounds 1-8 (Main rounds) ======
    // 各ラウンドで:
    //   1. state をバイト分解してインデックス化 (byte + position*0x100)
    //   2. rlut_N[index] で T-table lookup
    //   3. ctx の対応するラウンドキーワードと XOR
    //   4. ShiftRows は lookup インデックスの順序で暗黙的に実行
    for (int r = 1; r <= 8; r++) {
        // バイト分解: s0→4 bytes, s1→4 bytes, s2→4 bytes, s3→4 bytes
        // 各バイトに position prefix (0x000..0xF00) を OR
        // rlut_(2*r-1) と rlut_(2*r) を交互に使用
        // (実際には unrolled、各ラウンドが異なる rlut を使う)
        // MixColumns は T-table に埋め込まれている
        ...
    }

    // ====== Round 9 (Special: TFIT_r9_op_iAES11) ======
    // 0x248DC で処理
    // rmat_9_* と rmask_9_* を使った再エンコーディング
    TFIT_r9_op_iAES11(ctx, state_round8, state);

    // ====== Round 10 (Final round: SubBytes + ShiftRows + AddRoundKey) ======
    // rlut_11 で最終ラウンドの T-table lookup
    // 最終ラウンドには MixColumns がない (AES-128 標準)

    // ====== Output encoding ======
    // 16 個の output S-box (out_0..out_15) で各バイトを変換
    for (int i = 0; i < 16; i++) {
        output[i] = out_i[byte_i_of_state];  // バイト単位の S-box
    }

    return 0;
}
```

### 3.3 ラウンド構造の詳細

| Round | 使用する rlut | ctx offset (Round Key) | 備考 |
|-------|-------------|----------------------|------|
| 0 | rlut_0 | 0x10-0x1C | Initial: AddRoundKey + T-table |
| 1 | rlut_1 | 0x20-0x2C | |
| 2 | rlut_2 | 0x30-0x3C | |
| 3 | rlut_3 | 0x40-0x4C | |
| 4 | rlut_4 | 0x50-0x5C | |
| 5 | rlut_5 | 0x60-0x6C | |
| 6 | rlut_6 | 0x70-0x7C | |
| 7 | rlut_7 | 0x80-0x8C | |
| 8 | rlut_8 | 0x90-0x9C | |
| 9 | (rmat/rmask) | via TFIT_r9_op | Re-encoding round |
| 10 | rlut_11 | 0xD0-0xDC | Final round (no MixColumns) |
| Out | out_0..15 | - | Output byte permutation |

### 3.4 T-table (rlut) の構造

各 rlut は 4096 エントリ (u32)。インデックスは `(position << 8) | byte_value`:

```
rlut[i] where i = (column * 256) + plaintext_byte
```

これは標準 AES の **T-table** に相当し、以下を1つのテーブル参照に融合:

```
T[x] = MixColumns(SubBytes(x))  // u32 出力
```

ラウンドキーは T-table 出力に XOR される (White-box では鍵が埋め込まれている)。

### 3.5 Output S-box

最終出力で 16 個の独立した 256-byte 置換テーブル (全て全単射) を適用。
これは **external encoding** であり、出力をスクランブルして中間値の復元を防ぐ。

**重要**: この外部エンコーディングは送信前に逆変換される必要がある。
サーバー側が同じ S-box の逆を持っているか、あるいは XOR nonce (key 33.9) の適用が
このエンコーディングを相殺する仕組みになっている。

## 4. TFIT テーブルのバイナリ内位置

| テーブル | オフセット | サイズ | エントロピー |
|---------|-----------|--------|-------------|
| mgkATV key schedule | 0x1ACF28 | 224B | 0.66 (mostly zeros) |
| mgkiPad key schedule | 0x1AD008 | 224B | 7.07 |
| mgkiPhone key schedule | 0x1AD0E8 | 224B | 7.04 |
| rmat_9_0..5 | 0x1AD630 | 6 x 96B | - |
| rmat_10_0..7 | 0x1AD870 | 8 x 96B | - |
| rmask_9_0..5 | 0x1ADB70 | 6 x 4B | - |
| rmask_10_0..7 | 0x1ADB88 | 8 x 4B | - |
| rlut_0..11 | 0x1ADBA8 - 0x1D9BA8 | 12 x 16KB | ~8.00 |
| out_0..15 | 0x1DDBA8 - 0x1DEBA8 | 16 x 256B | 8.00 (全て全単射) |
| **合計** | 0x1ACF28 - 0x1DEBA8 | **199.1 KB** | 8.00 |

## 5. MGKType とデバイス選択

```
enum MGKType {
    iPhone = 0,  // デフォルト
    iPad   = 1,
    ATV    = 2,  // Apple TV
};
```

`AppleWebCrypto` コンストラクタで `[device mgkDeviceType]` から取得。

**注意**: ATV のキースケジュールは最初の 16 バイトのみ非ゼロ (残り 208 バイトがゼロ)。
これは ATV 向けの WB-AES 鍵が不完全か、別のコードパスが使われることを示唆する。

## 6. DH 公開鍵から key 33.6 への変換 (推定フロー)

DH 公開鍵 (128B) は `genModelGroupKeys` の **入力ではない**。
`genModelGroupKeys` は ESN から MGK ペアを生成する。

key 33.6 の構成 (352B の場合):

```
key 33.6 [352B] =
  ┌─ CBOR header [128B]     ← 静的メタデータ (key ID, algorithm 等)
  ├─ TFIT(DH_pubkey) [160B] ← DH 公開鍵の TFIT 変換
  │    └─ 128B DH pubkey を 8 ブロック x 16B で WB-AES-ECB
  │       → 128B ciphertext + 32B MGK = 160B
  └─ Per-request data [64B] ← タイムスタンプ、sequence number 等
```

key 33.6 (144B の場合、圧縮形式):

```
key 33.6 [144B] =
  ┌─ CBOR header (短縮) [~16B]
  └─ DH pubkey TFIT [128B]  ← 8 blocks x WB-AES-128-ECB
```

### TFIT エンコーディングの方式

**Block-by-block AES-128-ECB** (White-box 実装):

```
for (int i = 0; i < 8; i++) {
    TFIT_wbaes_ecb_encrypt_iAES11(
        mgk_key_schedule,      // 224B device-specific key
        dh_pubkey + i * 16,    // 16B plaintext block
        output + i * 16        // 16B ciphertext block
    );
}
```

- 使用するテーブル: デバイスの MGKType に応じて mgkiPhone / mgkiPad / mgkATV
- 暗号化モード: **ECB** (ブロック間の連鎖なし)
- ブロックサイズ: 16 bytes (AES-128)
- ラウンド数: 11 (AES-128 標準)

## 7. 関数アドレスまとめ

| 関数 | アドレス | 説明 |
|------|---------|------|
| `AppleWebCrypto::AppleWebCrypto` | 0x0B018 | MGK 生成を含むコンストラクタ |
| `genModelGroupKeys` | 0x1DB74 | SHA384(ESN) → 3x TFIT-AES → MGK pair |
| `encryptAes128Ecb` | 0x1DDB8 | MGKType 選択 + WB-AES-ECB 1 block |
| `TFIT_wbaes_ecb_encrypt_iAES11` | 0x248C4 | WB-AES ECB エントリ (null check) |
| `TFIT_r9_op_iAES11` | 0x248DC | Round 9 特殊処理 |
| `TFIT_op_iAES11` | 0x25CB0 | 1 ブロック WB-AES 全ラウンド |
| `TFIT_wbaes_ecb_cipher_iAES11` | 0x26C9C | マルチブロック ECB ループ |
