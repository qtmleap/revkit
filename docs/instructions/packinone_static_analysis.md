# PackinOne.dll Static Analysis

Target: `/home/vscode/app/targets/Kanade/plugin/PackinOne.dll`  
Format: PE32 (MSVC x86), 708608 bytes, ImageBase=0x10000000  
Analysis method: static only (lief, capstone, radare2, objdump)

## Section Layout

| Section | RVA       | File Offset | VSize    | RawSize  |
|---------|-----------|-------------|----------|----------|
| .text   | 0x001000  | 0x000400    | 0x72a25  | 0x72c00  |
| .rdata  | 0x074000  | 0x073000    | 0x23484  | 0x23600  |
| .data   | 0x098000  | 0x096600    | 0x0ac98  | 0x007c00 |
| .reloc  | 0x0a3000  | 0x09e200    | -        | -        |

VA-to-file-offset: `file = section.rawOffset + (rva - section.virtualAddress)`

---

## 1. 登録エントリテーブル

プラグインは DllMain から3つのリンクリストを走査してエントリを登録する。  
リストヘッドアドレス: `[0x1009fb20]` (List0), `[0x1009fb24]` (List1), `[0x1009fb28]` (List2)

スタブパターン (x86):

```
A1 [head_va]               ; mov eax, [list_head]
A3 [entry_va+4]            ; mov [entry.next], eax
C7 05 [head_va] [entry_va] ; mov [list_head], entry_ptr
C3                         ; ret
```

### List 0 — ncbCallbackAutoRegister (4 entries)

| stub VA    | entry VA   | vtable VA  | vtable[0] (fn0) | entry[8] callback  | 備考                          |
|-----------|-----------|-----------|-----------------|-------------------|-------------------------------|
| 0x10073310 | 0x1009a3a8 | 0x1007770c | 0x100215d0      | 0x00000000        | 起動時コールバック未設定        |
| 0x100734b0 | 0x1009bba8 | 0x1007770c | 0x100215d0      | 0x00000000        | 起動時コールバック未設定        |
| 0x100734d0 | 0x1009bc88 | 0x1007770c | 0x100215d0      | 0x10032ec0        | XP3 登録+TJS初期化コールバック |
| 0x100734f0 | 0x1009bc50 | 0x1007770c | 0x100215d0      | 0x10040590        | System.commandExecute 登録     |

`ncbCallbackAutoRegister` vtable `0x1007770c`:
- vtable[0] `0x100215d0`: thunk — `mov eax,[ecx+8]; test eax,eax; jmp eax / ret`
- vtable[1] `0x10021e90`: DoRegister thunk
- COL → type `.?AUncbCallbackAutoRegister@@`

**List0[2] callback `0x10032ec0`**: `TVPGetScriptDispatch()` を取得後、TVPFunctionExporter で複数 TJS API を解決し、XP3 ストレージプロバイダ登録 (`fn 0x10031a40` → `TVPRegisterStorageMedia`) を実行する。

**List0[3] callback `0x10040590`**: `tTJSString::tTJSString(const tjs_nchar *)` + `TVPAddImportantLog` を使用して `System_commandExecute` を登録。

### List 1 — ncbNativeClassAutoRegister / ncbAttachTJS2ClassAutoRegister / ncbNativeFunctionAutoRegisterTempl (25 entries)

| stub VA    | entry VA   | vtable VA  | fn0 VA     | 登録内容                                    |
|-----------|-----------|-----------|-----------|---------------------------------------------|
| 0x100732d0 | 0x1009a37c | 0x10077a38 | 0x10021000 | ncbAttachTJS2Class: VStoragesFstat          |
| 0x10073330 | 0x1009a38c | 0x10077dc8 | 0x10021110 | ncbNativeClass: VTemporaryFiles             |
| 0x10073370 | 0x1009bb68 | 0x10079234 | 0x10034a70 | ncbAttachTJS2Class: VArrayAdd               |
| 0x10073390 | 0x1009bb78 | 0x10079278 | 0x10034b80 | ncbAttachTJS2Class: VDictAdd                |
| 0x100733b0 | 0x1009bbd0 | 0x10079d5c | 0x10034810 | ncbAttachTJS2Class: UFontEx                 |
| 0x100733d0 | 0x1009bbb8 | 0x100795bc | 0x10034c90 | ncbAttachTJS2Class: VScriptsAdd             |
| 0x100733f0 | 0x1009bb88 | 0x10079294 | 0x10034da0 | ncbAttachTJS2Class: VScriptsAddForSaveStruct|
| 0x10073410 | 0x1009bc40 | 0x1007a1f4 | 0x10034ee0 | ncbAttachTJS2Class: VlayerExImage           |
| 0x10073430 | 0x1009bc60 | 0x1007a2b0 | 0x10034950 | ncbAttachTJS2Class: UlayerExRaster          |
| 0x10073510 | 0x1009bc20 | 0x1007a084 | 0x10034ff0 | ncbNativeFunction: Layer_clipAlphaRect      |
| 0x10073530 | 0x1009bc18 | 0x1007a050 | 0x10035040 | ncbNativeFunction: Layer_copyAlphaToProvince|
| 0x10073550 | 0x1009bc08 | 0x10079ff0 | 0x10035090 | ncbNativeFunction: Layer_copyBottomBlueToTopAlpha |
| 0x10073570 | 0x1009bc00 | 0x10079fb0 | 0x100350e0 | ncbNativeFunction: Layer_copyRightBlueToLeftAlpha |
| 0x10073590 | 0x1009bc10 | 0x1007a030 | 0x10035130 | ncbNativeFunction: Layer_fillAlpha          |
| 0x100735b0 | 0x1009bc30 | 0x1007a0d4 | 0x10035180 | ncbNativeFunction: Layer_fillByProvince     |
| 0x100735d0 | 0x1009bc38 | 0x1007a100 | 0x100351d0 | ncbNativeFunction: Layer_fillToProvince     |
| 0x100735f0 | 0x1009bc28 | 0x1007a0ac | 0x10035220 | ncbNativeFunction: Layer_overwrapRect       |
| 0x10073610 | 0x1009bbf0 | 0x10079d80 | 0x10035270 | ncbNativeFunction: Layer_shrinkCopy         |
| 0x10073630 | 0x1009bbf8 | 0x10079da4 | 0x100352c0 | ncbNativeFunction: Layer_shrinkCopyFast     |
| 0x10073650 | 0x1009bc70 | 0x1007a7b4 | 0x10035310 | ncbNativeFunction: Plugins_link             |
| 0x10073670 | 0x1009bc78 | 0x1007a7dc | 0x10035360 | ncbNativeFunction: Plugins_unlink           |
| 0x10073690 | 0x1009bbc8 | 0x100797cc | 0x100353b0 | ncbNativeFunction: Scripts_rehash           |
| 0x100736b0 | 0x1009bc80 | 0x1007a7f8 | 0x10035440 | ncbNativeFunction: Storages_setCurrentDirectory |
| 0x10073700 | 0x1009d978 | 0x1007b3d8 | 0x10047960 | ncbNativeFunction: System_commandExecute    |
| 0x10073720 | 0x1009d96c | 0x1007b278 | 0x100478c0 | ncbNativeClass: VProcess                   |

### List 2 — ncbCallbackAutoRegister (5 entries)

| stub VA    | entry VA   | vtable VA  | vtable[0] | entry[8] callback  | 備考                               |
|-----------|-----------|-----------|-----------|-------------------|------------------------------------|
| 0x100732f0 | 0x1009a398 | 0x1007770c | 0x100215d0 | 0x10020bd0        | TVPExecuteExpression でスクリプト実行 |
| 0x10073450 | 0x1009bc98 | 0x1007770c | 0x100215d0 | 0x00000000        | 未設定                              |
| 0x10073470 | 0x1009bbe0 | 0x1007770c | 0x100215d0 | 0x00000000        | 未設定                              |
| 0x10073490 | 0x1009bb98 | 0x1007770c | 0x100215d0 | 0x10033620        | TVPGetScriptDispatch + TJS呼び出し  |
| 0x100736e0 | 0x1009d95c | 0x1007770c | 0x100215d0 | 0x00000000        | 未設定                              |

**List2[0] callback `0x10020bd0`**: `TVPExecuteExpression` と `tTJSString::tTJSString(const tjs_char *)` を使用。TJS スクリプトを実行してプラグイン設定を行う (推定)。

**List2[3] callback `0x10033620`**: `TVPGetScriptDispatch()` + `tTJSVariant::tTJSVariant(tjs_int32)` を使用して TJS ディスパッチ経由で API を呼び出す。

---

## 2. TVPFunctionExporter 参照 (API ルックアップ)

TVPFunctionExporter テーブルは `[0x100a0010]` に格納される。ルックアップ関数は `0x10001b30` (引数: API 文字列 VA → 戻り値: 関数ポインタ)。

主要 API ルックアップ一覧:

| API 文字列 (VA)                                        | 用途                                      |
|------------------------------------------------------|------------------------------------------|
| `tTJSVariant::tTJSVariant()` (0x10098008)            | TJS バリアント初期化                       |
| `tTJSString::tTJSString(const tjs_char *)` (0x100983cc) | ワイド文字列構築                         |
| `tTJSString::tTJSString(const tTJSString &)` (0x10098074) | 文字列コピー                          |
| `tTJSString::~ tTJSString()` (0x100980a0)            | 文字列解放                                |
| `iTJSDispatch2 * ::TVPGetScriptDispatch()` (0x10098a98) | TJS スクリプトディスパッチ取得           |
| `void ::TVPExecuteExpression(...)` (0x1009a8a4)      | TJS 式実行                                |
| `void ::TVPRegisterStorageMedia(iTVPStorageMedia *)` (0x1009c198) | XP3 ストレージプロバイダ登録   |
| `void ::TVPUnregisterStorageMedia(iTVPStorageMedia *)` (0x1009c1cc) | ストレージプロバイダ解除       |
| `IStream * ::TVPCreateIStream(const ttstr &, tjs_uint32)` (0x10099114) | ファイルストリーム開く     |
| `void ::TVPAddImportantLog(const ttstr &)` (0x1009916c) | ログ出力                                |

---

## 3. XP3 アーカイブオープナーフック

### 登録経路

```
List0[2] callback (0x10032ec0)
  -> TVPFunctionExporter lookup: TVPRegisterStorageMedia
  -> fn 0x10031a40   ; alloc 0x14 bytes, call ctor 0x1002c630, call TVPRegisterStorageMedia
     -> ctor 0x1002c630 : ProxyStorage ctor
        sets vtable = 0x1007a5ec
        COL @ 0x10090234 -> TypeDescriptor: .?AVProxyStorage@@
```

### ProxyStorage クラス

- vtable VA: `0x1007a5ec`
- RTTI 型名: `.?AVProxyStorage@@`
- 逆登録関数: `0x10028dd0` (ポインタが `0x1009b908` に格納、TVPUnregisterStorageMedia を呼ぶ)
- vtable[6] `0x10032980`: ストリームオープン (`iTVPStorageMedia::OpenStream` 相当)
  - 内部で `fn 0x10040080` (URL フィルタ) を呼び出して XP3 エントリ番号を解決
  - 次いで `fn 0x10014590` (推定: 暗号ストリームラッパー生成) を呼び出す

---

## 4. 暗号クラス階層 (RTTI 復元)

### RTTI 型名と vtable RVA

| 型名 (TypeDescriptor)                                                                          | vtable VA  | vtable RVA  |
|-----------------------------------------------------------------------------------------------|-----------|-------------|
| `.?AUStreamCryptFilter@@`                                                                      | 不明       | —           |
| `.?AUBufferedStreamCryptFilter@@`                                                              | 不明       | —           |
| `.?AUStreamCryptReaderWriter@@`                                                                | 0x10075590 | 0x00075590  |
| `.?AV?$BasicCryptFilter@U?$BlockStreamCipher@UChaCha@DJBernsteinStreamCipher@@@DJBernsteinStreamCipher@@@@` | 0x10075cb0 | 0x00075cb0 |

### BasicCryptFilter 完全型名

```
BasicCryptFilter<
  BlockStreamCipher<
    ChaCha,
    DJBernsteinStreamCipher
  >,
  DJBernsteinStreamCipher
>
```

RTTI COL (@ `0x1008e4e4`): sig=0, offset=0, pTD=`0x10099e50`, pCH=`0x1008e4f8`  
基底クラス (3): BasicCryptFilter → BufferedStreamCryptFilter → StreamCryptFilter

### vtable 0x10075cb0 エントリ

| idx | VA         | 備考                                 |
|-----|-----------|--------------------------------------|
| [-1]| 0x1008e4e4 | CompleteObjectLocator (COL)          |
| [0] | 0x10016f90 | dtor                                 |
| [1] | 0x100154e0 | Read/Write dispatch                  |
| [2] | 0x1008e3a0 | 埋め込み COL (推定)                  |
| [17]| 0x10015610 | —                                    |
| [18]| 0x10018830 | —                                    |
| [19]| 0x10018830 | —                                    |

---

## 5. ChaCha 暗号パラメータ

### 5-1. Sigma 定数 (expand 32-byte k)

`.rdata` VA `0x10075c54` (file offset `0x00074c54`) に **ビット反転 (NOT)** で格納:

```
Raw:    9a 87 8f 9e  91 9b df cc  cd d2 9d 86  8b 9a df 94
~Raw:   65 78 70 61  6e 64 20 33  32 2d 62 79  74 65 20 6b
ASCII:  e  x  p  a   n  d     3   2  -  b  y   t  e     k
```

= 標準 ChaCha sigma `"expand 32-byte k"`。ChaCha 実装全体でステートワード (sigma, key, nonce) はメモリ上で常に反転して保持される。

### 5-2. 鍵設定関数

`fn 0x10010570` (key setup):

1. `[ebp+0xc]` = key 配列先頭アドレス、`[ebp+0x10]` = nonce 配列先頭アドレス
2. key の各 4 バイトをビッグエンディアンで dword に組み立て `NOT` を適用 → state+0x10..+0x2c (8 dwords = 32 bytes)
3. nonce の各バイトを同様に処理 → state+0x00..+0x0c
4. 追加ワードを state+0x30..+0x3c に格納
5. Sigma 定数 `0x10075c54` を別途 `NOT` して state に展開

ChaCha ブロック関数 `0x10011ed0` は SSE `pandn` (= NOT AND) を用いて state から実際の値を復元し、ROL 16/12/8/7 の標準 ChaCha ダブルラウンドを実行する。

### 5-3. ラウンド数の根拠

ブロック関数のループ変数 `[ebp-0x84] = ceil(nonce_bytes / 2)`:

- 後退ジャンプ: `0x100121c8: jne 0x10011fc0`
- 各ループ反復で QR を 8 回実行 (カラム 4 + 対角 4) = 1 ダブルラウンド = 2 ラウンド
- よってトータルラウンド数 = `loop_iters * 2 = nonce_bytes`

### 5-4. ファクトリ関数とラウンド数の対応

`fn 0x1000eb90` (cipher factory, 唯一の呼び出し元: `0x1000c140`)  
ジャンプテーブル: `0x1000ed3c` (6 エントリ)

| cipher type | nonce_bytes | key_bytes | ラウンド数 | 種別     |
|------------|------------|----------|-----------|---------|
| 1          | 8          | 16       | **8**     | ChaCha8 |
| 2          | 12         | 8        | **12**    | ChaCha12|
| 3          | 20         | 4        | **20**    | ChaCha20|
| 4          | 8          | 1        | **8**     | ChaCha8 (key_bytes=1 → 推定: 1バイトキーの繰り返しまたは別方式) |
| 5          | 12         | 1        | **12**    | ChaCha12 (同上) |
| 6          | 20         | 1        | **20**    | ChaCha20 (同上) |

type 1/2/3 (key_bytes=16/8/4) と type 4/5/6 (key_bytes=1) の 2 グループが存在する。key_bytes=1 の場合の鍵展開方法は **不明** (推定: 1バイトから 32 バイトへの繰り返し埋め、または別の KDF)。

### 5-5. 鍵・Nonce の出処 (完全解析)

#### 経路の分離確認

**2 つの経路は完全に独立している:**

| 経路 | 鍵設定関数 | 起動契機 |
|------|-----------|---------|
| loadDataPack | `fn 0x10010570` ← `fn 0x1000bb80` ← `fn 0x1000eb90` ← `fn 0x1000c100` | TJS `Scripts.loadDataPack()` |
| XP3 openStream | `ProxyStorage::vtable[6]` = `fn 0x10032980` | KANADE.exe が XP3 エントリを開くとき |

**`fn 0x10010570` の唯一の呼び出し元は `fn 0x1000bb80` のみ (xref 1件: `0x1000bd3b`)。**  
`fn 0x10032980` は `fn 0x1000bb80` も `fn 0x10014590` も `fn 0x1000c300` も呼ばない。

---

#### loadDataPack 経路の鍵導出 (完全追跡)

**呼び出し連鎖:**
```
TJS: Scripts.loadDataPack(path)
  -> fn 0x10010a90 (loadDataPack コールバック; 0x1000f124 で登録)
     -> fn 0x1000c300 (StorageReader ctor)
        -> IStream::Read(buf, 0x44)  // ヘッダ 68 バイト読み取り
     -> fn 0x10014590 (stream wrapper factory)
        -> fn 0x1000c570 (config struct 初期化)
        -> fn 0x1001c860 (IStream ヘッダ解析 + 追加バイト読み取り)
           -> IStream::Read([ebp-0x14], 0x10)   // nonce 候補 16 バイト読み取り
           -> IStream::Read([esi+0x14], [esi+0x24])  // key_string バイト読み取り
        -> fn 0x1000c100 -> fn 0x1000eb90(type=1) -> fn 0x1000bb80 (BasicCryptFilter ctor)
```

**fn 0x1001c860 内で IStream からの読み取り確定:**
- `0x1001c978: call [eax+8]` = `IStream::Read([ebp-0x14], 0x10)` → 16 バイト nonce 候補
- `0x1001c9ad: call [eax+8]` = `IStream::Read([esi+0x14], [esi+0x24])` → key_string バイト  
- `[esi+0x24]` = key_string のバイト長 (config から)
- 読んだ key_string は StorageReader の `this+0x28` に格納される

---

#### fn 0x1000bb80 における ChaCha 鍵導出アルゴリズム

`fn 0x1000bb80` (BasicCryptFilter ctor) の鍵導出手順 (命令レベルで確定):

**Step 1: SHA-256 ベース KDF**

```
SHA256_state = [ebp-0xec]
key_string   = arg_14 (StorageReader+0x28 = IStream から読んだバイト列)
key_len      = arg_18 (key_string の長さ)

// 0x1000bc96: mov [ebp-0x70], 0x01010420  (4 バイト整数、LE: 20 04 01 01)
init_block[0..3]  = 0x20040101  // 定数
init_block[4..31] = 0x00 * 28  // ゼロパディング

// 0x1000bc9d: call 0x10017be0(ecx=SHA256_state, arg=[ebp-0x70])
fn 0x10017be0: SHA256_init(state) then XOR state IV with init_block[0..31]
// -> HMAC-SHA256 的な初期化 (初期 IV を定数で XOR してから開始)

// 0x1000bcc8: call 0x1001be20(ecx=SHA256_state, data=key_string, len=key_len)
SHA256_update(state, key_string, key_len)

// 0x1000bd00: call 0x100174f0(ecx=SHA256_state, out=[ebp-0x118], len=0x20)
SHA256_finalize(state) → 32 バイトダイジェスト at [ebp-0x118]
// これが ChaCha KEY (32 バイト)
```

**Step 2: XXH32 ハッシュ (extra フィールド用)**

```
// 0x1000bd16: call 0x10009700(data=key_string_ptr, len=key_len, seed=cipher_type)
fn 0x10009700: XXH32(key_string, key_len, seed=cipher_type=1)
// 返値 eax = 32-bit hash = extra_lo フィールド
```

**Step 3: ChaCha state 初期化呼び出し**

```
// 0x1000bd3b: call 0x10010570 の引数 (push 順):
push ebx+0x2c         // state_ptr  (arg+0x08)
push [ebp-0x118]      // key_ptr    (arg+0x0c) = SHA256(key_string) の 32 バイト
push 0x10075c54       // nonce_ptr  (arg+0x10) = sigma 定数 "~(expand 32-byte k)"
push xxh32_result     // extra_lo   (arg+0x14) = XXH32(key_string, cipher_type)
push 0                // extra_hi   (arg+0x18)
push 0                // extra_a    (arg+0x1c)
push cipher_type(=1)  // extra_b    (arg+0x20)
```

**nonce_ptr = `0x10075c54`** (sigma 定数の NOT 格納アドレス = `~"expand 32-byte k"`)  
つまり **nonce は ChaCha sigma 定数で固定** (全 type 共通)。

---

#### fn 0x10010570 引数マッピング (確定版)

```
fn 0x10010570(state_ptr, key_ptr, nonce_ptr, extra_lo, extra_hi, extra_a, extra_b):
  [ebp+0x08] = state base ptr
  [ebp+0x0c] = key_ptr → SHA256(key_string) 32 バイト
  [ebp+0x10] = nonce_ptr = 0x10075c54 (sigma 定数 NOT 格納)
  [ebp+0x14] = extra_lo = XXH32(key_string, cipher_type)  → ~extra_lo → state+0x38
  [ebp+0x18] = extra_hi = 0                               → ~0        → state+0x3c
  [ebp+0x1c] = extra_a  = 0                               → ~0        → state+0x30
  [ebp+0x20] = extra_b  = cipher_type (=1)                → ~1        → state+0x34

  key 32 バイト → state+0x10..0x2c (各 4 バイト LE→BE + NOT)
  nonce 16 バイト → state+0x00..0x0c (NOT なし)
```

---

#### XP3 openStream 経路 (fn 0x10032980) の鍵供給

`fn 0x10032980` は `fn 0x10010570`/`fn 0x1000bb80` を**一切呼ばない**。  
鍵は TJS Dispatch オブジェクト経由で供給される:

```
fn 0x10032980 (ProxyStorage::OpenStream):
  1. fn 0x10040080: URL → ProxyStorage[+4] dispatch に FuncCall(filepath) → TJSVariant result
  2. VariantType 分岐:
     - Type 1 (Object):  fn 0x1002dea0 -> fn 0x1002b370 でストリームラップ
                         -> fn 0x10030860: QueryInterface('HSmM') at vtable+0x64
                            ProxyStorage vtable[25] = fn 0x1002e780 が担当
                         -> fn 0x100443a0: cipher attach (ecx+0x0c が cipher ptr)
     - Type 2 (String):  TVPCreateIStream -> QueryInterface('HSmM') on engine stream
                         engine (KANADE.exe) 側が鍵を供給 — PackinOne は関与しない
     - Type 3 (Octet):   fn 0x1003bfa0 -> fn 0x10044460 -> fn 0x10043c40
                         ProxyStorage dispatch FuncCall でパラメータ取得
  3. fn 0x1003bfa0 -> fn 0x100443a0 -> vtable+0x0c に cipher ptr がセットされる
```

**XP3 経路の鍵素材は TJS スクリプトが `Plugins.PackinOneList` グローバルオブジェクトに  
事前に設定した dispatch 関数から得られる。** PackinOne.dll のバイナリに鍵定数はない。

`TVPRegisterGlobalObject("PackinOneList", ...)` (`fn 0x10032ec0`、`0x100330c5`) で  
TJS グローバル `Plugins.PackinOneList` に ProxyStorage インスタンスが登録される。

---

#### 鍵素材の出処まとめ

| 経路 | key 素材 | nonce | cipher_type | KDF |
|------|----------|-------|-------------|-----|
| loadDataPack | IStream から読んだ可変長バイト列 (`StorageReader+0x28`) | `0x10075c54` = sigma定数固定 | 1 (ハードコード) | HMAC-SHA256(constant, key_string) + state extra にXXH32 |
| XP3 openStream (Type 1/3) | TJS Dispatch FuncCall の返値 (スクリプト制御) | スクリプト制御 | スクリプト制御 | スクリプト側で完結 |
| XP3 openStream (Type 2) | KANADE.exe engine 側 | engine 側 | engine 側 | 不明 (engine 内部) |

**結論: 3 XP3 (data/patch/steam) が異なる keystream を使うのは、各 XP3 エントリに対応する  
TJS Dispatch FuncCall が返すオブジェクト (key material) がアーカイブ別に異なるためと推定。  
PackinOne.dll 内に XP3 名から鍵を派生させるコードは存在しない — 鍵はすべてスクリプト側から注入される。**

---

#### Q1. 何のファイルから 0x44 バイトを読んでいるか

`fn 0x1000c300` は **TJS スクリプトから `Scripts.loadDataPack(path, ...)` を呼んだとき**に起動するコールバック (`fn 0x10010a90`) 経由で呼ばれる。

ファイルパスは TJS バリアント (実行時スクリプト変数) からの文字列であり、バイナリに定数として埋め込まれていない。ゲーム固有の TJS スクリプト (startup.tjs / config.tjs 等) で決まる。

#### Q2. 0x44 バイトのヘッダレイアウト (部分確定)

| header offset | サイズ | StorageReader フィールド | 用途 |
|--------------|--------|------------------------|------|
| 0x00..0x03   | 4      | `this+0x10` | fn 0x1000c100 → key/nonce 選択 |
| 0x04..0x07   | 4      | `this+0x14` | 詳細不明 |
| 0x08..0x3f   | 56     | 不使用 (fn 0x1000c300 内では未代入) | 不明 |

`this+0x08` (cipher_type) は `0x1000c33a: mov byte [esi+8], 1` でハードコード=1 に固定。

#### Q3. cipher_type (1-6) の出処

loadDataPack 経路: `fn 0x100145e8: push 1` でハードコード type=1 (ChaCha8, nonce=8 bytes)。  
XP3 openStream 経路: TJS スクリプト制御。静的解析では確定不能。

### 5-6. 暗号ストリームラッパー

```
fn 0x10014590 (stream wrapper factory; loadDataPack 経路):
  arg1 = IStream ptr
  arg2 = config struct ptr (edi)
    edi+0x08 = cipher type (常に 1)
    edi+0x0c = nonce ptr
    edi+0x10 or edi+0x28 = key area (選択は edi+0x38 > 0 か否か)
  1. fn 0x1000c570 で config struct を初期化
  2. fn 0x1001c860 で ストリーム方向 (read "TJS/" / write "TJS\") とチェックを実施
  3. fn 0x1000c100 で BasicCryptFilter を生成
     -> factory fn 0x1000eb90 を type=1 (ハードコード) で呼び出し
     -> StreamCryptReaderWriter (vtable 0x10075590) でラップして返す
```

XP3 openStream 経路 (`ProxyStorage::vtable[6]` = `fn 0x10032980`):
```
fn 0x10032980 (ProxyStorage::OpenStream):
  1. fn 0x10040080 で URL フィルタ / XP3 エントリ解決
  2. TJS バリアント型でブランチ:
     - type=0 (TJSVariantType_Object): fn 0x1002dea0 経由 → fn 0x1002b370
     - type=1 (TJSVariantType_String): TVPCreateIStream でファイルオープン
     - type=2 (TJSVariantType_Octet):  fn 0x1003bfa0 → fn 0x10044460 (GlobalAlloc)
  3. fn 0x10030860 (QueryInterface 'HSmM') で暗号 extension を問い合わせ
  4. fn 0x10043c40 で dispatch vtable[6] 呼び出し → ストリーム付与
```

`fn 0x1002b370/0x1002b430`: 0x20/0x30 バイト struct を alloc し vtable (0x1007a774 / 0x1007a6fc) をセット。  
内部で `fn 0x10041940` (TJSVariantOctet からデータポインタ/長さ取得) と `fn 0x10041aa0` (TJS dict から "file"/"offset"/"size" キーを取得してストリーム組み立て) を呼ぶ。

#### Q4. LZ4 と ChaCha の呼び出し順序

`fn 0x10041aa0` のフローから:
1. `fn 0x100419d0`: ファイル名文字列で `TVPCreateIStream` を呼んで raw IStream を開く
2. `fn 0x10042c60`: IStream を offset に seek
3. `fn 0x100408f0`: size を設定 (range-limit ラッパー)
4. `fn 0x10030860` / `fn 0x10043c40`: 暗号ストリームをラップ (ChaCha)
5. LZ4DecompressStream (vtable `0x10099e0c`) は別経路

LZ4DecompressStream の vtable 参照は `.rdata` の COL `0x1008e048` / `0x1008e074` にのみ存在し、XP3 openStream の直接経路では呼ばれていない。LZ4 解凍は **ChaCha 復号の後に** 別レイヤーで行われると推定されるが、静的解析でその具体的な呼び出し位置は未確認。

#### Q5. Hxv4 blob の flag (2 bytes) の意味

TLG 画像フォーマットのエラーメッセージ `"Data flag must be 0 (any flags are not yet supported)"` (VA `0x1007d7f2`) はあるが、これは TLG ピクセルフォーマットのフラグであり Hxv4 index の flag フィールドとは別物。

Hxv4 blob (14 byte: offset[8] + size[4] + flag[2]) の flag フィールドが使われているコードを静的に特定できなかった。バイナリ内に "flag" テーブルキーや flag 分岐の有力な候補が見当たらない。

推定: Hxv4 index は PackinOne 側ではなく KirikiriZ エンジン本体 (KANADE.exe) で解析されている可能性が高く、PackinOne.dll の静的解析では flag の意味は**不明**。

---

## 6. XP3 に使用される cipher type の特定

cipher type は `fn 0x1000c300` 内のハードコード `mov byte [esi+8], 1` によって **常に 1 (ChaCha8, nonce=8 bytes, key=16 bytes)** に固定されている。

header (`0x44` バイト) の `[4..7]` フィールドが `this+0x10` に格納されるが、これは cipher type ではなく key selection フラグまたは key 素材の一部と推定される。

- `data.xp3` (226269 bytes)、`patch.xp3` (11240 bytes)、`steam.xp3` (198 bytes) が対象アーカイブとして存在することは確認済み。
- cipher type は設定ファイルのヘッダから取得されることはなく、type 4/5/6 (ChaCha12/20, key_bytes=1 グループ) が XP3 読み取りに使われることは静的解析では確認されていない。

---

## 7. その他の暗号関連実装

| 関数 VA    | 型 / 役割                            |
|-----------|--------------------------------------|
| 0x10017a40 | SHA-256 (IV 定数 0x6a09e667 確認済み) |
| 0x1009a0ac | `.?AUXXH32Hasher@@` (XXH32 ハッシャ)  |
| 0x1009a0c8 | `.?AUBlake2sHasher@@` (Blake2s ハッシャ) |
| 0x1009a090 | `.?AUVariantHasher@@`                |
| 0x10099df0 | `.?AVLZ4StreamBase@@` (LZ4 圧縮)     |
| 0x10099e0c | `.?AVLZ4DecompressStream@@`          |

---

## 8. TJS メソッド登録 (makeDataPackDigest 等)

`fn 0x1000ee30` が以下の TJS メソッドを登録する:

| type | fn VA      | TJS メソッド名        |
|------|-----------|----------------------|
| 1    | 0x100110d0 | makeDataPackDigest   |
| 3    | 0x10012220 | makeDataPackThumb    |
| 7    | 0x10010a90 | saveDataPack         |
| 0xf  | (不明)     | loadDataPack         |

TJS スクリプト側からの登録確認 (`fn 0x1000ee30` の呼び出し元 `0x1000f110` 周辺):

| 登録 VA    | コールバック fn VA | TJS メソッド / スコープ |
|------------|------------------|----------------------|
| 0x1000f124 | 0x10010a90       | `Scripts.loadDataPack` (index=7) |
| 0x1000f32d | 0x10010eb0       | `Scripts.loadOctet` (index=0x11) |

`fn 0x10010a90` が `fn 0x1000c300` を呼ぶ経路:  
`Scripts.loadDataPack(path)` → `fn 0x10010a90` → `fn 0x1000c300(StorageReader, ttstr_from_variant, flag=1)`

---

## 9. 不明・推定の整理

| 項目                                       | 状態   | 理由・根拠                                                                        |
|-------------------------------------------|--------|-----------------------------------------------------------------------------------|
| Q1: 読み込むファイルパス                    | 不確定 | TJS `Scripts.loadDataPack(path)` の path は実行時スクリプト変数。バイナリに定数なし |
| Q2: 0x44 ヘッダの全フィールドレイアウト     | 部分確定 | [0..3]→this+0x10, [4..7]→this+0x14 のみ追跡。[0x08..0x43] の用途は未確認        |
| Q3: cipher_type の出処                     | 確定   | `mov byte [esi+8], 1` でハードコード type=1。header からは読まれない              |
| Q4: LZ4 と ChaCha の順序                   | 推定   | ChaCha 後に LZ4 と推定。LZ4DecompressStream のコール経路が XP3 openStream 上で未特定 |
| Q5: Hxv4 flag (2 bytes) の意味             | 不明   | PackinOne.dll 内で flag 値を参照する分岐コードが静的に特定できず。エンジン本体依存の可能性 |
| key_bytes=1 の場合の鍵展開方式             | 不明   | type 4/5/6 の内部実装を詳細追跡していない                                         |
| BasicCryptFilter vtable[2..16] の意味     | 推定   | vtable[2]=0x1008e3a0 は埋め込み COL と推定、詳細未確認                           |
| key_bytes=4 (type=3, ChaCha20) の意味     | 推定   | 4バイト鍵の用途は不明。XOR マスクや IV のみとして使う可能性あり                  |
