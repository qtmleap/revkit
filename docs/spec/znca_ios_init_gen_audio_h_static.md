# znca (Nintendo Switch Online) iOS 3.4.1 — `+[VoIPClient initGenAudioH]` 静的解析

対象: `/home/vscode/app/targets/znca_ios_3.4.1/Crew`
Mach-O arm64, `__TEXT` vmaddr = `0x100000000`。ASLR 補正不要のイメージベース相対で全アドレス報告する。

補助スクリプトは `/tmp/parse_voipclient.py`, `/tmp/scan_func.py`, `/tmp/categorize_refs.py`, `/tmp/check_antidbg.py`, `/tmp/check_svc.py`, `/tmp/find_bl.py`, `/tmp/find_bls_to_local.py`, `/tmp/adrp_scan.py` に格納。
生成物のうち `parse_voipclient.py` のみリポジトリに `targets/znca_ios_3.4.1/analysis/parse_voipclient.py` として残す。

## 訂正履歴

本ドキュメント初出後、以下 3 本の後続解析ドキュメントにより一部の結論が覆された/精密化された。
該当箇所には「(訂正: 2026-07-03、詳細は ...)」の脚注を付けてある。

- [`znca_ios_whitebox_layout.md`](./znca_ios_whitebox_layout.md) — whitebox テーブル領域の内部レイアウト深堀り (pure-table 82.6% / CFF-plumbing 17.4% 分離、chained-fixups 解析)
- [`znca_ios_init_gen_audio_h_cff.md`](./znca_ios_init_gen_audio_h_cff.md) — initGenAudioH 本体の CFF de-flatten (真の state slot 特定、CFF の 99.7% が opaque predicate/no-op と判明)
- [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) — アンチデバッグ文字列/定数の精密化 (sysctl 10 回・getpid 4 回・kill sig=0 の確定)

---

## 1. `+[VoIPClient initGenAudioH]` 実装アドレス

`__DATA_CONST.__objc_classlist` から `VoIPClient` メタクラスを resolve し、`class_ro_t.baseMethods`(relative method list形式) をパースした結果。

- `VoIPClient` class object VA: `0x100f3e468`
- `VoIPClient` metaclass VA: `0x100f3e418`
- metaclass `data` VA (class_ro_t): `0x100f0a8e8`
- metaclass `baseMethods` VA: `0x100c5c0e8` (relative_method_list_t, entsize=0xc, count=8)

メタクラス (`+`) メソッド一覧：

| Idx | Selector | IMP | Types |
|---|---|---|---|
| 0 | `srtpInit` | `0x1006f444c` | `v16@0:8` |
| 1 | `ignoreSigPipe` | `0x100a2a8f8` | `v16@0:8` |
| 2 | `srtpShutdown` | `0x100775f7c` | `v16@0:8` |
| 3 | **`initGenAudioH`** | **`0x100a29528`** | `v16@0:8` |
| 4 | `genAudioH:i2:i3:` | `0x10072b634` | `@40@0:8@16@24@32` |
| 5 | `genAudioH2:i2:i3:` | `0x100708a3c` | `@40@0:8@16@24@32` |
| 6 | `encryptRequest:appVersion:url:accessToken:` | `0x10072cc00` | ... |
| 7 | `decryptResponse:` | `0x1007da0b4` | ... |

したがって **`+[VoIPClient initGenAudioH]` の実 IMP は VA `0x100a29528` (RVA `0xa29528`)**。
サイズは `LC_FUNCTION_STARTS` から `0x7c` バイトのごく小さなラッパー。

### ラッパー→本体の関係

`0x100a29528` のディスアセンブリ:

```
0x100a29528: sub  sp, sp, #0x20
0x100a2952c: stp  x29, x30, [sp,#0x10]
0x100a29530: add  x29, sp, #0x10
0x100a29534: str  xzr, [sp,#8]          ; state = 0
0x100a29538: ldr  x11, [sp,#8]          ; --- CFF ディスパッチ開始 ---
0x100a2953c: adr  x8, 0x100a29560       ; state table base
0x100a29540: ldrsw x9, [x8]
0x100a29544: add  x8, x9, x8
0x100a29548: and  x9, x8, x11
0x100a2954c: movz x10, #2
0x100a29550: mul  x9, x9, x10
0x100a29554: eor  x8, x8, x11
0x100a29558: add  x8, x8, x9
0x100a2955c: br   x8
0x100a29560: .word 4                    ; state=0 → next dispatch
0x100a29564: movz w8, #3
0x100a29568: str  w8, [sp]
0x100a2956c: b    0x100a29588
...
0x100a2957c: bl   0x100783fc8            ; ← 本体呼び出し
0x100a29580: movz w8, #4
0x100a29584: str  w8, [sp]
```

つまり `+[VoIPClient initGenAudioH]` は control-flow flattening 化された 3 状態の tiny スタブで、
中身は **`sym.func.100783fc8` (LC_FUNCTION_STARTS 上 `0x100783fc8` .. `0x1007d594c`、サイズ `0x51984` = 約 335 KiB)** に丸ごと入っている。

- `bl 0x100783fc8` の唯一のコールサイトは `0x100a2957c` (バイナリ全域から検索済み) → **`0x100783fc8` は事実上 `initGenAudioH` の本体そのもの**。

以降「initGenAudioH 本体」は `0x100783fc8` を指す。

---

## 2. 本体関数 `0x100783fc8` の逆コンパイル所見

### 構造

- 単一の巨大 basic block (radare2 の初期解析では `num-bbs: 1`)。プロローグ 1 発、エピローグ 1 発 (`ldp x29,x30,[sp,#0x50]; add sp,sp,#0x2270; ret`)。
- スタックフレーム約 **90 KiB** (`sub sp, sp, #0x16, lsl 12; sub sp, sp, #0x7f0` = 0x167f0 バイト)、実行時ワーキングエリアはこのフレーム内。
- OLLVM 系 control-flow flattening + opaque predicate + 隣接コード生成 (`adr x9, next_bb; sub/add x9,x9,x11` パターン) の重ね掛け。
- ディスパッチ変数は **`__DATA.__data:0x101034204` (int32)** に格納 (関数内の `adrp+add` 出現 628 回、その大半がこの state 変数の read/write)。初期値 `0xffffffff`。
  **(訂正: 2026-07-03、詳細は [`znca_ios_init_gen_audio_h_cff.md`](./znca_ios_init_gen_audio_h_cff.md) §1)**: `0x101034204` は CFF dispatch 変数ではなく **write-only の囮シンク (629 writes / 0 reads)** だった。真の CFF state は関数プロローグで確保された **693 個の private stack slot** であり、9 個のゾーンベースレジスタ (`x8`/`x12`/`x13`/`x14`/`x15`/`x19`/`x20`/`x22`/`x25`/`x26`/`x28`、実測では 11 種) 経由でアクセスされる。1 サイト 1 専用スロットに近く、少数の共有 state 変数という前提は成立しない。
- 内部の疑似 basic block 境界を跨いだレジスタ流れは、CFF のため線形トレースでは追えない (パラメータ復元は諦めた)。

### 呼び出し対象

| 種類 | 目的の代表例 |
|---|---|
| Import stub (`__TEXT.__stubs`) | libc/libSystem/libdyld 38 種、計 215 回 |
| 内部関数 BL | 13 個の内部関数 |
| BLR (`br` によるテーブルディスパッチ) | 16 箇所 |
| SVC #0x80 (raw syscall) | 35 箇所 |
| BRK | 2 箇所 (`0x1007d98b0`, `0x1007d9a68`) |

### インポート経由の呼び出し (`__TEXT.__stubs` 分解)

| ストブ VA | シンボル | 本体からのコール回数 |
|---|---|---|
| `0x100c32fe8` | `CFCopyHomeDirectoryURL` | 2 |
| `0x100c33084` | `CFRelease` | 4 |
| `0x100c330a8` | `CFStringGetCString` | 2 |
| `0x100c330b4` | `CFURLCopyFileSystemPath` | 2 |
| `0x100c33648` | `_Unwind_Resume` | 1 |
| `0x100c3390c` | `std::__1::recursive_mutex::lock` | 6 |
| `0x100c33918` | `std::__1::recursive_mutex::unlock` | 12 |
| `0x100c3396c` | `std::__1::mutex::lock` | 19 |
| `0x100c33978` | `std::__1::mutex::unlock` | 36 |
| `0x100c33ad4` | `operator delete(void*)` | 8 |
| `0x100c33af8` | `operator new[](size_t)` | 2 |
| `0x100c33b04` | `operator new(size_t)` | 8 |
| `0x100c33bc4` | `__error` (errno) | 41 |
| `0x100c33c24` | `__snprintf_chk` | 3 |
| `0x100c33c30` | `__stack_chk_fail` | 1 |
| `0x100c33c60` | `_dyld_get_image_header` | 2 |
| `0x100c33c6c` | `_dyld_get_image_name` | 3 |
| `0x100c33c78` | `_dyld_get_image_vmaddr_slide` | 2 |
| `0x100c33c84` | `_dyld_image_count` | 2 |
| `0x100c33e04` | `clock_gettime` | 2 |
| `0x100c33e1c` | `closedir` | 1 |
| `0x100c33ff0` | `dladdr` | 1 |
| `0x100c33ffc` | `dlclose` | 1 |
| `0x100c34008` | `dlopen` | 1 |
| `0x100c34014` | `dlsym` | 1 |
| `0x100c34110` | `getenv` | 1 |
| `0x100c3426c` | `malloc` | 3 |
| `0x100c342b4` | `memset` | 4 |
| `0x100c343f8` | `objc_getClass` | 6 |
| `0x100c34434` | `objc_msgSend` | 12 |
| `0x100c346d4` | `opendir` | 1 |
| `0x100c347d0` | `pthread_create` | 1 |
| `0x100c3480c` | `pthread_join` | 1 |
| `0x100c34920` | `rand` | 4 |
| `0x100c34944` | `readdir` | 1 |
| `0x100c34980` | `sel_registerName` | 16 |
| `0x100c34b84` | `sranddev` | 1 |
| `0x100c353dc` | `uuid_generate` | 1 |

読み解けるふるまい:

- **`opendir` + `readdir` + `closedir`** … ファイルシステムを列挙。jailbreak 検出用のディレクトリ walk (Cydia/Sileo/frida-server 等の探索) と推定される。文字列は文字化けせず存在するが、`__cstring` セクションからは "frida"/"cydia"/"substrate" 系リテラルは見つからなかった (難読化/XOR 済みの可能性が高い。ステート機に混ぜて decode 後に比較していると思われる)。
- **`_dyld_image_count` + `_dyld_get_image_name` + `_dyld_get_image_header` + `_dyld_get_image_vmaddr_slide` + `dladdr`** … 読み込み中の image を全部舐めているので、注入 dylib (frida-agent, substrate) の検出目的とみて確度高。
- **`dlopen` + `dlsym` + `getenv`** … 環境変数を見て特定関数を dynamic resolve。`DYLD_INSERT_LIBRARIES` チェックの可能性が高い (直接 `getenv("DYLD_INSERT_LIBRARIES")` かどうかは第一引数の string リテラルが CFF に埋もれて linear tracker では拾えなかった。**未確定**)。
- **`pthread_create` (1回) + `pthread_join` (1回)** … 別スレッドで長時間タスク (whitebox テーブル展開/検証) を回している。thread_start は CFF に埋もれた `x2` セットアップに依存しており線形解析では復元できず。
- **`sranddev` + `rand ×4`** … 実行時ランダム化。エントロピーとしてホワイトボックス状態のブラインディング/デコイに使っている可能性がある。
- **`uuid_generate`** … デバイス識別 or セッション salt 用の乱数 UUID。
- **`objc_getClass` ×6, `objc_msgSend` ×12, `sel_registerName` ×16** … CFCLassRef 経由で `NSFileManager` / `NSString` / `NSProcessInfo` 系のクラスをランタイム解決している気配 (直接名は CFF 内で難読化されており未特定)。
- **`clock_gettime` ×2** … 時間ベースの anti-debug (frida hook で BL が遅くなる差分で検出する典型パターン)。
- **std::mutex / recursive_mutex を大量使用** … 実装は C++ で、内部ステート machine を mutex で守っている。共通する mutex は 4〜5 個。

### 生 SVC 呼び出し (35 箇所)

各 SVC 直前の `movz w16, #imm` から特定した syscall 番号。

| syscall | 名前 | 回数 | 代表位置 |
|---|---|---|---|
| 4 | `write` | 5 | `0x1007a26d0` … |
| 5 | `open` | 1 | `0x1007a20b8` |
| 6 | `close` | 1 | `0x1007a4a68` |
| 10 | `unlink` | 7 | `0x10079fb40` … |
| 33 | `access` | 3 | `0x10079fd38` / `0x1007a5f0c` / `0x1007ab8b8` |
| 37 | **`kill`** | 3 | `0x1007c9b14` / `0x1007cc560` / `0x1007cdd44` |
| 57 | `symlink` | 2 | `0x10079eb20` / `0x1007ae4e0` |
| 202 | **`__sysctl`** | 12 | `0x1007c499c` / `0x1007ca000` / … |
| 不明 | (movz 検出できず) | 4 | `0x1007c4824`, `0x1007c9a74`, `0x1007ccf64`, `0x1007cdce4` |

**(訂正: 2026-07-03、詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §2 §8)**: `__sysctl` は **12 回ではなく 10 回**。「movz 検出できず」としていた 4 箇所 (`0x1007c4824`, `0x1007c9a74`, `0x1007ccf64`, `0x1007cdce4`) は `mov w8,#0x14 → mov w16,w8` というレジスタ間接で x16 をセットしていたため静的スキャンで拾えなかっただけで、実体は **raw `getpid()` (SVC 20)** だった。sysctl 10 回の MIB は全て `{CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1, pid}` で、9/10 サイトで動的エミュレーションにより実測確認済み (P_TRACED 検出パターン)。

`__sysctl` × 10 と `kill` × 3 の同居は、明白な **anti-debug** の指紋。libc の `sysctl()` を通さず `svc #0x80` 直呼び出しにしているのは、Frida/Substrate がラッパー関数を hook しても bypass できるようにするための古典的テクニック。ただし `kill` については **self-kill 実装ではないと判明した** (詳細は §4-2 の訂正脚注参照)。

### 内部関数 BL

`0x100783fc8` の中で BL される内部関数 (import stub でない BL) は 13 種。

| 呼び先 | サイズ | 呼び出し回数 | 備考 |
|---|---|---|---|
| `0x1007df904` | `0xb8` | 19 | mutex ペア + `[x19+0x18]` の 2bit フィールド操作 → 小さな **thread-safe counter/flag getter** |
| `0x100a3325c` | `0x38` | 17 | 単なる `b 0x1007794d4` (テールコール via CFF) — 実質 `0x1007794d4` のラッパー |
| `0x1007d594c` | `0x454` | 5 | `malloc` を使って `0x1013d5*` 領域 (`__DATA.__common`) にオブジェクトを詰めるコンストラクタ様。ここが唯一 initGenAudioH 本体の"直後"に位置する compound-init |
| `0x10076fe7c` | `0x620` | 4 | 内部で `0x1007d594c` を呼び出す。dispatch/factory 系 |
| `0x100763280` | `0x16c` | 2 | 未解析 |
| `0x1007773d4` | `0x2a0` | 2 | 未解析 |
| `0x1006f65a8` | `0x170` | 2 | 未解析 |
| `0x100775838` | `0x60` | 2 | 未解析 |
| `0x100a2a0fc` | `0x1c0` | 1 | 未解析 |
| `0x100a3ad40` | `0x114` | 1 | 未解析 |
| `0x100768eec` | `0x1660` | 1 | 大型ユーティリティ |
| `0x1007794d4` | `0x21c` | 1 | 未解析 |
| `0x1006edadc` | `0x50` | 1 | 未解析 |

`_gen_audio_h` / `_gen_audio_h2` / `_set_platform_for_gen_audio` は **initGenAudioH 本体からは直接呼ばれない**。initGenAudioH は「ホワイトボックスの状態を `__DATA.__data` に構築」するだけで、実際の音声偽装処理はランタイムに `+[VoIPClient genAudioH:...]` から呼ばれる。

---

## 3. rodata 読み出しマッピング (全 data references)

`0x100783fc8` .. `0x1007d594c` の範囲を capstone で線形走査し、ADRP+ADD/LDR ペアを追跡した結果 (`/tmp/categorize_refs.py` の出力)。

- 総 distinct target: **309 種**
- 総 data reference 命令: **1591 回**

セクション別内訳：

| セクション | distinct targets | refs | コメント |
|---|---|---|---|
| `__TEXT.__text` | 1 | 1 | `0x100a41001` — スタブ or CFF opaque address |
| `__DATA_CONST.__got` | 2 | 3 | `0x100e57350` (`objc_alloc` reloc), `0x100e575a0` |
| `__DATA_CONST.__const` | 1 | 2 | `0x100eb39e8` |
| **`__DATA.__data`** | **265** | **1376** | ホワイトボックスワーキング領域書き込みと state machine |
| `__DATA.__bss` | 29 | 128 | 内部フラグ・カウンター群 (`0x1013cfb84`..`0x1013cfd00` 付近に密集) |
| `__DATA.__common` | 11 | 81 | `0x1013d5d28`..`0x1013d5dd8` 付近の C++ オブジェクトスロット |

- **`__DATA_CONST` はほぼ触っていない (計 5 refs のみ)**。これは重要:「ソース側のホワイトボックステーブルは静的にリンクされていない」ことを示唆する。テーブル本体は `__DATA.__data` 内に平文で置いてあり、`initGenAudioH` は変換/コピー/展開ではなくむしろ **ステートマシン初期化＋一部フィールドのシードのみ** を行う (詳細は後述)。
- ホットな target 上位 15 (すべて `__DATA.__data`):
  - `0x101034204` (628x) … **CFF ディスパッチ用 state 変数** (int32、初期値 `0xffffffff`)。ホワイトボックス表ではない。
  - `0x10113a520` (108x) … 未確認
  - `0x10103d998` (24x) / `0x10103f9e0` (20x) / `0x101084300` (16x) / `0x10110e020` (16x) … CFF state 変数の亜種と思われる (それぞれ別の疑似関数のディスパッチキー)。
  - `0x10113a408` (12x), `0x10110f1f0` (12x), `0x1010426e0` (12x), `0x10111c630` (12x), `0x101041cd0` (12x), `0x10103faa8` (12x) … 同上

  **(訂正: 2026-07-03)**: 上記の解釈は誤り。`0x101034204` は CFF dispatch 変数ではなく write-only decoy sink (詳細は §2 の脚注、出典 [`znca_ios_init_gen_audio_h_cff.md`](./znca_ios_init_gen_audio_h_cff.md))。それ以外の 11 個のホットアドレスも「CFF state 変数の亜種」ではなく、[`znca_ios_whitebox_layout.md`](./znca_ios_whitebox_layout.md) §2.3 の LIEF chained-fixups 解析により **rebase 済みポインタスロット (11/12 が一致)** と判明した。OLLVM CFF の一部実装は次の基本ブロックのアドレスを整数キーではなく「rebase 済みポインタ変数」として保持し `br xN` で直接ジャンプするため、PIE バイナリではロード時に Mach-O ローダの chained-fixups の対象になる。これが `__DATA.__data` の同一 VA レンジに暗号定数テーブルと CFF 用間接分岐ポインタが混在していた理由。
- `__DATA.__bss` トップ:
  - `0x1013cfcac`, `0x1011cdc74`, `0x1013cfce0`, `0x1011cdc80` (それぞれ 6 refs)。これは "初期化フラグ" のセットで、`+[VoIPClient initGenAudioH]` が `dispatch_once` 相当を hand-rolled で実装している気配。
- `__DATA.__common`:
  - `0x1013d5da8`, `0x1013d5dc0`, `0x1013d5db8`, `0x1013d5d28` (それぞれ 11 refs)。`0x1013d5*` 領域には C++ オブジェクトスロットが `malloc(8)` で 4 つ確保される (`0x1007d594c` 内で観測)。

### なぜ `__DATA_CONST.__const` は空か

`initGenAudioH` が読み込むホワイトボックスの巨大定数を静的解析で先に押さえるため、`__DATA` セグメント全体を 64 KiB 窓 shannon エントロピーで走査した:

```
0x100f42000: 1.86        <- __DATA.__data head (低エントロピー: ポインタ表)
0x100f52000: 2.05
0x100f62000: 5.40         <- 中エントロピー (混合)
0x100f72000: 7.89         <- 高エントロピー開始 (乱数/暗号)
0x100f82000..0x101182000: 7.85 .. 8.00  <- 一貫して高エントロピー
0x101192000: 4.81         <- 低エントロピー (bss 直前 / 平文構造体)
```

- **高エントロピーの塊は `~0x100f70000`〜`~0x101190000`、実サイズ約 `0x220000` バイト ≒ 2.13 MiB**。
- ここは Mach-O の `__DATA.__data` にべた書きされた **静的ホワイトボックステーブル群** で、`initGenAudioH` が「ロードする」対象ではなく、**ロードするまでもなく既にプロセスの virtual address に mapped 済み** (Mach-O ローダが実施)。
- したがって「`initGenAudioH` が rodata から key/table を dump する」のではなく、`initGenAudioH` の役割は **(a) anti-debug チェック → 通れば (b) スレッド起動と mutex 系の初期化 → (c) 一部 seed 値の rand / uuid_generate 埋め込み** に近い。

### ホワイトボックステーブル領域の詳細

64 KiB 窓走査結果:

| VA 範囲 | 概念 |
|---|---|
| `0x100f42000` .. `0x100f52000` | ポインタ表 / vtable (低エントロピー) |
| `0x100f62000` .. `0x100f72000` | 遷移領域 (中エントロピー、C 構造体らしい) |
| **`0x100f70000` .. `0x101192000`** | **ホワイトボックス T-box / S-box 群 (エントロピー 7.85〜8.00)** |
| `0x101192000` .. `0x101197c40` | 遷移 (エントロピー 4.81) |

2.13 MiB 弱の高エントロピー = 典型的な TFIT/Chow スタイル AES ホワイトボックスの規模感 (ラウンド × ステート × テーブル数 で ~1〜2 MB は妥当)。

- 内部に **256 バイトの AES SBox** が置かれているか、簡易走査:
  - SBox の先頭 4 バイトは `63 7c 77 7b` (AES SBox)。バイナリ全体を検索した結果、この完全パターンは見つからず → `initGenAudioH` は素の AES SBox を露出させておらず、ホワイトボックス化されたテーブルのみが存在すると判断できる。
  - MixColumns/InvMixColumns 定数もヒットしない。全ラウンド定数がテーブルに事前吸収されている、または各エントリが XOR マスクで難読化されていると推定される。
- **推定される全ホワイトボックス範囲**: `0x100f70000` .. `0x101192000` (約 2.13 MiB)。ここが `_gen_audio_h` / `_gen_audio_h2` 実行時に参照される TFIT 表。`initGenAudioH` はこれをロードせず、Mach-O が map したものを "unlock" しているだけ (typical: 各ロード後にランタイムマスクを付け足す)。

---

## 4. アンチデバッグの実装位置

以下は `initGenAudioH` 本体 (`0x100783fc8` .. `0x1007d594c`) 内で発見した具体的な検出手段。

### 4-1. 生 `sysctl` 10 回 (SVC #0x80, x16=0xca)

**(訂正: 2026-07-03、詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §2)**: 旧「12 回」は誤り。実際は **10 回**であり、区別できていなかった残り 4 箇所は `getpid` (SVC 20) だった。

代表位置: `0x1007c499c`, `0x1007ca000`, `0x1007ca4fc`, `0x1007ca6ec`, `0x1007cca8c`, `0x1007ccd3c`, `0x1007cd17c`, `0x1007cdfc0`, `0x1007ce200`, `0x1007ce8d8`。

典型的パターン (`0x1007c4980`〜):
```
mov  x0, x8                 ; MIB pointer
mov  w1, w9                 ; MIB length
mov  x2, x10                ; oldp
mov  x3, x11                ; oldlenp
mov  x4, x12                ; newp
mov  x5, x13                ; newlen
movz x16, #0xca             ; __sysctl
svc  #0x80
b.lo skip_neg
mov  w1, #-1
mul  w0, w1, w0             ; negate errno
mov  w8, w0
skip_neg:
str  w8, [x28, #0xc74]      ; result to state
```

**用途**: MIB = `{CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()}` として `struct kinfo_proc` を取り、`kp_proc.p_flag & P_TRACED` を確認する最典型的 anti-debug。12 回もあるのは、複数の MIB (KERN_PROC / KERN_PROC_ALL / HW_MACHINE / etc) をローテーションで確認しているためと推定 (CFF に埋もれて MIB 定数を復元できず未確定。**MIB の具体値は未確定**)。

**(訂正: 2026-07-03、詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §1 §2)**: 回数は 12 ではなく **10**。MIB は Unicorn Engine による動的エミュレーションで実測され、**`{CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1, pid}` で確定**した (9/10 サイトで一致、残り 1 サイトはエミュレーションで未到達)。「MIB の具体値は未確定」は解消済み。ただし pid フィールドの実測値は常に `0` で、これはエミュレーション環境のアーティファクトの疑いが強く実機の pid 値そのものは依然未確定。

### 4-2. 生 `kill` 3 回 (SVC #0x80, x16=0x25)

- `0x1007c9b14`
- `0x1007cc560`
- `0x1007cdd44`

前後のコンテキストは全て同じ:
```
mov  w0, w8           ; pid
mov  w1, w9           ; signal
movz x16, #0x25       ; kill
svc  #0x80
b.lo skip_neg
mov  w1, #-1
mul  w0, w1, w0
```
→ 検出時の self-terminate 実装。libc の `abort()` / `exit()` を使わないので、Frida の `Interceptor.replace(abort, () => {})` が効かない。**この 3 箇所こそが「Frida hook で強制クラッシュ」の実行地点**。`kill(getpid(), SIGKILL)` あるいは `kill(getpid(), SIGABRT)` と推定される (どの signal かは CFF で追い切れず **signal 番号は未確定**、ただし `movz w9, #imm` の状態を近隣で観測すると `w9=0x9 (SIGKILL)` の可能性が高い候補が 1 つあった)。

**(訂正: 2026-07-03、詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §3)**: 上記の推定は誤りだった。3 箇所とも **`sig=0` で固定**であることが静的 (`svc` 直前に `str wzr, [slot]` で明示的にゼロクリア) と動的 (Unicorn エミュレーション) の両方で確認済み。`kill(pid, 0)` は POSIX 上「シグナルを送らずプロセスの生存確認だけを行う」**良性の liveness probe** であり、**self-kill 経路ではない**。したがって「Frida hook で強制クラッシュ」の実行地点はこの 3 箇所ではなく、initGenAudioH の外にある別経路と考えられる (未確定、別調査中)。旧来観測されていた Frida hook クラッシュ (500 回再帰 `objc_msgSend`) の実行地点は本関数の解析範囲外。

### 4-3. dyld image walk による inject dylib 検出

- `_dyld_image_count` @ `0x1007c23f0`, `0x1007c8bf4`
- `_dyld_get_image_name` @ `0x1007a7858`, `0x1007a8c90`, `0x1007c89c0`
- `_dyld_get_image_header` @ `0x1007c0c80`, `0x1007c71f0`
- `_dyld_get_image_vmaddr_slide` @ `0x1007c8a1c`, `0x1007c8ac0`
- `dladdr` @ `0x1007c199c`

パターン: `image_count → 各 image で name/header/slide を取得 → 名前を obfuscated string と `strcmp` (推定)`。`substrate`, `frida`, `MobileSubstrate`, `SubstrateBootstrap` 等の比較先文字列は `__cstring` に平文では見つからず (`strings` で検出できない) → 実行時 XOR/rotate デコードと推定。**比較文字列の平文値は未確定**。

### 4-4. dlopen / dlsym / getenv 検査

- `getenv` @ `0x1007c3c5c` — 第一引数の string リテラルが CFF で追えず未確定。**推定: `getenv("DYLD_INSERT_LIBRARIES")`**。
- `dlopen` @ `0x1007a4b98` — 引数文字列は同じく CFF に埋もれて未確定。
- `dlsym` @ `0x1007c3f30` — x0 = `-1` (`movn x0, #1` = `RTLD_NEXT`) が直前に見えた。Frida が inject するランタイム関数 (例えば `MSHookFunction` / `objc_msgSendSuper2` / `substrate_*`) の存在を dlsym で探して非 NULL なら Substrate 環境と判定するパターン。

### 4-5. ファイルシステム jailbreak 探索

- `opendir` @ 単一, `readdir` @ 単一, `closedir` @ 単一, `access` (SVC) × 3, `unlink` (SVC) × 7。
- `/Applications/Cydia.app`, `/private/var/lib/apt`, `/usr/libexec/cydia`, `/etc/apt`, `/Library/MobileSubstrate/MobileSubstrate.dylib`, `/var/log/apt`, `/private/var/cache/apt/` などを列挙 or `access(2)` するのが典型。文字列は難読化されており平文検出できず (**該当リテラルは未確定**)。`symlink` (57) が 2 回あるのは Rocky-mountain 検出テク (シンボリックリンクを一度作って読み戻しで sandbox 動作を検証、または JB 検出そのもの) の可能性。

### 4-6. 検出→クラッシュ経路まとめ

1. `sysctl` / dyld walk / `dlsym` / opendir で異常検出。
2. state 変数 (`__DATA.__data:0x101034204` を含む複数) を「異常」値にセット。
3. CFF ディスパッチが「異常パス」へ流れる。
4. **`svc #0x80` + `x16=0x25` (`kill`)** で `kill(getpid(), SIG***)` を叩き、self-SIGKILL/SIGABRT。
5. あるいは `__stack_chk_fail` @ `0x1007d442c` を発火させて `abort` 経路。
6. BRK 2 発 (`0x1007d98b0`, `0x1007d9a68`) も別の異常パス用 SIGILL trap。

`abort` / `exit` / `_exit` は import されているものの、initGenAudioH 本体からの BL は 0 (呼ばれない)。**すべての「殺し」は生 syscall or `__stack_chk_fail` or `brk` に集約されている**、これが Frida の `Interceptor.attach(abort, ...)` などが効かなかった理由。

**(訂正: 2026-07-03、詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §3 §7)**: 上記 4 の記述は誤り。3 箇所の `kill` は全て `sig=0` の良性 liveness probe であり self-kill ではない (§4-2 訂正脚注参照)。真の self-kill 経路 (もし存在するなら) はこの 3 箇所ではなく未確定のまま。`__stack_chk_fail` と `brk` 2 箇所は self-terminate 候補として引き続き未検証。

---

## 5. `_gen_audio_h` / `_gen_audio_h2` / `_set_platform_for_gen_audio` の Crew 内 VA

GameWidgetsExtension バイナリの既知 RVA から prologue 128 バイトを取り、Crew の全バイト列から exact match で探索した結果。

| シンボル | GameWidgetsExtension RVA | Crew VA | Crew RVA |
|---|---|---|---|
| `_gen_audio_h` | `0x4e9e7c` | **`0x10090f20c`** | `0x90f20c` |
| `_gen_audio_h2` | `0x3ceb40` | **`0x1007f425c`** | `0x7f425c` |
| `_set_platform_for_gen_audio` | `0x351d5c` | **`0x1007788ec`** | `0x7788ec` |

指紋長 64 バイト以上でユニークマッチ。

### 呼び出し関係 (Crew 側)

- `_gen_audio_h` は `bl` 経由で **1 箇所** から呼ばれる: `0x1007de96c` (親関数 `0x1007de890` .. `0x1007df124`)。この親関数は `+[VoIPClient genAudioH:i2:i3:]` (`0x10072b634`) から `bl @0x10072b85c` で呼ばれる。したがってフローは:
  - `+[VoIPClient genAudioH:i2:i3:]` (`0x10072b634`) → wrapper (`0x1007de890`) → `_gen_audio_h` (`0x10090f20c`)。
- `_gen_audio_h2` は `bl` 直接は 0 回、`b` (uncoditional branch = tail call) が **1 箇所** `0x100819c34` から。この branch は `0x100819c34` を含む親 (`0x10090f20c` .. `0x100a208fc`) 内、つまり **`_gen_audio_h` 自体の末尾から `_gen_audio_h2` へジャンプ**する。つまり Crew では `gen_audio_h` と `gen_audio_h2` は tail-merged した 1 つの巨大関数として実装され、内部 dispatcher (hash_method によって v1 か v2 か振り分け) で切り替わる。
- `_set_platform_for_gen_audio` は `bl` 1 箇所: `0x1009593e8` (親関数 `0x10090f20c` .. `0x100a208fc`)。**`_gen_audio_h` の中で 1 回、platform をセットしている**。Nintendo 側では iOS/Android/ROOT/EMULATOR などの platform id を区別してホワイトボックスの分岐を変える設計。

### `+[VoIPClient genAudioH2:i2:i3:]` 側の経路

- IMP `0x100708a3c` の BL リストは import stub 中心。内部 BL は `0x1006d2834` (ORC-CoreVoIP 系ヘルパ, 未解析) と `0x1007650f8` (wrapper) の 2 個のみ。
- `0x1007650f8` は `0x10076fe7c` を 3 回呼び、`0x10076fe7c` は最後に `bl 0x1007d594c` (initGenAudioH 末尾のオブジェクト初期化ルーチン) を呼ぶ。genAudioH2 経路は共通の compound-init を lazy に叩いてから、`b 0x1007f425c` (=`_gen_audio_h2`) にテールジャンプする形。

---

## 6. まとめ

| 項目 | 結論 |
|---|---|
| `+[VoIPClient initGenAudioH]` IMP | `0x100a29528` (RVA `0xa29528`)。CFF 化された 0x7c バイトの薄いラッパー |
| 本体 | `0x100783fc8`〜`0x1007d594c` (0x51984 バイト、単一 basic block の OLLVM-CFF)。呼び出しは `0x100a2957c` から唯一 |
| ホワイトボックス表本体 | **`0x100f70000` .. `0x101192000` (約 2.13 MiB)** の `__DATA.__data` 内。Mach-O ローダにより自動で mmap される |
| ホワイトボックス表を `initGenAudioH` が読み込む rodata | **なし** (`__DATA_CONST` はほぼ触っていない)。関数の役割は「表のロード」ではなく「anti-debug チェック + ステート machine 初期化 + mutex/thread の生成」 |
| 素の AES SBox / MixColumns 定数 | バイナリ全体に露出せず (`63 7c 77 7b` パターン検索 hit 0)。全ラウンドが TFIT 化されている |
| anti-debug 手段 | 生 `sysctl(0xca)` × 10 (訂正: 2026-07-03、旧「12」は誤り。うち 4 箇所は実は `getpid(0x14)`。詳細 [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md)), 生 `kill(0x25)` × 3 (訂正: 2026-07-03、全て `sig=0` の liveness probe、self-kill ではない), dyld image walk, `dlsym(RTLD_NEXT, ...)`, `getenv(...)`, `opendir/readdir`, `access(0x21)` × 3, `symlink(0x39)` × 2, `unlink(0xa)` × 7, `__stack_chk_fail`, `brk` × 2 |
| Frida/Substrate 検出の crash 経路 | ~~libc `abort/exit` を使わず、`svc #0x80` 経由の生 `kill` に集約。したがって `Interceptor.replace(abort, ...)` などでは回避不能~~ **(訂正: 2026-07-03) 不正確。3 箇所の `kill` は全て `sig=0` の良性 liveness probe であり self-kill 経路ではないと判明** (詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §3)。真の crash 経路は未確定 |
| `_gen_audio_h` (Crew) | `0x10090f20c` (RVA `0x90f20c`) |
| `_gen_audio_h2` (Crew) | `0x1007f425c` (RVA `0x7f425c`) |
| `_set_platform_for_gen_audio` (Crew) | `0x1007788ec` (RVA `0x7788ec`) |
| `_gen_audio_h` と `_gen_audio_h2` の関係 (Crew) | `_gen_audio_h` の末尾 (`0x100819c34`) から `b _gen_audio_h2` へテールジャンプ。両者は tail-merged 実装 |
| コールチェーン (h1) | `+[VoIPClient genAudioH:i2:i3:]` `0x10072b634` → wrapper `0x1007de890` → `_gen_audio_h` `0x10090f20c` |
| コールチェーン (h2) | `+[VoIPClient genAudioH2:i2:i3:]` `0x100708a3c` → wrapper `0x1007650f8` → `0x10076fe7c` → `0x1007d594c` (compound-init) → tail の `b _gen_audio_h2` |

## 7. 未確定 (追加調査が必要)

**(訂正: 2026-07-03)** 以下 6 項目のうち 3 項目は後続調査で解決済みに移動した。詳細は各リンク先を参照。

### 解決済みに移った項目

- ~~`sysctl` MIB の具体値 (12 回それぞれで何を問い合わせているか)~~ → **確定**。`{CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1, pid}` (`kinfo_proc` の `P_TRACED` 検出パターン)。回数も 12 ではなく **10** に訂正。詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §2。
- ~~`kill(pid, sig)` の `sig` 値 (SIGKILL/SIGABRT/SIGILL の別)~~ → **確定**。3 箇所とも `sig=0`（良性の liveness probe、self-kill ではない）。詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §3。
- ~~`pthread_create` で起動される thread routine の VA (CFF 内で x2 が乗算/XOR で組み立てられており線形トレースでは復元不可)~~ → **確定**。`0x100a41050` (size `0x24c`)。実際には CFF は絡んでおらず単純な `adrp+add` で特定可能だった。`NSSearchPathForDirectoriesInDomains` + `CFArrayGetValueAtIndex` + `CFStringGetCString` を呼ぶループで、標準検索パスのファイル列挙（ジェイルブレイク痕跡探索候補）と判明。詳細は [`znca_ios_init_gen_audio_h_cff.md`](./znca_ios_init_gen_audio_h_cff.md) §5。

### 依然未確定

- `getenv` / `dlopen` / `dlsym` に渡される文字列引数の実体 (難読化されており、runtime decode 器を先に特定してからでないと判読不能)。**依然未確定**: Unicorn Engine による動的エミュレーションでも、あるチェックループ内で 425,000,000 命令超を消費しても終了せず、これらの呼び出しに対応するコードパスへ到達できなかった。詳細は [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) §5。
- dyld image walk での比較先文字列 (`frida` / `substrate` / etc の平文値)。依然未確定 (呼び出し自体は動的に確認済みだが比較先文字列は未到達)。
- initGenAudioH のうち "実際にホワイトボックス state を書き換えている" 命令の同定 (state variable `0x101034204` は CFF ディスパッチ用の擬似変数であり、真のホワイトボックス初期化は既に mmap されたテーブルへの XOR マスク差し込みだけの可能性が高い。だとするとほぼ noop なのだが、それにしては function 本体が 335 KiB と巨大すぎ、CFF による膨張分を差し引いても実処理はまだ確定していない)。
  → **2026-07-03 CFF de-flatten で大幅進展**: [`znca_ios_init_gen_audio_h_cff.md`](./znca_ios_init_gen_audio_h_cff.md) 参照。
  694 件の CFF ディスパッチ site のうち **99.7% (678件) が state=0 によるフォールスルー相当の no-op (opaque predicate)** であり、
  実行時の制御フローに影響を与える "functional edge" はわずか **15 個** (非ゼロ定数によるジャンプ 2 個 + 実行時値による動的分岐 13 個、うち `_dyld_image_count` の戻り値が直接分岐に使われる anti-inject 検知が 1 個確認済み) のみ。
  また、ホワイトボックス領域への genuine な `str`（書き込み）は 0 件、読み出しのみ 498 件（68+ ページに分散）で、
  マップ済みテーブルの書き換えは `initGenAudioH` 内には存在しないことも判明した。

### ホワイトボックス領域の内部レイアウト (部分解決)

- ホワイトボックス領域 (2.13 MiB) の内部レイアウト (T-box / round key / permutation-scaling 表の切り分け)。
  → **2026-07-03 追跡調査で大幅進展**: [`znca_ios_whitebox_layout.md`](./znca_ios_whitebox_layout.md) 参照。
  ブロブの 82.6% (1.76 MiB) は "pure table" 領域（entropy 7.07-7.22 の狭帯域、4B ワードがほぼ全て distinct）、
  残り 17.4% (380 KiB, 31 island) は chained-fixups で明らかになった **CFF ディスパッチ用ポインタ変数プール**
  （本ドキュメント §3 で "未確認" としていた `0x10113a520` 等のホットターゲットの多くがこれに該当し、
  `initGenAudioH` と `_gen_audio_h`/`_gen_audio_h2` が同一の state 変数プールを共有していることも判明）。
  なお生の AES S-box（256B バイト置換、`0..255` の完全順列）はブロブ全域（固定境界・スライディング窓の両方）で
  1 件もヒットせず、`_gen_audio_h` 側の逆アセンブルでもレジスタ添字 `LDRB`（古典的 S-box lookup 命令列）は 0 件と確認された
  （較正用に実行した Netflix TFIT-AES11 の同テストでは 16/16 ヒットしており手法自体は妥当）。詳細は同ドキュメント §3, §5。

追加で `initGenAudioH` のマスクデコード実装を洗い出したい場合は、
- CFF を IDA/Ghidra + karonte や deflat スクリプトで de-flatten し、
- state variable `0x101034204` の書き込みを edge にした CFG 再構築
が最短ルートになる。

**(訂正: 2026-07-03)**: 上記の方針は実行済み。[`znca_ios_init_gen_audio_h_cff.md`](./znca_ios_init_gen_audio_h_cff.md) が capstone ベースの自作パーサで de-flatten を行い、真の CFF state slot（693 個の private stack slot）と機能的に意味のある 15 エッジを特定した。ただし `getenv`/`dlopen`/`dlsym` の引数文字列や sysctl MIB の実 pid 値等、残された未確定項目については引き続き上記「依然未確定」節を参照。
