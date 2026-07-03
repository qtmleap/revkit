# znca iOS 3.4.1 — `+[VoIPClient initGenAudioH]` 本体の CFF de-flatten

対象: `/home/vscode/app/targets/znca_ios_3.4.1/Crew` (arm64 Mach-O, `__TEXT` vmaddr = `0x100000000`)
本体関数: `0x100783fc8` .. `0x1007d594c` (0x51984 バイト、約335 KiB)。前提となる静的解析は
`docs/spec/znca_ios_init_gen_audio_h_static.md` を参照。

このドキュメントは前セッションで「単一 basic block に見える巨大関数」と判明した本体を、
capstone ベースの自作パーサで **de-flatten（制御フロー平坦化の解除）** した結果をまとめる。

補助スクリプトはすべて `targets/znca_ios_3.4.1/analysis/cff/` に配置:

| ファイル | 役割 |
|---|---|
| `common.py` | セグメント/ファイルオフセット解決、共通定数 |
| `disasm_body.py` | 関数域を capstone で線形逆アセンブルし `insns.pkl` にキャッシュ |
| `explore_wrapper.py` | `+[VoIPClient initGenAudioH]` ラッパー (`0x100a29528`) で CFF イディオムの仮説を検証 |
| `find_dispatch.py` | CFF ディスパッチイディオム (Type A / Type B) を全走査で検出、`target_base` を解決 |
| `resolve_edges.py` | 各ディスパッチ site の state slot への全 writer を走査し、定数なら `target_base+value` に解決 |
| `build_cfg.py` | 上記を統合し pseudo-BB グラフを構築 (`cfg.pkl`) |
| `export_dot.py` | `cfg.pkl` から DOT を出力 (`cfg_full.dot` + zone 別 `cfg_zone_<reg>.dot`) |
| `list_real_effects.py` | 「本当に意味のある」15 個のディスパッチ効果 (非ゼロ定数 2 件 + 動的 13 件) を再現表示 |

再実行方法:
```bash
cd /home/vscode/app/targets/znca_ios_3.4.1/analysis/cff
python3 disasm_body.py      # insns.pkl 生成 (要 force=True の初回のみ)
python3 build_cfg.py        # cfg.pkl 生成
python3 export_dot.py       # DOT 出力
python3 list_real_effects.py
```

---

## 1. CFF ディスパッチイディオムの完全な解読

前セッションで確認した idiom:

```
ldr   xSTATE, [base, #off]      ; state slot を読む
adr   xA, #TT                   ; TT = このイディオム自身の近傍アドレス
[ldrsw xB, [xA]; add xA, xB, xA]; ← Type A のみ (TT 直後に埋め込まれた delta word を加算)
and   xC, xA, xSTATE
mov   xD, #2
mul   xC, xC, xD
eor   xA, xA, xSTATE
add   xA, xA, xC                 ; xA = (target_base ^ state) + 2*(target_base & state)
br    xA
```

`a^b + 2*(a&b) == a+b` という桁上げの恒等式を使って `xA = target_base + state` を計算しているだけ、
というのが前セッションからの仮説だった。**今回、`0x100a29528` ラッパーの手計算トレースで厳密に確認した**:
`state=0` のとき `target_base = TT+4 = 0x100a29564` へ分岐し、実際にその番地の命令列と一致した。

2 つの変種が存在する:

- **Type A** (`ldrsw` による間接テーブル経由): `target_base = TT + word_at(TT)` (符号付き 32bit)。**317 件**。
- **Type B** (直接): `adr` の結果 `TT` 自体が `target_base`。**377 件**。

全 **694 件**のディスパッチ site をバイナリ全域から検出した (`find_dispatch.py`)。
いずれも `word_val` は事実上常に `4`、すなわち `target_base` は「このイディオム自身の直後の命令アドレス」
(= state=0 のときの通常フォールスルー) に一致する — obfuscator は per-site に自分専用の delta table を
埋め込んでいるが、その値はほぼ常に「次の命令へフォールスルーするための自明値」になっている。

### state 変数の実体は「関数プロローグで確保した専用スタックスロット」

**重要な訂正**: 前回セッションの静的解析ドキュメントは「`__DATA.__data:0x101034204` (628 refs) が CFF
ディスパッチ変数」と推定していたが、**これは誤り**だった。実際に idiom を機械的に検出して state レジスタの
出所を後方追跡した結果 (`find_dispatch.py` の `state_load_addr`/`state_src_operand`)、694 件の site が
参照する state slot は **すべて `[baseReg, #imm]` という形のスタックローカル変数**であり、`0x101034204`
のような固定グローバルアドレスを参照する site は **1 件も存在しない**。

`0x101034204` を直接検証すると:

```
adrp x9, #0x101034000
add  x9, x9, #0x204
str  w8, [x9]              ; ← 常にレジスタ値の書き込みのみ (628/629回)
```

このアドレスへの参照は本体全域で **629 回すべてが書き込み、読み込みは 0 回**。つまり
**`0x101034204` は CFF ディスパッチ変数ではなく、"書きっぱなしの囮シンク" (dead-store 難読化)** である。
同様に、前回ドキュメントが「state 変数の亜種」と推定した以下のグローバルアドレスも、実際には
**読み込み優勢** (書き込みはたかだか 0〜1 回) であり、これも CFF state ではなく **通常のデータ/設定値読み出し**
である可能性が高い:

| アドレス | reads | writes | 前回の推定 | 今回の判定 |
|---|---|---|---|---|
| `0x101034204` | 0 | 629 | CFF state var (628 refs) | **書き込み専用の囮シンク** |
| `0x10113a520` (ページ `0x10113a000`) | 123 | 1 | state var 亜種 | **読み出し優勢、CFF ではない** |
| `0x10103d998` (`0x10103d000`) | 27 | 0 | state var 亜種 | **読み出し専用** |
| `0x10103f9e0` (`0x10103f000`) | 43 | 0 | state var 亜種 | **読み出し専用** |
| `0x101084300` (`0x101084000`) | 18 | 0 | state var 亜種 | **読み出し専用** |
| `0x10110e020` (`0x10110e000`) | 24 | 1 | state var 亜種 | **読み出し優勢、CFF ではない** |

### 真の state slot: 9 個の「ゾーン」レジスタ + 個別オフセット

関数プロローグ (`0x100783fc8`〜`0x100784028`) は `sub sp, sp, #0x167f0` (約90KiB) の巨大フレームを確保した後、
即値オフセットが 12bit に収まるように **9 個のゾーンベースレジスタ**へ分割している:

```
0x100783fec: mov x19, sp                      ; zone x19 = +0
0x100783ff0: add x22, x19, #0xc, lsl #12
0x100783ff4: add x22, x22, #0x460             ; zone x22 = +0xc460
0x100783ff8: add x28, x19, #0xa, lsl #12
0x100783ffc: add x28, x28, #0x1e0             ; zone x28 = +0xa1e0
0x100784000: add x24, x19, #6, lsl #12
0x100784004: add x24, x24, #0x204             ; zone x24 = +0x6204
0x100784008: add x25, x19, #4, lsl #12
0x10078400c: add x25, x25, #0xfbe             ; zone x25 = +0x4fbe
0x100784010: add x26, x19, #3, lsl #12
0x100784014: add x26, x26, #0xfb0             ; zone x26 = +0x3fb0
0x100784018: add x23, x19, #2, lsl #12
0x10078401c: add x23, x23, #0xfee             ; zone x23 = +0x2fee
0x100784020: add x21, x19, #1, lsl #12
0x100784024: add x21, x21, #0xfc7             ; zone x21 = +0x1fc7
0x100784028: add x20, x19, #0xfba             ; zone x20 = +0xfba
```

CFF の state slot は、実測では以下のレジスタを base に使う (`x21`/`x23`/`x24` は
dispatch state としては一度も観測されず、単なるデータ用ゾーンとして使われている模様):

| base reg | dispatch site 件数 | 観測アドレス範囲 |
|---|---|---|
| `x19` | 369 | `0x100784064`–`0x1007d45a4` (関数ほぼ全域) |
| `x20` | 68 | `0x1007b2ca0`–`0x1007bf02c` |
| `x22` | 60 | `0x1007cd3d8`–`0x1007d4614` |
| `x25` | 56 | `0x1007b9ab4`–`0x1007cacb8` |
| `x28` | 55 | `0x1007bf658`–`0x1007c66e0` |
| `x14` (別名) | 42 | `0x1007b8f38`–`0x1007d4b20` |
| `x12` (別名) | 23 | `0x1007b943c`–`0x1007d4e4c` |
| `x8` (別名) | 13 | `0x1007b90b8`–`0x1007d5118` |
| `x26` | 5 | `0x1007c966c`–`0x1007c9988` |
| `x13` (別名) | 2 | `0x1007cc53c`–`0x1007d4ff0` |
| `x15` (別名) | 1 | `0x1007d550c` |

**693 個の distinct slot に対して 694 件の dispatch site** — ほぼ 1 サイト 1 専用スロットであり、
少数の共有変数による「単一の巨大 switch」ではなく、**関数全体に散らばった約 700 個の独立した
マイクロ state-machine**として実装されている。これは task 記述にあった「副次ディスパッチ変数ごとに
分離して疑似関数を切り出す」という前提を修正する必要があることを意味する: **明確に分離できる少数の
疑似関数には分割できない**。x19/x20/x22/x25/x28 等の「ゾーン」はアドレス局所性を示すが、`x19` ゾーン
だけで関数のほぼ全域をカバーし、`kill` 呼び出し 3 箇所はいずれも 4〜5 個のゾーンに同時に属する
(後述 §4)。DOT ファイルはゾーン単位でも分割出力したが (`cfg_zone_<reg>.dot`)、これは**疑似関数境界の
確定的な切り分けではなく、あくまで参考情報**として扱うべきである。

---

## 2. de-flatten の結果

`resolve_edges.py` は、694 件の dispatch site が参照する 693 個の state slot それぞれについて、
**関数全体を走査してその slot へ書き込む全命令**を集め、書き込み元レジスタを最大 6 命令分だけ
後方追跡して `mov`/`movz`/`movn`/`movz+movk` 連鎖の定数に還元できるか試みた。

| 分類 | 件数 | 比率 |
|---|---|---|
| state slot への writer 総数 | 714 | 100% |
| うち **定数に解決できた** (`resolved`) | 701 | 98.2% |
| うち **実行時値 (動的、解決不能)** | 13 | 1.8% |
| 解決できたが target が 4byte非整列/範囲外 (`invalid`、後述) | (701 中 10 件を除外) | — |
| 有効な CFF エッジとして採用 | **693** | — |

`build_cfg.py` はこれらを実際の分岐先アドレスに変換し、**通常の分岐命令 (`b`/`b.cond`/`cbz`/`cbnz`/
`tbz`/`tbnz`、10150 件、`bl` 273 件) と統合した pseudo-CFG** を構築した (`cfg.pkl`)。

```
leaders (pseudo-BB 数):        13200
de-flatten された CFF エッジ:   693
直接分岐 (b/b.cond/cbz/...):   10150
bl 呼び出し site:               273
動的 (未解決) エッジ:            13
無効 (整列/範囲外、除外済み):     10
```

### 「無効」エッジについて (10 件)

10 件の writer は、定数への還元には成功したが、結果アドレスが 4byte 非整列 (例: `target_base+3`)
または関数域外になった。サンプル:

```
write=0x1007b9bd8 slot=('x25',232) value=0x3 target_base=0x1007c6864 target=0x1007c6867 (非整列)
write=0x1007c8bcc slot=('x25',840) value=0x1 target_base=0x1007baa28 target=0x1007baa29 (非整列)
```

`(base_reg, offset)` が一致するというだけで「同一の CFF state slot への書き込み」と誤認したケースで、
実際には**関数内の別の無関係なコード領域が、生存期間の終わったスタックスロットを別の目的の
ローカル変数として再利用している**ケース (レジスタ/スタックスロットの再利用は巨大関数の
コンパイラ最適化として一般的)。これらは CFG から除外した。**701 件中 691 件 (98.6%) は 4byte 整列・
関数域内という妥当な結果**であり、手法自体の健全性を裏付けている (§3 でサンプル検証済み)。

---

## 3. 検証: de-flatten されたエッジは実際に「意味のある」コードへ着地するか

`dispatch_edges` からランダムサンプルした 6 件について、write site の直前コンテキストと
target 先頭数命令を確認した。全件で target は自然な「ローカル変数の読み書き・比較」から
始まっており、ゴミ地帯やデータ領域への着地はなかった。例:

```
write=0x100794b84 val=0 slot=('x19', 12144) -> target=0x100794bb4
  0x100794b80: cbnz w8, #0x100794d34
  0x100794b84: str xzr, [x19, #0x2f70]     ; state=0
  -> 0x100794bb4: strb wzr, [x21, #0xfa8]  ; 自然なコード
  -> 0x100794bb8: b #0x100794d40
```

---

## 4. 「本当に意味のある」15 件のディスパッチ効果

de-flatten された 693 件のうち、**689 件は state=0 が書き込まれた結果、target_base (= 直後の命令、
つまり実質フォールスルー) に一致するだけの no-op** であることが判明した (`list_real_effects.py` で
`val != 0` を抽出すると 693 件中わずか **2 件**しかヒットしない)。すなわち **CFF ディスパッチ機構の
99.7% は静的解析・逆コンパイルを妨害するためだけの opaque predicate であり、実行時の制御フローには
何の影響も与えていない**。これ自体が重要な発見であり、335 KiB という関数サイズの大半が
「本物の処理」ではなく「フォールスルーするだけの巨大な迂回機構」で占められていることを示す。

本当に意味を持つのは以下の **15 箇所**のみ:

### 4-1. 非ゼロ定数による実ジャンプ (2 件)

| write addr | value | slot | target |
|---|---|---|---|
| `0x1007c721c` | `4` | `(x25, 1000)` | `0x1007bafb8` |
| `0x1007c9454` | `0x80` | `(x25, 248)` | `0x1007b9b3c` |

いずれも長距離の無条件ジャンプで、着地先は自然なコード (ローカル変数の `and`/`cmp`/`cset` など)。
`b` 命令の代わりにわざわざ CFF イディオムを使って実装された「本物の goto」。

### 4-2. 実行時値による動的分岐 (13 件) — anti-debug/anti-inject との相関

この 13 件こそが、`initGenAudioH` の中で**唯一、実行時の環境によって制御フローが変わる**箇所である。

| write addr | slot | 直前の出所 | 解釈 |
|---|---|---|---|
| `0x1007c8bf8` | `(x25, 624)` | `bl 0x100c33c84` (**`_dyld_image_count`**) の戻り値 `w0` | **ロード済み dylib 数がそのまま次の分岐先を決める** — インジェクトされた dylib (Frida/Substrate) の有無を検知する最有力候補 |
| `0x1007bcae8` | `(x25, 1984)` | `bl 0x100c34980` (**`sel_registerName`**) の戻り値 `x0` | 動的に解決した Objective-C セレクタのポインタ値が分岐先を決める |
| `0x1007bdbf0` | `(x25, 2752)` | 同上 `sel_registerName` (別呼び出し) | 同上 |
| `0x1007caacc` | `(x25, 2456)` | `eor`/`lsr`/`lsl` を連鎖させたローリング XOR 合成 (2 つのローカル値を混合) | マスク/ハッシュ的な合成値。ホワイトボックス関連の可能性が最も高いが、書き込み先は **スタックローカル**でありマップ済みホワイトボックス領域そのものではない |
| `0x1007cab1c` | `(x25, 2528)` | 上記合成の続き (別シフト量での XOR) | 同上 |
| `0x1007d4d48` | `(x20, 128)` | `eor w8, w9, w8` — 2 つの別ゾーン (`x20`/`x21`) 由来の値の XOR | 同系統のマスク合成 |
| `0x1007bba7c` | `(x25, 1240)` | `ldr x8,[x25,#0x4d0]; str x8,[x25,#0x4d8]` (既存ローカル値のコピー) | 出所は本ウィンドウ内では追跡不可 (**追跡不可**) |
| `0x1007bcb50` | `(x25, 2008)` | `sub w8,w8,w9` (2 ローカル値の差分) | 減算結果が分岐先を決める。オペランドの最終出所は未追跡 (**追跡不可**) |
| `0x1007bd1f4` | `(x25, 2544)` | `ldr w8,[x25,#0x9ec]` (既存ローカル値のコピー) | 出所未追跡 (**追跡不可**) |
| `0x1007c7f90` | `(x25, 1304)` | `ldr w8,[x25,#0x510]` (既存ローカル値のコピー) | 出所未追跡 (**追跡不可**) |
| `0x1007c8490` | `(x25, 1376)` | `ldr w8,[x25,#0x558]` (既存ローカル値のコピー) | 出所未追跡 (**追跡不可**) |
| `0x1007c91d4` | `(x25, 1216)` | `ldr w8,[x25,#0x4b8]` (既存ローカル値のコピー) | 出所未追跡 (**追跡不可**) |
| `0x1007ca1a8` | `(x25, 1760)` | `ldr w8,[x25,#0x680]` (既存ローカル値のコピー、直前に `cbz`/内側 CFF あり) | 出所未追跡 (**追跡不可**) |

**6 件は「既存のローカル変数コピー/算術結果」であり、その値の一次的な出所 (元をたどれば sysctl の
結果か、単なるループカウンタか) は今回の後方追跡ウィンドウ (直近 6〜10 命令) では確定できなかった**。
これ以上追うには、各 slot ごとに専用のデータフロー解析 (SSA 構築や symbolic execution) が必要であり、
本セッションのスコープでは**未確定・追跡不可のまま報告する**。

### 4-3. anti-debug syscall との対応関係 (ゾーン重複のため確定的な帰属はできない)

`docs/spec/znca_ios_init_gen_audio_h_static.md` §4-2 に記載の 3 箇所の生 `kill` (SVC) 呼び出しが、
どの state slot ゾーンに属するかを機械的に確認した:

| kill site | 属するゾーン |
|---|---|
| `0x1007c9b14` | `x12`, `x14`, `x19`, `x25` |
| `0x1007cc560` | `x12`, `x13`, `x14`, `x19` |
| `0x1007cdd44` | `x12`, `x13`, `x14`, `x19`, `x22` |

いずれも 4〜5 個のゾーンに**同時に**属しており (`x19` はほぼ全域をカバーするため常にヒットする)、
ゾーンによる疑似関数分割では anti-debug 処理を単一の疑似関数に切り分けることはできなかった。
**確定的な帰属付けは不可能** — これは §1 で述べた通り「少数の共有 state 変数」という前提が
成立しないことの直接的な帰結である。

---

## 5. `pthread_create` の thread routine — 特定成功

前セッションでは「CFF に埋もれて線形解析では復元不可」と判定されていたが、**実際には CFF は
一切絡んでおらず、単純な `adrp`+`add` で直接特定できた**。

```
0x1007a4128: adrp x8, #0x100a41000
0x1007a412c: add  x2, x8, #0x50           ; x2 = 0x100a41050  (start_routine)
0x1007a4130: add  x0, x19, #5, lsl #12
0x1007a4134: add  x0, x0, #0x318          ; x0 = &thread (out param)
0x1007a4138: mov  x1, #0                  ; x1 = NULL (attr)
0x1007a413c: add  x3, x19, #0x10, lsl #12
0x1007a4140: add  x3, x3, #0x7d7          ; x3 = arg
0x1007a4144: bl   #0x100c347d0            ; pthread_create(x0, x1, x2, x3)
```

**thread routine VA = `0x100a41050`**。`LC_FUNCTION_STARTS` で正式な関数境界として確認済み
(直前の関数開始 `0x100a40dfc`、直後の関数開始 `0x100a4129c` — つまりサイズ `0x24c` バイト)。

この関数自体も**独自の CFF (own dispatch idiom, own local state slot `[sp,#0x30]` 系列) を持つ**
別関数であり、`initGenAudioH` 本体とは完全に独立している。内部で呼ぶ import は 3 つ:

| VA | シンボル (rabin2 `-i` で解決) |
|---|---|
| `0x100c330a8` | `CFStringGetCString` |
| `0x100c33414` | `NSSearchPathForDirectoriesInDomains` |
| `0x100c32fdc` | `CFArrayGetValueAtIndex` |

ループ構造 (`cbnz w8, #0x100a410b0` による戻り分岐) と合わせると、**この thread は
`NSSearchPathForDirectoriesInDomains` で取得したパス配列を `CFArrayGetValueAtIndex` で順に取り出し、
各要素を `CFStringGetCString` で C 文字列化するループ**であると判断できる。これは前回ドキュメントが
「whitebox テーブル展開/検証を別スレッドで行っている」と推測していた内容よりも具体的で、
**標準 iOS 検索パス (Documents/Library/Caches/tmp 等) を辿ってファイルシステム上の
ジェイルブレイク痕跡/改ざんアーティファクトを探索するバックグラウンドスレッド**という解釈のほうが
証拠と整合する (呼び出し順序は CFF により実行時に決まるため確定はできないが、3 API の組み合わせ自体が
強い状況証拠)。

---

## 6. ホワイトボックステーブル領域への読み書き (task #5)

`docs/spec/znca_ios_init_gen_audio_h_static.md` は「`0x100f70000`–`0x101192000` (約2.13MiB) の
高エントロピー領域が TFIT 系ホワイトボックス表」「`initGenAudioH` はこれを *読み込まない*」と推定していた。
今回、ADRP が指すレジスタを実際に**後続命令の base オペランドとして参照しているか (真の deref)** を
区別する厳密なチェックを行い、以下を確認した:

```
genuine DEREF reads  (ldr [wb_addr]):  498 件
genuine DEREF writes (str [wb_addr]):    0 件   ← ホワイトボックス領域への書き込みは皆無
pointer-cached (アドレス値をスタックへ退避するだけ、非 deref): 65 件
```

`0x101034204` を含む「決め打ちの単一ページ」ではなく、**ホワイトボックス範囲内の少なくとも 68 個の
異なる 4KiB ページ**に散らばって読み出しが発生している。単一のテーブル参照ではなく広範囲を
まんべんなく読む挙動は、**AES ホワイトボックス演算そのものではなく、テーブル全体のチェックサム/
ハッシュを計算する改ざん検知 (integrity check) パス**である可能性が高い
(実際の AES 演算テーブル参照は `docs/spec/znca_ios_init_gen_audio_h_static.md` §5 の通り
`_gen_audio_h`/`_gen_audio_h2` (`0x10090f20c`/`0x1007f425c`) 側で行われ、`initGenAudioH` からは
呼ばれない)。

**結論**: task #5 で問われた「ホワイトボックス state の書き換え箇所」は **`initGenAudioH` 内には
存在しない** (書き込み 0 件を確認済み)。ホワイトボックス由来の値を使った"合成"らしき処理は
§4-2 の `0x1007caacc`/`0x1007cab1c`/`0x1007d4d48` (ローリング XOR) に見られるが、これは
**スタックローカルへの書き込みであり、マップ済みテーブル自体を書き換えるものではない**。

---

## 7. まとめ表

| 項目 | 結論 |
|---|---|
| CFF ディスパッチの数式 | `target = target_base + state` (`a^b + 2*(a&b) = a+b` の恒等式による難読化)。Type A (間接、317件) / Type B (直接、377件)、計 694 件 |
| **CFF state 変数の実体** | **前回推定 (`0x101034204` 他グローバル) は誤り。実際は関数プロローグで確保した専用スタックスロット (693 個、ほぼ 1 site 1 slot)** |
| `0x101034204` | 書き込み専用の囮シンク (629 writes / 0 reads)。CFF とは無関係 |
| `0x10113a520` 等 5 種 | 読み出し優勢のデータ/設定値。CFF state ではない |
| de-flatten 成功率 | state writer 714 件中 701 件 (98.2%) を定数解決、うち 691 件 (98.6%) が妥当な (整列・範囲内) ターゲット |
| **実際に意味のある分岐** | de-flatten された 693 件のうち **わずか 15 件** (非ゼロ定数 2 + 動的 13)。残り 678 件は state=0 による no-op (フォールスルーの迂回路)。**CFF の 99.7% は静的解析妨害だけが目的の opaque predicate** |
| anti-inject 検知の直接証拠 | `0x1007c8bf8`: `_dyld_image_count()` の戻り値が **そのまま** CFF 分岐セレクタに使われている |
| anti-debug syscall の疑似関数帰属 | ゾーン重複のため確定不可 (`kill` 3 箇所いずれも 4〜5 ゾーンにまたがる) |
| **`pthread_create` thread routine** | **`0x100a41050`** (LC_FUNCTION_STARTS 確認済み, size `0x24c`)。CFF ではなく単純な `adrp+add` で特定。`NSSearchPathForDirectoriesInDomains`+`CFArrayGetValueAtIndex`+`CFStringGetCString` を呼ぶループ = 標準検索パスのファイル列挙 (ジェイルブレイク痕跡探索の可能性) |
| ホワイトボックス領域への書き込み | **0 件** (498 件の読み出しのみ、68+ ページに分散 → 改ざん検知目的の走査と推定) |
| pseudo-CFG 規模 | leaders 13200 / CFF エッジ 693 / 直接分岐 10150 / bl 273 |

## 8. 未確定・追跡不可のまま残した項目

- 4-2 節の 13 件中 6 件 (`0x1007bba7c`, `0x1007bcb50`, `0x1007bd1f4`, `0x1007c7f90`, `0x1007c8490`,
  `0x1007c91d4`, `0x1007ca1a8` — 実際は 7 件) は、値が既存ローカル変数のコピー/単純算術結果であり、
  その一次的な出所 (sysctl の戻り値か、単なるカウンタか) を後方追跡ウィンドウ内で確定できなかった。
  各 slot 専用のデータフロー解析が必要。
- `sel_registerName` に渡されたセレクタ名文字列 (`0x1007bcae8`/`0x1007bdbf0` の呼び出し引数 `x0`) は
  未解決。CFF に埋もれた文字列構築ロジックの追跡が必要。
- `docs/spec/znca_ios_init_gen_audio_h_static.md` §4 に記載の `sysctl` MIB 具体値・`kill` の signal 番号・
  dyld image walk の比較文字列は、本セッションのスコープ (CFF de-flatten) では解決していない
  (別タスク、文字列/定数デコーダの特定が前提)。
- 疑似関数への「明確な分割」は達成できなかった (§1, §4-3 参照)。ゾーンベースの `cfg_zone_*.dot` は
  参考程度に留め、確定的な境界としては扱わないこと。

## 9. 成果物一覧

- `targets/znca_ios_3.4.1/analysis/cff/common.py`
- `targets/znca_ios_3.4.1/analysis/cff/disasm_body.py` (+ `insns.pkl` キャッシュ)
- `targets/znca_ios_3.4.1/analysis/cff/explore_wrapper.py`
- `targets/znca_ios_3.4.1/analysis/cff/find_dispatch.py`
- `targets/znca_ios_3.4.1/analysis/cff/resolve_edges.py`
- `targets/znca_ios_3.4.1/analysis/cff/build_cfg.py` (+ `cfg.pkl`)
- `targets/znca_ios_3.4.1/analysis/cff/export_dot.py` (+ `cfg_full.dot`, `cfg_zone_{x8,x12,x13,x14,x15,x19,x20,x22,x25,x26,x28}.dot`)
- `targets/znca_ios_3.4.1/analysis/cff/list_real_effects.py`
- 本ドキュメント: `docs/spec/znca_ios_init_gen_audio_h_cff.md`
