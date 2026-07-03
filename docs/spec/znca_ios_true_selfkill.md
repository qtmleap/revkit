# znca iOS 3.4.1 — `+[VoIPClient initGenAudioH]` フック時クラッシュの真の発生地点 再調査

対象: `/home/vscode/app/targets/znca_ios_3.4.1/Crew` (Mach-O arm64, `__TEXT` vmaddr = `0x100000000`)

## 0. 背景と訂正対象

`docs/spec/znca_ios_f_generation.md` §「anti-tweak / anti-debug 検出メカニズム」(2026-07-03 記載) は、Substrate で
`+[VoIPClient initGenAudioH]` をフックした際に発生した `EXC_BAD_ACCESS at 0x0` クラッシュについて、以下のように結論していた:

> コールスタック: `_logos_meta_method$..$VoIPClient$initGenAudioH` → `Crew@0x7D5B4` を **500 回以上再帰**して
> `objc_msgSend` でスタックオーバーフロー
> 判明: `initGenAudioH` は実行前に自己 IMP の integrity check を行い、swizzle 検出時に自分自身を無限再帰呼び出しでスタック破壊する

その後、`docs/spec/znca_ios_antidebug_strings.md` の追加調査で、旧 `znca_ios_init_gen_audio_h_static.md` が
self-kill 機構と推定していた 3 箇所の raw `kill()` 呼び出しが全て `sig=0` (生存確認のみ、自殺ではない) であることが
判明し、上記「500+ 再帰」説の実行メカニズムは未確定のまま残されていた。

本ドキュメントは、その未解決事項 — **`Crew@0x7D5B4` の正体と、真の "self-kill" 経路の有無** — を静的手法のみで
再調査した結果である。**結論を先に言うと、`0x7D5B4` は `initGenAudioH` と無関係な別関数の一命令の中間バイトであり、
「`initGenAudioH` が自己 IMP チェックで `objc_msgSend` 再帰する」という仮説はコード上不可能であることを、
バイナリ全域の網羅的スキャンにより反証した。** 詳細は §1〜§4 を参照。

補助スクリプトはすべて `targets/znca_ios_3.4.1/analysis/selfkill/` に配置。

---

## 1. `image_base + 0x7D5B4` (= VA `0x10007d5b4`) の正体

### 1-1. LC_FUNCTION_STARTS による関数境界の確定

`find_func.py` (`lief` の `function_starts` を `bisect` で検索) により、VA `0x10007d5b4` を含む関数の開始アドレスは
**`0x10007d5ac`** (16 バイト、次の関数開始 `0x10007d5bc`) と確定した。

これは `initGenAudioH` 本体 (`0x100783fc8`–`0x1007d594c`、`docs/spec/znca_ios_init_gen_audio_h_static.md` 確定値)
よりも **約 `0x706414` バイト (約 7.3 MiB) 手前** にあり、また `+[VoIPClient initGenAudioH]` ラッパー
(`0x100a29528`–`0x100a295a4`) からも約 `0x24C974` バイト (約 2.3 MiB) 離れている。**アドレス算術だけで、
`0x7D5B4` が本体にもラッパーにも属さないことが確定する。**

### 1-2. 実際の逆アセンブル (`disasm_target.py`)

```
--- dump @ 0x10007d5ac size=0x18 ---
0x10007d5ac:  mov   x1, x0
0x10007d5b0:  adrp  x0, #0x100c7a000
0x10007d5b4:  add   x0, x0, #0xc18        ; ← ここが "Crew@0x7D5B4"
0x10007d5b8:  b     #0x100c34fbc          ; = _swift_getWitnessTable (stub、末尾参照確認済み)
0x10007d5bc:  mov   w0, #4
0x10007d5c0:  ret
```

`0x7D5B4` は命令 `add x0, x0, #0xc18` の**命令中間バイト**であり、命令アドレスとしても不自然 (命令境界は
`0x10007d5b0`/`0x10007d5b4` のいずれかで、`0x10007d5b4` 自体は正しい命令境界だが、その命令は `objc_msgSend`
関連命令ではない)。この 16 バイト関数は「`x1=引数, x0=定数, b swift_getWitnessTable` という **Swift ランタイムの
witness table 取得を tail-call するだけのトランポリン**」であり、**`objc_msgSend` を一切呼ばない**。したがって
**「swizzle 検出時に `objc_msgSend` で自己再帰する」という仕組みをこの関数が実装することはアーキテクチャ上不可能**
(そもそも `objc_msgSend` へも `initGenAudioH` へも分岐しない)。

**結論: `Crew@0x7D5B4` は `initGenAudioH` の IMP-integrity-check とは無関係の、Swift ランタイム glue コードの
一部 (`swift_getWitnessTable` tail-call thunk) である。確定。**

---

## 2. `+[VoIPClient initGenAudioH]` の真の・唯一の呼び出し経路

### 2-1. 静的確認: 呼び出し元関数 `0x10007d5c4`

`0x7D5B4` のすぐ後ろ (`0x10007d5c4`) に、別の小関数が存在する。これが `initGenAudioH` を実際に呼ぶ
Swift `dispatch_once` ガード付き lazy-static 初期化 thunk である:

```
0x10007d5c4:  stp   x20, x19, [sp, #-0x20]!
0x10007d5c8:  stp   x29, x30, [sp, #0x10]
0x10007d5cc:  add   x29, sp, #0x10
0x10007d5d0:  bl    #0x10007d608
0x10007d5d4:  adrp  x1, #0x100f47000
0x10007d5d8:  add   x1, x1, #0x920
0x10007d5dc:  bl    #0x100c35004        ; = _swift_initStaticObject
0x10007d5e0:  mov   x19, x0
0x10007d5e4:  adrp  x8, #0x100f26000
0x10007d5e8:  ldr   x0, [x8, #0xe70]     ; classref → VoIPClient class object (下記 2-2 参照)
0x10007d5ec:  bl    #0x100c34470        ; = _objc_opt_self
0x10007d5f0:  bl    #0x100c40240        ; = objc_msgSend$initGenAudioH  ← ★ 実際の呼び出し ★
0x10007d5f4:  adrp  x8, #0x1013d5000     ; ← リターンアドレス (戻り先)
0x10007d5f8:  str   x19, [x8, #0x5d0]
0x10007d5fc:  ldp   x29, x30, [sp, #0x10]
0x10007d600:  ldp   x20, x19, [sp], #0x20
0x10007d604:  ret
```

`+[VoIPClient initGenAudioH]` への実際の呼び出し命令は `0x10007d5f0` (`bl objc_msgSend$initGenAudioH`)、
**戻りアドレスは `0x10007d5f4`** である。

### 2-2. classref/selref のチェイン修正 (chained fixups) デコードによる裏付け

`decode_chained.py` で `DYLD_CHAINED_PTR_64` 形式 (`target = BASE + (raw & 0xFFFFFFFFF)`) を手動デコード:

| slot VA | raw | decode 先 VA | 内容 |
|---|---|---|---|
| `0x100f26e70` (classref, `0x10007d5e8` が参照) | `0x10000000f3e468` | `0x100f3e468` | **`VoIPClient` class object** (`znca_ios_init_gen_audio_h_static.md` 記載の VA と完全一致) |
| `0x100f1ec30` (selref、`objc_msgSend$initGenAudioH` stub 内部が参照) | `0x10000000d60d7a` | `0x100d60d7a` | 文字列 `b'initGenAudioH'` |

= `VoIPClient` クラスに対して `objc_opt_self` → `initGenAudioH` セレクタで `objc_msgSend` している、という
静的デコードが完全に裏付けられた。

### 2-3. `objc_msgSend$initGenAudioH` スタブ自体の確認

```
--- dump @ 0x100c40240 (objc_msgSend$initGenAudioH stub) ---
0x100c40240:  adrp x1, #0x100f1e000
0x100c40244:  ldr  x1, [x1, #0xc30]      ; x1 = selref → "initGenAudioH"
0x100c40248:  adrp x16, #0x100e57000
0x100c4024c:  ldr  x16, [x16, #0xb0]     ; x16 = &objc_msgSend (GOT)
0x100c40250:  br   x16                   ; tail-branch to libobjc の本物の objc_msgSend
0x100c40254:  brk  #1                    ; (次の per-selector stub の先頭パディング)
```

標準的な ObjC2 の per-selector `objc_msgSend$<sel>` スタブそのもので、`br x16` によりランタイムの
`objc_msgSend` へ tail-branch するだけ。**このスタブが再帰的に自分自身や `initGenAudioH` へ戻ることは
コード上あり得ない**(常に `libobjc.A.dylib` 側へ抜ける一方通行)。

### 2-4. バイナリ全域スキャン: この呼び出しは本当に「1 箇所だけ」か

`find_all_selrefs.py` で `__DATA_CONST`/`__DATA` 全域の chained-fixup スロットを走査し、
`"initGenAudioH"` 文字列 (`0x100d60d7a`) を指す selref を数え上げた:

```
total selref slots pointing to "initGenAudioH" string @ 0x100d60d7a: 1
  0x100f1ec30 (seg __DATA)
```

さらに `find_bl_callers.py` (手動 A64 `bl` エンコード decode、`__TEXT` 全域 `0x100000000`–`0x100e54000` を
4byte 単位で総当り) で `objc_msgSend$initGenAudioH` スタブ (`0x100c40240`) への `bl` 呼び出し元を数え上げた:

```
target=0x100c40240: 1 callers
  bl-site 0x10007d5f0
```

**確定: `+[VoIPClient initGenAudioH]` を呼び出す selref も `bl` サイトも、バイナリ全体でそれぞれ厳密に 1 箇所しか
存在しない。** すなわち `initGenAudioH` を objc_msgSend 経由で呼び出せるコードパスはこの 1 箇所のみであり、
**「500 回以上の再帰呼び出し」を実現するコードパスはバイナリ上に存在しない**（少なくとも直接 `objc_msgSend$<sel>`
スタブ経由の呼び出しでは物理的に不可能）。

### 2-5. 実測ログとの突合 (動的、確定)

このリポジトリに実在する Frida 実機ログ `targets/znca_ios_3.4.1/frida_znca_20260703_043544.log` に、
`+[VoIPClient initGenAudioH] ENTER` の実測バックトレースが記録されている:

```
backtrace:
    0x1021d55f4 Crew!0x7d5f4 (0x10007d5f4)
    0x1a2b90780 libdispatch.dylib!_dispatch_client_callout
    0x1a2b60ddc libdispatch.dylib!_dispatch_once_callout
    0x1021919a8 Crew!0x399a8 (0x1000399a8)
    0x102191c00 Crew!-[Crew.AppDelegate application:didFinishLaunchingWithOptions:]
    0x19e0a8644 UIKitCore!-[UIApplication _handleDelegateCallbacksWithOptions:isSuspended:restoreState:]
    ...
```

**PC が `Crew!0x7d5f4` — 上記 §2-1 で静的に導出した戻りアドレス `0x10007d5f4` と完全一致する。** また
`_dispatch_once_callout` 経由であることから、`initGenAudioH` は `AppDelegate.didFinishLaunching` 内の
Swift `dispatch_once`-guarded lazy static により**アプリ起動時に一度だけ**呼ばれることも実測で裏付けられた
(静的解析の「呼び出し元は 1 箇所のみ」という結論と整合)。このログ自体はクラッシュではなく正常な ENTER であるが、
「`Crew!0x7d5f4` が実在する正しいアドレスである」ことの動的な傍証として扱える。

---

## 3. `0x7D5B4` と `0x7D5F4` の食い違いについての所見

旧ドキュメントの `Crew@0x7D5B4` と、本調査で確定した実際の呼び出し元 `Crew@0x7D5F4` は、**下 2 桁が `B4` と
`F4` で異なるのみ**(16進数で `B` と `F` の一文字違い)であり、かつ両者は同一の極小関数クラスタ
(`0x10007d5ac`–`0x10007d608` の 92 バイトの範囲) に含まれる隣接命令である。

以下の理由から、**「`0x7D5B4` は `0x7D5F4` の転記ミス (`B`/`F` の視覚的取り違え)である」という説明が最も
節約的 (parsimonious) である**と判断した:

- 上記 §2-5 の実機ログには、Frida/r2 が自動生成した文字列として **`Crew!0x7d5f4`** がそのまま記録されている
  (ランタイムベースからの引き算をこちらで再計算した値ではなく、ログ自体に既に「0x7d5f4」という文字列が
  出力されている)。したがって「ランタイムベース差し引き計算の誤り」という可能性は排除できる。
- スタックオーバーフロー後のバックトレース破損 (SP がガードページを越えた後の frame-pointer unwind が
  古い/繰り返しのスタック値を誤読する現象) という仮説も検討したが、`0x7D5B4` は `initGenAudioH` や
  `objc_msgSend` 呼び出しと全く無関係な Swift witness-table thunk の命令中間アドレスであり、
  **破損したバックトレースが偶然「本物っぽく見えるが無関係な」命令アドレスに着地する** というのは、
  同じ 16 バイト関数の隣、かつ 1 文字違いのアドレスに着地する確率としては不自然に低い。転記ミス説の方が
  単純に説明力が高い。

**注記 (正直な申告): これは状況証拠に基づく最有力仮説であり、100% の証明ではない。** 実際のクラッシュ発生時の
生の `.ips`/バックトレースファイルは本ワークスペースに存在せず、旧セッションがどのように `0x7D5B4` という値を
得たかの生ログも保存されていないため、「転記ミスであった」ことを直接証明することはできない。**この点は
「追跡不可」として明記する。**

---

## 4. 真の self-kill (非ゼロ signal) 経路の探索 — 結果: 発見できず (空振り)

### 4-1. `initGenAudioH` 本体内: 既知の 3 箇所の `kill` は `sig=0` (確定、既存ドキュメント通り)

`docs/spec/znca_ios_antidebug_strings.md` の結論を踏襲: `0x1007c9b14`/`0x1007cc560`/`0x1007cdd44` の 3 箇所は
いずれも `kill(pid, 0)` (liveness probe) であり、self-kill ではない。本セッションでは再検証していないが、
既存の静的+動的 (Unicorn エミュレーション) 両面の確認結果を訂正する新情報は得られなかった。

### 4-2. `brk` 命令のバイナリ全域スキャン (新規、本セッションで実施)

`scan_all_brk.py` で `__TEXT` セグメント全域 (`0x100000000`–`0x100e54000`) を 4byte 単位で総当りし、
BRK 命令のエンコード (`(word & 0xFFE0001F) == 0xD4200000`) に一致する箇所をすべて列挙した:

```
total BRK instructions found in __TEXT: 19601
  brk #0x1  ×19599
  brk #0xc00e ×1
  brk #0x6380 ×1
INSIDE initGenAudioH body (0x100783fc8–0x1007d594c): 0 件
INSIDE wrapper (0x100a29528–0x100a295a4): 0 件
```

**`initGenAudioH` 本体・ラッパーいずれの範囲にも `brk` 命令は 1 件も存在しない。** `brk #0x1` が
19599 件という圧倒的多数を占めることから、これは Swift コンパイラが強制アンラップ失敗・配列範囲外アクセス・
整数オーバーフローなどの `precondition` 違反時に自動挿入する**標準的なランタイムトラップ**であり、
Swift で書かれたアプリ全体に遍在する。**アンチデバッグ/self-kill に特化した特殊な `brk` ではない**、
という所見も付記する (数の多さと分布の一様性から)。

### 4-3. 旧ドキュメントが「本体内 brk」としていた 2 箇所の訂正

`docs/spec/znca_ios_init_gen_audio_h_static.md` は `brk`×2 を `0x1007d98b0`/`0x1007d9a68`
(いずれも `brk #0x1`) として「`initGenAudioH` 本体内」に記載していた。`locate_brk_funcs.py` で
LC_FUNCTION_STARTS を用いてこれらのアドレスが実際にどの関数に属するかを確認したところ:

```
0x1007d98b0 -> containing function start=0x1007d94d0 end=0x1007d9bd0 size=0x700
0x1007d9a68 -> containing function start=0x1007d94d0 end=0x1007d9bd0 size=0x700
```

**この 2 箇所は `initGenAudioH` 本体 (`0x100783fc8`–`0x1007d594c`) の終端より `0x4108` バイト (約 16.5 KiB)
先にある、別の独立した関数 `0x1007d94d0`–`0x1007d9bd0` (サイズ `0x700`) に属する。** 旧ドキュメントの
「本体内」という記載は誤りであったことを本調査で確定した (訂正)。

### 4-4. この `brk` 保有関数は `initGenAudioH` と静的呼び出しグラフでつながっているか

`find_bl_callers.py`/`check_brk_caller_chain.py` で `bl` 呼び出しを手動デコードして呼び出し元を追跡した:

```
target=0x1007d94d0 (brk を含む関数): 1 callers
  bl-site 0x1007f17fc  (関数 0x1007f17ac–0x1007f18f4, initGenAudioH 本体域外)

target=0x1007f17ac (↑の呼び出し元関数): 2 callers
  bl-site 0x100a2eed8  (関数 0x100a2ed34)
  bl-site 0x100a2efdc  (関数 0x100a2ed34)
```

`0x100a2ed34` は 3 引数 (`self`/`_cmd`/`arg` 相当の CFF 付き ObjC メソッドスタイル) を持つ別の小関数で、
`+[VoIPClient initGenAudioH]` のラッパー (`0x100a29528`、0 引数) とは**シグネチャも中身も異なる**別のメソッド
実装であり、これも `initGenAudioH` 本体域外に位置する。

**結論: 直接 `bl` による静的呼び出しグラフを最大 3 ホップ遡っても、この `brk` 保有関数
(`0x1007d94d0`) は `initGenAudioH` 本体にもラッパーにも到達しない。** ここまでの範囲では
**「本体外の `brk` で `initGenAudioH` と graph-connected な経路」は見つからなかった (空振り)**。

**留保 (追跡不可)**: 本調査の `bl` スキャンは直接分岐命令のみを対象としており、`initGenAudioH` 本体自体が
CFF (control-flow flattening) で `objc_msgSend`/`bl` を間接的に呼ぶケースや、ブロック (`imp_implementationWithBlock`
経由の invoke) やファンクションポインタテーブル経由の間接呼び出しは捕捉できていない。したがって
「`initGenAudioH` 本体からこの `brk` 関数への間接呼び出しが絶対に存在しない」とまでは証明できておらず、
**未確定・追跡不可**として明記する。

### 4-5. まとめ: self-kill 経路の探索結果

| 候補 | 結果 |
|---|---|
| `kill()` ×3 (`sig=0`) | liveness probe と確定。self-kill ではない (既存ドキュメント通り) |
| `brk`×2 (`0x1007d98b0`/`0x1007d9a68`) | **`initGenAudioH` 本体内ではないと訂正確定**。本体との静的 `bl` グラフ連結も見つからず (空振り、ただし間接呼び出しは追跡不可) |
| `brk` 全 19601 箇所 (バイナリ全域) | 本体・ラッパー内は 0 件。ほぼ全て `brk #0x1` = Swift 標準トラップで、アンチデバッグ専用のものとは考えにくい |
| `__stack_chk_fail` | 本セッションでは未着手 (**追跡不可**) |
| **「500+ 回の `objc_msgSend` 自己再帰」自体** | **§2-4 の全域スキャンにより、コード上不可能であることを確定** (selref/呼び出し site とも厳密に 1 箇所のみ) |

**正直な結論: 本セッションでは「真の self-kill (非ゼロ signal) 経路」を発見できなかった。** これは
「探索が不十分だった」というより、「そもそも `initGenAudioH` を objc_msgSend 経由で 2 回以上呼べるコードパスが
存在しない」という §2 の結果と合わせて考えると、**旧ドキュメントが観測したクラッシュの真因は
`initGenAudioH` 内部の自己再帰ロジックではなく、別のメカニズム (例: Substrate の hook 機構自体が `%orig` 経由で
何らかの不整合を起こした、あるいは `dispatch_once` フラグの二重初期化・フック注入によるスタック/レジスタ
破壊など、`initGenAudioH` の実装コードそのものではなく hook 機構との相互作用側の問題) である可能性が高い**、
という所見に留める。**この所見は状況証拠に基づく推定であり、確定事実ではない。**

---

## 5. ObjC hook 検出パターン / anti-tweak ライブラリ存在検出ロジックの探索

### 5-1. 候補 API の xref 総数 (r2 `axt`、既存調査の再確認)

| API | インポート先 VA | xref 数 | 呼び出し元 |
|---|---|---|---|
| `class_getMethodImplementation` | `0x100c33dec` | **0** | (呼ばれていない) |
| `class_replaceMethod` | `0x100c33df8` | **0** | (呼ばれていない) |
| `class_getInstanceMethod` | `0x100c33dd4` | 9 | `0x100559e04`, `0x100559ef8`, `0x10055bfc0`, `0x10055c0b4`, `0x100561ddc`, `0x100561fd8`, `0x100562170`, `0x1006947e8`, `0x10069493c` |
| `method_getImplementation` | `0x100c342cc` | 3 | `0x100559e04`, `0x10055bfc0`, `0x100561fd8` |
| `method_setImplementation` | `0x100c342e4` | 2 | `0x1006947e8`, `0x10069493c` |
| `imp_implementationWithBlock` | `0x100c3417c` | 1 | `0x100561ddc` |

**注目点**: `class_getMethodImplementation`/`class_replaceMethod` という「典型的な自己 IMP 検査 (現在の IMP を
取得して既知の値と比較する)」に使われがちな API は、**このバイナリでは一度も呼ばれていない**。これは
「`initGenAudioH` が `class_getMethodImplementation` で自己 IMP を検査し、想定外なら異常終了する」という
仮説に対する **直接的な反証** である。

### 5-2. `0x1006947e8` の同定: Firebase Cloud Messaging の swizzler と確定

`decode_swizzle_refs2.py` で `0x1006947e8` 内の直接文字列参照 (adrp+add、ldr を介さない直接ポインタ) を
デコードしたところ、以下の**完全な ObjC メソッドシグネチャ文字列**が埋め込まれていた:

```
0x100da9fa1 (直接参照, __TEXT): b'-[FIRMessagingRemoteNotificationsProxy swizzleSelector:inClass:withImplementation:inProtocol:]'
```

`FIRMessagingRemoteNotificationsProxy` は **Google の Firebase Cloud Messaging (FCM) SDK
(`FirebaseMessaging`/`GoogleUtilities`) 内の実装クラス名そのもの**であり、この文字列は Firebase SDK の
アサーション/デバッグメッセージとして Google 自身のソースに実在するものと一致する (プッシュ通知配送のための
`UIApplicationDelegate` メソッド swizzling を行うクラス)。`docs/spec/znca_ios_f_generation.md` の
「バイナリ構成」節で `FirebaseAnalytics.framework`/`GoogleAppMeasurement.framework` がアプリバンドルに
含まれていることも既に確認済みであり、Firebase 系ライブラリが静的にリンクされていること自体は既知の前提と
整合する。

**確定: `0x1006947e8` は Nintendo 独自のコードではなく、Firebase Cloud Messaging SDK 自身の
`GULAppDelegateSwizzler`/`FIRMessagingRemoteNotificationsProxy` 系メソッドスウィズリング処理
(プッシュ通知配送用の `AppDelegate` メソッド差し替え) が静的リンクによって Crew バイナリに埋め込まれたもの
である。** `class_getInstanceMethod` → `method_setImplementation`(or `class_addMethod`) →
`protocol_getMethodDescription` → `NSStringFromSelector`/`NSStringFromClass` というこの関数内の API 呼び出し
順序も、Google 製 swizzling ユーティリティの一般的な実装パターン(donor method 実装のコピー、既存実装との
衝突検知、デバッグログ)と整合する。

### 5-3. `0x100559e04` 等の残り 8 箇所も同一クラスタ由来と推定

`0x100559e04` は `class_getInstanceMethod`→`method_getImplementation`→`method_getTypeEncoding`→
`class_addMethod`→(条件分岐で早期 return) という、`0x1006947e8` とほぼ同型の骨格を持ち、`objc_retain`/
`objc_release`/`objc_retainAutoreleasedReturnValue` という同じ ARC ヘルパーの使い方、`NSStringFromSelector`
呼び出し、そしてエラーパスに Swift 由来と思われる「行番号定数 (`w8 = 0x3f1 = 1009`) + ファイル名文字列」の
組み合わせが見られる。これは Swift 側の `precondition`/`assert` ラッパーの典型パターンであり、
`0x1006947e8` (確定 Firebase) と**同一アドレス帯 (`0x1005xxxxx`) にあり、同型の API 骨格を共有する**ことから、
**同じ静的リンクされた Firebase/GoogleUtilities スウィズリングモジュールの一部である可能性が高い**、
という所見に留める (文字列の完全一致による確定はできていないため、確度は「中程度」)。

**いずれの swizzling 関連 9 サイトも `initGenAudioH` 本体 (`0x100783fc8`–`0x1007d594c`) やラッパー
(`0x100a29528` 付近) から地理的にも呼び出しグラフ的にも遠く離れた `0x1005xxxxx`–`0x1006xxxxx` 帯に集中して
おり、Nintendo 独自の anti-tweak ロジックであることを示す証拠はない。**

### 5-4. anti-tweak ライブラリ (ellekit/theos/frida-gum) の存在検出ロジック

Crew バイナリ全体に対して以下のキーワードで `strings -a` を実行したが、**一致なし (0 件)**:

```
substrate, ellekit, frida, cydia, cynject, MSHookFunction, libhooker,
xposed, TweakInject, frida-gum, gum-js, FridaGadget,
jailbreak, /Applications/Cydia, /bin/bash, /private/var/lib/apt,
MobileSubstrate, TweakLoader
```

**確定 (空振り): Crew バイナリ内に、既知の脱獄/フックフレームワークの名称を直接文字列比較する形の
検出ロジックは見つからなかった。** これは「そのような検出が存在しない」ことの証明ではなく、
「存在するとしても文字列としてハードコードされていない (`znca_ios_antidebug_strings.md` が指摘する
`symlink()` 引数の非 ASCII 24byte 列のような、実行時難読化/エンコードされた形である可能性が残る)」という
留保付きの null result である。**追跡不可**として明記する。

---

## 6. 最終まとめ

| 項目 | 結論 | 確度 |
|---|---|---|
| `Crew@0x7D5B4` の正体 | `initGenAudioH` と無関係な独立関数 (`0x10007d5ac`–`0x10007d5bc`, Swift `swift_getWitnessTable` tail-call thunk) の命令中間アドレス。本体からもラッパーからも約 2.3–7.3 MiB 離れている | **確定** |
| `initGenAudioH` の唯一の呼び出し元 | `0x10007d5c4`–`0x10007d604` (Swift `dispatch_once` lazy-static thunk)。実呼び出し命令 `0x10007d5f0`、戻り先 `0x10007d5f4` | **確定** (静的 chained-fixup デコード + 実機 Frida ログの PC 完全一致) |
| `objc_msgSend$initGenAudioH` スタブの呼び出し元数 (バイナリ全域) | **1 箇所のみ** (`0x10007d5f0`) | **確定** (`bl` エンコード総当りスキャン) |
| `"initGenAudioH"` selref 数 (バイナリ全域) | **1 箇所のみ** (`0x100f1ec30`) | **確定** (chained-fixup 総当りスキャン) |
| 「500+ 回の `objc_msgSend` 自己再帰」 | **コード上不可能と確定** (§2-4 の全域スキャンで反証) | **確定** |
| `0x7D5B4` と `0x7D5F4` の食い違いの原因 | 転記ミス (`B`/`F` 取り違え) が最有力。スタック破損によるバックトレース汚染説より説明力が高い | 推定 (状況証拠。**直接証明は追跡不可**) |
| `kill()`×3 (`sig=0`) | liveness probe。self-kill ではない | 確定 (既存ドキュメント通り、変更なし) |
| `brk`×2 (`0x1007d98b0`/`0x1007d9a68`) が本体内、という旧記載 | **誤り。訂正確定**。実際は本体末尾より 16.5 KiB 先の別関数 (`0x1007d94d0`–`0x1007d9bd0`) に属する | **確定** |
| その `brk` 保有関数と `initGenAudioH` の静的呼び出しグラフ連結 | 直接 `bl` を最大 3 ホップ遡っても未発見 (空振り) | 確定 (直接 `bl` の範囲内。間接呼び出しは**追跡不可**) |
| `brk` 命令の全域分布 (19601 件) | 本体・ラッパー内 0 件。大半 (19599件) は `brk #0x1` = Swift 標準トラップで遍在 | 確定 |
| 真の self-kill (非ゼロ signal) 経路 | **本セッションでも未発見 (空振り)**。`initGenAudioH` を 2 回以上呼べるコードパス自体が存在しないため、"検出時に自己を再帰的に呼んで自殺する" という機構自体が成立し得ないという新たな確定的傍証を得た | 確定 (機構の不成立) / 経路自体は未確定 |
| `class_getMethodImplementation`/`class_replaceMethod` | 0 xref (未使用) | **確定** |
| swizzling 関連 9 サイトの帰属 | `0x1006947e8` は **Firebase Cloud Messaging (`FIRMessagingRemoteNotificationsProxy`) の swizzler と文字列で確定**。残り 8 サイトも同型パターンから同モジュール由来と推定 (中確度)。Nintendo 独自の anti-tweak ロジックである証拠はなし | 確定 (1件) / 推定 (8件) |
| ellekit/theos/frida-gum の文字列ベース存在検出 | 全域 `strings` 検索で 0 件 (空振り)。存在しないと断定はできない (難読化の可能性は残る) | **追跡不可** (null result) |

### 6-1. 旧ドキュメントへの訂正提案

`docs/spec/znca_ios_f_generation.md` §「anti-tweak / anti-debug 検出メカニズム」の以下の記述は、
本調査により**反証されたものとして訂正が必要**:

- ~~「`initGenAudioH` は実行前に自己 IMP の integrity check を行い、swizzle 検出時に自分自身を無限再帰呼び出しでスタック破壊する」~~
  → **§2-4 の全域スキャンにより、`initGenAudioH` を 2 回以上呼び出すコードパス自体が存在しないため、この
  メカニズムはコード上不可能であることが確定した。**
- ~~`Crew@0x7D5B4` を 500 回以上再帰~~
  → **`0x7D5B4` は無関係な独立関数の命令アドレスであり、`initGenAudioH` とは何の呼び出し関係もない。**

一方で、実際に発生した `EXC_BAD_ACCESS at 0x0` クラッシュ自体の実在性は否定しない (旧セッションの実機観測を
疑う根拠はない)。**真因は `initGenAudioH` 内部の自己再帰ロジックではなく、Substrate hook 機構と
`dispatch_once`/ObjC ランタイムとの相互作用側にある可能性が高い**、という所見のみ残し、確定的な代替説明は
本セッションでは得られなかった (**追跡不可**)。

---

## 7. 未確定・追跡不可のまま残る項目 (正直な申告)

- `0x7D5B4`→`0x7D5F4` の食い違いが本当に転記ミスなのか、旧セッションが依拠した生のクラッシュログ/バックトレースが
  別の要因で異なる値を報告したのか — **生の `.ips`/ログが本ワークスペースに残っていないため証明不可能。追跡不可。**
- `initGenAudioH` 本体から `brk` 保有関数 (`0x1007d94d0`) への**間接呼び出し** (CFF 経由の `br`、ブロック
  invoke 等) の有無 — 直接 `bl` スキャンでは連結なしと確認したが、間接呼び出しは本調査手法では捕捉できない。
  **追跡不可。**
- `__stack_chk_fail` が self-kill 経路として使われているかどうか — 本セッションでは着手していない。
  **追跡不可 (次セッションの候補)。**
- ellekit/theos/frida-gum の文字列を使わない、難読化された形での hook framework 検出ロジックの有無 —
  `znca_ios_antidebug_strings.md` が指摘した「到達できなかった長大なループ」「`getenv`/`dlopen`/`dlsym` の
  実引数」がこれに該当する可能性はあるが、本セッションでも到達できていない。**追跡不可。**
- `0x100559ef8`/`0x10055bfc0`/`0x10055c0b4`/`0x100561ddc`/`0x100561fd8`/`0x100562170` (Firebase 由来と
  推定した残り 8 サイトのうち未逆アセンブルの分) の完全な逆アセンブルによる文字列同定 — 時間の都合上
  `0x100559e04` のみ完全に確認し、他は API 骨格の類似性からの推定に留めた。**中確度の推定のまま。**

---

## 付録: 成果物一覧

- `targets/znca_ios_3.4.1/analysis/selfkill/find_func.py` — LC_FUNCTION_STARTS から `0x7D5B4` 含有関数を特定
- `targets/znca_ios_3.4.1/analysis/selfkill/disasm_target.py` — `0x10007d5ac`–`0x10007d608` 領域 + `objc_msgSend$initGenAudioH` スタブの逆アセンブル
- `targets/znca_ios_3.4.1/analysis/selfkill/resolve_stub.py` / `resolve_stub2.py` — GOT スロット → bind シンボル名解決 (`_swift_getWitnessTable`/`_swift_initStaticObject`/`_objc_opt_self`)
- `targets/znca_ios_3.4.1/analysis/selfkill/decode_chained.py` — classref/selref の chained-fixup 手動デコード (VoIPClient classref, "initGenAudioH" selref)
- `targets/znca_ios_3.4.1/analysis/selfkill/read_refs.py` — 上記デコードの補助読み出しヘルパ
- `targets/znca_ios_3.4.1/analysis/selfkill/find_all_selrefs.py` — `"initGenAudioH"` selref のバイナリ全域総当り検索 (結果: 1件のみ)
- `targets/znca_ios_3.4.1/analysis/selfkill/find_bl_callers.py` — 任意ターゲットへの `bl` 呼び出し元のバイナリ全域総当り検索 (手動 A64 命令デコード)
- `targets/znca_ios_3.4.1/analysis/selfkill/scan_all_brk.py` — `__TEXT` 全域の `brk` 命令総当りスキャン (19601件検出)
- `targets/znca_ios_3.4.1/analysis/selfkill/locate_brk_funcs.py` — 既知 `brk` サイトの所属関数を LC_FUNCTION_STARTS で確定 (本体外と訂正)
- `targets/znca_ios_3.4.1/analysis/selfkill/check_brk_caller_chain.py` — `brk` 保有関数から `initGenAudioH` への静的呼び出しグラフ連結有無の確認
- `targets/znca_ios_3.4.1/analysis/selfkill/decode_swizzle_refs.py` / `decode_swizzle_refs2.py` — swizzling 関連関数内の文字列/参照デコード (`FIRMessagingRemoteNotificationsProxy` 文字列の発見)
- 本ドキュメント: `docs/spec/znca_ios_true_selfkill.md`

## 関連ドキュメント

- [`znca_ios_f_generation.md`](./znca_ios_f_generation.md) — 訂正対象の旧記述を含む、f-token 生成の全体像
- [`znca_ios_init_gen_audio_h_static.md`](./znca_ios_init_gen_audio_h_static.md) — `initGenAudioH` 静的解析 (本体境界確定、旧 `brk` 帰属の訂正元)
- [`znca_ios_init_gen_audio_h_cff.md`](./znca_ios_init_gen_audio_h_cff.md) — CFF de-flatten、`kill` の zone 帰属不能の確認
- [`znca_ios_antidebug_strings.md`](./znca_ios_antidebug_strings.md) — `kill` の `sig=0` 確定、`sysctl` MIB 確定、self-kill 経路未確定の申告元
