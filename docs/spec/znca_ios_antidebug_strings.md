# znca iOS 3.4.1 — `+[VoIPClient initGenAudioH]` 本体のアンチデバッグ文字列/定数 解析

対象: `/home/vscode/app/targets/znca_ios_3.4.1/Crew` (Mach-O arm64, `__TEXT` vmaddr = `0x100000000`)
対象範囲: `initGenAudioH` 本体 `0x100783fc8` .. `0x1007d594c` (335 KiB, OLLVM control-flow-flattening 済み単一関数)。

前提となる静的解析結果は [`znca_ios_init_gen_audio_h_static.md`](./znca_ios_init_gen_audio_h_static.md) を参照。本ドキュメントはその §7「未確定」項目を追跡調査した結果。

**方針**: CFF (control-flow flattening) により線形の逆方向レジスタスライスは機能しないため、(a) `movz`/`mov` 直前文脈の静的スキャン（確定的に読める部分のみ）と、(b) Unicorn Engine による実行時エミュレーション（rebase/bind 解決済みフラットイメージ上で `initGenAudioH` 本体を実際に動かし、import stub と raw syscall をフックしてログを取る）の 2 経路を併用した。**CFF 内で追跡しきれなかった項目は推測で埋めず「未確定」と明記する。**

---

## 0. 手法とツール

| スクリプト | パス | 役割 |
|---|---|---|
| `common.py` | `targets/znca_ios_3.4.1/analysis/antidebug/common.py` | lief/capstone ヘルパ (segment 解決, disasm, entropy) |
| `scan_svc_context.py` | `targets/znca_ios_3.4.1/analysis/antidebug/scan_svc_context.py` | 全 35 `svc #0x80` を検出し、直前 14 命令ウィンドウで `x16`/`w16` セット元を特定 (静的) |
| `dump_loop_region.py` | `targets/znca_ios_3.4.1/analysis/antidebug/dump_loop_region.py` | 特定アドレス範囲の逆アセンブルダンプ (汎用) |
| `build_image.py` | `targets/znca_ios_3.4.1/analysis/antidebug/build_image.py` | dyld chained-fixups の rebase/bind を全解決したフラットメモリイメージを構築 |
| `emulate.py` | `targets/znca_ios_3.4.1/analysis/antidebug/emulate.py` | Unicorn Engine で `initGenAudioH` 本体を実行し、import stub 37 種 + raw syscall 10 種 + 未モデル化 external bind (3331 シンボル) をフックしてログを取る |

エミュレーション実行ログ: `/tmp/emu_log.txt` (実行毎に上書き)。過去ラン: `/tmp/emu_run3.txt` (INTERNAL_SKIP 導入後、strlen 系クラッシュ発見前)、`/tmp/emu_run5.txt` (strlen 系クラッシュ修正後、最終到達点)。

### エミュレーション環境の限界（正直な申告）

- x0=self / x1=_cmd はダミー値。呼び出し元 (`+[VoIPClient genAudioH:...]` 等) から渡される実引数は再現していない。
- `pthread_create` はスレッドを実際には起動しない (no-op で成功を返すのみ)。バックグラウンドスレッドが立てるはずのフラグは永遠に立たない。
- `sysctl`/`open`/`access` 等のファイルシステム系 syscall は「クリーンな非 jailbreak 端末」を装う固定応答 (ENOENT 等) を返すのみ。
- 未知の bind シンボル (libc++ 内部関数など 3331 種) は「呼ばれたことをログして 0 を返す」汎用フォールバックで処理しており、実装を再現していない。
- この結果、**あるチェックループの内部で 425M 命令 (実測で 600 秒タイムアウト予算の大半) を消費しても終了しない長大なループに到達し、そこから先 (`getenv`/`dlopen`/`dlsym`/`opendir` の実引数を含む) には到達できなかった**。詳細は §5。

---

## 1. 発見テーブル (呼び出し位置 / API / 引数種類 / 難読化blob位置 / decoder位置 / 平文候補 / 確度)

| 呼び出し位置(VA) | 呼び出しAPI | 引数種類 | 難読化blob位置 | decoder位置 | 平文候補 | 確度 |
|---|---|---|---|---|---|---|
| `0x10079eb20` (svc) | `symlink(path1, path2)` (raw syscall #0x39) | path1: 24byte バイナリ列 (非ASCII), path2: 空文字列 | スタックフレーム内 (`x19` 相対、CFF で動的に選択される複数オフセット。エミュレーションでは `path1` が `88 28 d2 e2 ee ea db 98 8e e6 fc 4a 85 b8 cf 69 34 d9 e2 a0 11 85 3a 9b` として観測) | 未特定。上記バイト列に既知の固定 XOR/rotate をかけても printable にならず、その場でエンコードされた乱数 (uuid 由来のシンボリックリンク名) である可能性が高い | 未確定 (デコード不能。固定リテラルではなく実行時ランダム値の可能性が高いという所見のみ) |
| `0x1007ae4e0` (svc) | `symlink(path1, path2)` (raw syscall #0x39) | 同上 | 同上 (別スタックオフセット) | 未到達 (エミュレーションで未実行) | 未確定 |
| `0x1007c3c5c` 付近 | `getenv(name)` | name: C 文字列ポインタ | CFF 内、実行時にエミュレーションが到達不可 | 未特定 | **未確定** (今回のエミュレーションでも到達できず。ドキュメント既存の「`DYLD_INSERT_LIBRARIES` 推定」は根拠のない推測であり本調査では追認も否定もできない) |
| `0x1007a4b98` 付近 | `dlopen(path, mode)` | path: C 文字列ポインタ | 同上 | 未特定 | 未確定 |
| `0x1007c3f30` 付近 | `dlsym(handle, symbol)` | handle: `RTLD_NEXT` (`movn x0,#1` を静的に確認済み), symbol: C 文字列ポインタ | 同上 | 未特定 | handle=`RTLD_NEXT` の部分のみ**確定** (静的に `movn x0, #1` を確認済み)。symbol 文字列は未確定 |
| `0x1007c199c` | `dladdr(addr, info)` | addr: 実行時アドレス | — | — | 呼び出し自体は確認済み (確定)。用途 (dylib 列挙時の相互チェック) は推定 |
| `0x1007c8bf4`/`0x1007c8bf8` | `_dyld_image_count()` | 引数なし | — | — | 呼び出し自体を動的に確認 (確定)。ret=1 (エミュレーション環境固有: image が 1 個しか無いため) |
| `0x1007c89c0`/`0x1007c89c4` | `_dyld_get_image_name(idx)` | idx: int | — | — | 呼び出し自体を動的に確認 (確定)。比較先の文字列 (`frida`/`substrate` 等) は未到達につき未確定 |
| `0x10079d960` | `CFCopyHomeDirectoryURL()` | 引数なし | — | — | 確定 (動的確認)。ホームディレクトリ URL 取得 |
| `0x1007a19cc` | `CFURLCopyFileSystemPath(url, style)` | — | — | — | 確定 (動的確認) |
| `0x1007a19e8` | `CFStringGetCString(str, buf, bufsize, encoding)` | buf: スタックバッファ (`x19` 相対) | — | — | 確定 (動的確認)。ホームパスをバッファにコピーする処理と判明。`bufsize` 引数は `0x400`。この一連の呼び出し (CFCopyHomeDirectoryURL→CFURLCopyFileSystemPath→CFStringGetCString→CFRelease×2→`__snprintf_chk`) は「ホームディレクトリ相対のパス文字列を構築している」ことは確定だが、構築される具体的なパス (`~/Library/...` 等) は `__snprintf_chk` のフォーマット文字列引数が CFF に埋もれておりエミュレーションでも捕捉できず未確定 |
| `0x1007c9b14` | `kill(pid, sig)` (raw syscall #0x25) | pid: 未追跡レジスタ由来 (下記表参照), **sig: 直前命令 `str wzr, [slot]` により静的に 0 と確定** | — | — | **sig=0 は確定** (静的+動的両方で一致)。pid の値は未確定 (下記参照) |
| `0x1007cc560` | `kill(pid, sig)` (raw syscall #0x25) | 同上 | — | — | 同上、sig=0 確定 |
| `0x1007cdd44` | `kill(pid, sig)` (raw syscall #0x25) | 同上 | — | — | 同上、sig=0 確定 |
| `0x1007ca000`, `0x1007ca4fc`, `0x1007ca6ec`, `0x1007cca8c`, `0x1007ccd3c`, `0x1007cd17c`, `0x1007cdfc0`, `0x1007ce200`, `0x1007ce8d8` (9/10) | `__sysctl(mib, miblen, oldp, oldlenp, newp, newlen)` (raw syscall #0xca) | mib: **`[1, 14, 1, 0]` を動的に確認 (9/10 サイト)** | mib 配列はスタック上 (`x19` 相対、CFF で複数レジスタ経由) | — | **MIB 構造 `{CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1, pid}` は確定** (`kinfo_proc`/`P_TRACED` 型アンチデバッグの典型形。9/10 サイトで完全一致)。ただし **4 番目のワード (pid) が全サイトで `0` として観測されており、これは実機の `getpid()` 実値ではなくエミュレーション上のアーティファクトである可能性が高い**（後述 §4） |
| `0x1007c499c` (10/10 中未到達) | `__sysctl(...)` (raw syscall #0xca) | 同上 (推定) | 同上 | — | 未確定 (今回のエミュレーションでは到達せず、MIB を実測できなかった) |
| `0x1007c4824`, `0x1007c9a74`, `0x1007ccf64`, `0x1007cdce4` | `getpid()` (raw syscall #0x14=20) | 引数なし | — | — | **確定 (静的)**。旧ドキュメントで「movz 検出できず」としていた 4 箇所は、直前の `w16 = w8/w9` (レジスタ間接) を辿ると全て `mov w8, #0x14` (=20=getpid) に帰着することを確認した。すなわちこの 4 箇所は sysctl でも謎の syscall でもなく **raw `getpid()`** |
| `0x7fb000002250` (fakebind cell, 元は `_strlen` の lazy-bind GOT スロット) | `strlen` | ポインタ引数 x0 (エミュレーション観測値 `0x100dad681`, `__TEXT` 領域内の定数アドレス) | — | — | エミュレーション基盤側の課題として発見 (アンチデバッグ本体とは無関係)。`STUBS` テーブルに未収録の libc 関数呼び出しが `__FAKEBIND` の未初期化データセルへ直接分岐してクラッシュしていた。汎用フォールバックフックで解消済み (詳細 §6) |

---

## 2. `sysctl` 全 10 箇所の `movz`/`mov` コンテキストスキャン (静的、確定)

`scan_svc_context.py` の出力から、`svc #0x80` 直前 14 命令内での x16 設定元を全数確認した（想定と異なり **12 ではなく 10 箇所**だった。旧ドキュメントの「12」は誤りで、残る 4 箇所は後述の通り `getpid` である）。

| # | SVC VA | x16 セット元命令 | 値 | miblen セット (`w1`) | MIB (動的観測。9/10) |
|---|---|---|---|---|---|
| 1 | `0x1007c499c` | `0x1007c4998: mov x16, #0xca` | `0xca` (202=`__sysctl`) | `mov w1, w9` (レジスタ由来、未追跡) | 未観測 (到達せず) |
| 2 | `0x1007ca000` | `0x1007c9ffc: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |
| 3 | `0x1007ca4fc` | `0x1007ca4f8: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |
| 4 | `0x1007ca6ec` | `0x1007ca6e8: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |
| 5 | `0x1007cca8c` | `0x1007cca88: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |
| 6 | `0x1007ccd3c` | `0x1007ccd38: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |
| 7 | `0x1007cd17c` | `0x1007cd178: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |
| 8 | `0x1007cdfc0` | `0x1007cdfbc: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |
| 9 | `0x1007ce200` | `0x1007ce1fc: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |
| 10 | `0x1007ce8d8` | `0x1007ce8d4: mov x16, #0xca` | `0xca` | 同上 | `[1, 14, 1, 0]`, miblen=4 |

各サイトの直前 6 命令パターン (10 箇所とも同一構造、代表として `0x1007c499c`):

```
ldr  x8,  [x28, #0xca0]   ; mib pointer  (frame-relative, レジスタは箇所ごとに異なる)
ldr  w9,  [x28, #0xc9c]   ; miblen
ldr  x10, [x28, #0xc90]   ; oldp
ldr  x11, [x28, #0xc88]   ; oldlenp
ldr  x12, [x28, #0xc80]   ; newp
ldr  x13, [x28, #0xc78]   ; newlen
mov  x0, x8
mov  w1, w9
mov  x2, x10
mov  x3, x11
mov  x4, x12
mov  x5, x13
mov  x16, #0xca
svc  #0x80
```

**確定事項**: 10 箇所全てが同一の 6 引数ロードパターンを持ち、`mib`/`oldp`/`oldlenp` 等はすべて frame-relative メモリ (CFF によりベースレジスタが箇所ごとに異なる) からロードされる。9 箇所で動的に MIB 実値 `[1, 14, 1, 0]` (`CTL_KERN, KERN_PROC, KERN_PROC_PID, pid=0`) を確認した。

---

## 3. `kill(pid, sig)` 3 箇所の `w1` (signal) トレース (静的+動的、確定)

3 箇所とも直前のコードで **signal スロットが `str wzr, [slot]` で明示的にゼロクリアされてから w1 にロードされている** ことを確認した。これは推測ではなく逆アセンブル上で直接読める事実。

| SVC VA | pid スロット設定 | sig スロット設定 | 動的観測 |
|---|---|---|---|
| `0x1007c9b14` | `str w11, [x25, #0x760]` (w11 は CFF 上流で未追跡) | **`str wzr, [x25, #0x75c]`** ← 明示的ゼロ | `kill(pid=0x0, sig=0)` |
| `0x1007cc560` | `str w11, [x13, #0xf48]` (同上) | **`str wzr, [x13, #0xf44]`** ← 明示的ゼロ | `kill(pid=0x0, sig=0)` |
| `0x1007cdd44` | `str w8, [x22, #0x218]` (同上) | **`str wzr, [x22, #0x214]`** ← 明示的ゼロ | `kill(pid=0x0, sig=0)` |

**結論 (旧ドキュメントの訂正)**: 旧 `znca_ios_init_gen_audio_h_static.md` §4-2 は「`kill(getpid(), SIGKILL)` あるいは `SIGABRT` と推定」と記していたが、これは誤りである可能性が高い。**この 3 箇所の raw `kill` は signal=0 で固定されており、`kill(pid, 0)` は POSIX 上「シグナルを送らずプロセスの生存確認だけを行う」liveness probe である。** すなわちこの 3 箇所自体は「検出時の self-kill 実行地点」ではなく、**「(おそらく直前で sysctl 等により取得した) 対象 pid が現在も生存しているかを確認するだけの処理」**である可能性が高い。実際の self-kill (もし存在するなら) は別の未発見の経路 (`__stack_chk_fail`, `brk` 2 箇所, あるいは今回到達できなかった残りの CFF パス) にある可能性が高く、**そちらは今回のエミュレーションでも到達できておらず未確定**。

pid の値 (常に `0x0` として観測) はエミュレーションのアーティファクトである可能性が高い。詳細は §4。

---

## 4. `pid` フィールドが常に `0` である理由についての所見 (未確定)

`kill`/`sysctl` の pid フィールドは静的にも動的にも「CFF 上流の未追跡レジスタ由来」であり、追跡を試みたが以下が判明した:

- raw `getpid()` (syscall #0x14=20) の呼び出し箇所は 4 つ確定した (`0x1007c4824`, `0x1007c9a74`, `0x1007ccf64`, `0x1007cdce4`)。
- しかし今回のエミュレーション実行 (`emulate.py`) では、この 4 箇所のいずれも一度も実行されなかった (ログに `getpid` 呼び出しの痕跡なし)。
- つまり、エミュレーションが辿った CFF パス上では、`kill`/`sysctl` に渡される pid フィールドは一度も `getpid()` の戻り値で上書きされておらず、**メモリ初期値 (ゼロ) がそのまま使われた**と考えられる。
- 実機では、同じ経路が実行される前に (エミュレーションでは辿れなかった別の分岐で) `getpid()` が呼ばれ、その結果が該当スロットにキャッシュされている可能性が高い。**したがって「pid=0」は実機の挙動ではなく、今回のエミュレーションが辿ったパスの制約によるアーティファクトである可能性が高いというのが誠実な結論であり、実機の pid 値そのものは未確定。**

---

## 5. エミュレーションで実際に到達できた実行順序 (動的、確定)

`initGenAudioH` 本体をエントリから実行した際に実際に観測された呼び出し順序 (import stub 名 / raw syscall のみ抜粋、mutex/malloc 等の C++ 内部処理は省略):

```
CFCopyHomeDirectoryURL
  → CFURLCopyFileSystemPath
  → CFStringGetCString (buf に "/var/mobile" 相当をコピー、bufsize=0x400)
  → CFRelease ×2
  → __snprintf_chk (フォーマット文字列は未確定)
symlink(path1=24byte非ASCII列, path2="")   ← §1参照、未確定
__error ×5                                  ← errno 参照 (symlink 失敗後の典型パターン)
_dyld_image_count → 1
_dyld_get_image_name → (エミュレーション上のダミーパス)
kill(pid=0, sig=0)                          ← §3参照、確定 sig=0
__sysctl ×3 (mib=[1,14,1,0])                ← §2参照
--- (mutex/malloc/operator_new/operator_new_array 等の C++ オブジェクト構築が多数) ---
strlen ×1, std::__1::random_device 系 ×3    ← C++ 標準ライブラリの乱数エンジン初期化 (§6のクラッシュ修正で到達)
kill(pid=0, sig=0)                          ← 2回目
__sysctl ×3 (mib=[1,14,1,0])                ← 2セット目
--- (再び mutex/malloc/operator_new/uuid_generate 等) ---
kill(pid=0, sig=0)                          ← 3回目 (3箇所全て確認)
__sysctl ×3 (mib=[1,14,1,0])                ← 3セット目
--- ここでチェックサム/整合性検証と推測される長大なループに入り、425,000,000 命令超 (実測タイムアウト予算の大半) を消費しても終了せず ---
```

**`getenv` / `dlopen` / `dlsym` / `opendir` / `readdir` / `objc_getClass` / `pthread_create` は、今回のいずれのエミュレーション実行でも一度も呼ばれなかった。** これらは上記の長大ループのさらに先にあると推定される。

### 5-1. 到達できなかった長大ループの構造所見 (静的、確定できる範囲のみ)

エミュレーションが停止した PC 範囲 (`0x1007cec00`〜`0x1007cf200` 付近) を静的に確認したところ、以下が読み取れた:

- `x22+0x460` を「インデックス」、`x22+0x468` を「終端」として比較しながら 1 バイトずつ処理する古典的なバイトループ構造 (`ldrb`→累積→インデックス+1→比較→分岐) を CFF 越しに確認できる (`0x1007ced48`〜`0x1007ced84` 付近)。
- 累積対象バッファのポインタ (`x22+0x470`) は `x19 + 0x161a0` (関数フレーム内のローカルスタックバッファ) から供給されていることを確認した (`0x1007cf6c4`〜`0x1007cf6c8`)。**すなわちこのループはホワイトボックステーブル領域 (`0x100f70000`..`0x101192000`) を直接舐めているのではなく、スタック上のローカルバッファに対するチェックサム/ハッシュ計算である**ことが確定した (何がそのバッファにコピーされているかは未確定)。
- ループの長さ・終了条件を決める式の一部に、ホワイトボックス領域内の定数 `0x1011239a8` (`__DATA.__data`) への直接参照が 1 箇所存在することを確認した (`0x1007cf35c`〜`0x1007cf364`)。ただしこの値がループの終了条件そのものに使われているのか、単なる補助定数なのかは MBA (mixed boolean arithmetic: `(a & ~b) - (~a & b)` 形式の XOR 難読化) に埋め込まれており、追加のシンボリック実行なしでは確定できない。**未確定。**
- `[x22, #0x468]` (ループ終端) 自体への `str` 命令は関数全体を通してこのベースレジスタでは一度も出現しない (`grep` で確認済み、CFF による別ベースレジスタへのエイリアシングが濃厚)。ただし `0x1007cf3b0`〜`0x1007cf3e8` に、`([x22,#0x43c] << 2)` と `[x22,#0x468]` (loop 終端値そのもの) を比較して分岐する MBA 難読化された等値比較を確認した。**これは確定的に読める事実として**、`[x22, #0x468]` (ループ終端バイト数) は `[x22, #0x43c]` (何らかの「ワード数」カウンタ) の 4 倍と一致するように設計されていることを意味する。ただし `[x22, #0x43c]` 自体の由来 (何をカウントした値か) は本調査では追跡できず未確定。
- したがって「これはホワイトボックステーブルの改ざん検知チェックサムである」という解釈は**推測レベル (中程度の確度)** に留め、確定事実としては書かない。「ループはワード数カウンタの4倍のバイト長を持つバッファをバイト単位で走査し、加算/減算の2アキュムレータに累積している」という構造自体は確定情報として上記の通り記載する。

---

## 6. エミュレーション基盤側の課題と対処 (参考、アンチデバッグ本体とは別件)

`build_image.py` の dyld chained-fixups 解決処理で、`__stubs` に収録されていない libc/libc++ シンボル (`strlen`, `sprintf`, `sscanf`, `std::__1::random_device` のコンストラクタ/`operator()`/デストラクタ等、計 3331 種) への直接呼び出しが、初期化されていない `__FAKEBIND` データセルへ分岐してクラッシュする問題があった。`get_cell_map()` で「セルアドレス→元シンボル名」の対応表を復元し、`__FAKEBIND` 領域全体 (`0x7fb000000000`〜`0x7fb000200000`) にレンジフックを 1 本張って未知の外部呼び出しをすべて「シンボル名をログして 0 を返す」汎用フォールバックにルーティングすることで解消した。個別にアドレス単位でフックを 3331 本張る実装は Unicorn 側のフック探索コストにより実行速度が 40 倍以上悪化したため採用しなかった (詳細は `emulate.py`/`build_image.py` の `get_cell_map`/`hook_generic_fakebind` 実装コメント参照)。

---

## 7. 未確定のまま残る項目 (正直な申告)

以下は本調査でも解決できなかった。想像で埋めていない。

- `getenv`/`dlopen`/`dlsym`/`opendir` に渡される実引数文字列 — **今回のエミュレーションで当該コードパスに到達できなかった**ため、旧ドキュメントの「`DYLD_INSERT_LIBRARIES` 推定」を含め全て未確定のまま。
- dyld image walk (`_dyld_get_image_name` 等) での比較先文字列 (`frida`/`substrate` 等) — 呼び出し自体は確認したが比較先文字列は未確定。
- `symlink()` の path1 引数 (24 バイトの非 ASCII 列) の意味・デコード方法 — 固定 XOR/rotate では printable にならず、実行時ランダム値 (uuid 由来?) である可能性を指摘するに留める。未確定。
- `kill(pid, 0)` に渡る実際の pid 値 — エミュレーションでは終始 `0` だったが、これは §4 で述べた通りアーティファクトの疑いが強く、実機の値は未確定。
- **本当の self-kill (非ゼロ signal) 経路の有無と場所** — 確認できた 3 箇所の `kill` は全て `sig=0` (liveness probe) であることが確定した。旧ドキュメントが想定していた「検出時に SIGKILL/SIGABRT で自殺する」経路は、少なくともこの 3 箇所ではない。他に存在するかどうかは未確定 (`__stack_chk_fail` および `brk` 2 箇所 (`0x1007d98b0`, `0x1007d9a68`) は依然として self-terminate 候補だが、今回追加の解析はしていない)。
- `__sysctl` 10 箇所中 1 箇所 (`0x1007c499c`) の MIB 実値 — 到達できず未確認 (他 9 箇所と同一と推定されるが未確認)。
- §5-1 で触れた長大ループが何を計算しているか (チェックサム/ハッシュか、他の用途か) — 構造の一部 (スタックバッファに対するバイト単位の累積処理、終了条件式にホワイトボックス領域内定数への参照が 1 箇所ある) までは確定したが、意味付けは未確定。

---

## 8. まとめ (今回判明した / 訂正された事実)

| 項目 | 結論 | 確度 |
|---|---|---|
| raw SVC 総数 | **35** (旧ドキュメント通り) | 確定 |
| raw SVC 内訳 | `write`×4, `open`×1, `close`×1, `unlink`×7, `getpid`×4 (新規特定), `access`×3, `kill`×3, `symlink`×2, `__sysctl`×10 (旧ドキュメントの「12」を訂正) | 確定 |
| `kill` の signal 値 | **3 箇所全て `sig=0`** (liveness probe。SIGKILL/SIGABRT ではない) | 確定 (静的+動的一致) |
| `sysctl` の MIB 構造 | `{CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1, pid}` | 確定 (9/10 サイトで動的一致) |
| `sysctl`/`kill` の pid 実値 | 不明 (エミュレーションでは 0 だがアーティファクトの疑い) | 未確定 |
| `getenv`/`dlopen`/`dlsym`/`opendir` の引数文字列 | 到達不能で未確定 | 未確定 |
| dyld walk 比較文字列、symlink path1 のデコード | 未確定 | 未確定 |
| 真の self-kill (非ゼロ signal) 経路 | 未発見 | 未確定 |

---

## 付録: 生成物一覧

- `/home/vscode/app/targets/znca_ios_3.4.1/analysis/antidebug/common.py`
- `/home/vscode/app/targets/znca_ios_3.4.1/analysis/antidebug/dump_func.py`
- `/home/vscode/app/targets/znca_ios_3.4.1/analysis/antidebug/dump_wrapper.py`
- `/home/vscode/app/targets/znca_ios_3.4.1/analysis/antidebug/find_loops.py`
- `/home/vscode/app/targets/znca_ios_3.4.1/analysis/antidebug/scan_svc_context.py`
- `/home/vscode/app/targets/znca_ios_3.4.1/analysis/antidebug/dump_loop_region.py`
- `/home/vscode/app/targets/znca_ios_3.4.1/analysis/antidebug/build_image.py`
- `/home/vscode/app/targets/znca_ios_3.4.1/analysis/antidebug/emulate.py`
