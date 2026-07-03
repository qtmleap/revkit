# znca iOS 3.4.1 `_gen_audio_h` 内部構造リバース

- 対象バイナリ: `/home/vscode/app/targets/znca_ios_3.4.1/Crew` (arm64 Mach-O, znca/Nintendo Switch Online iOS 3.4.1)
- 対象関数: `_gen_audio_h` VA `0x10090f20c` - `0x100a208fc`（サイズ `0x1116f0` = 1,120,496 バイト ≈ 1.07 MiB、命令数 279,996、`_gen_audio_h2` とテール結合）
- 前提ドキュメント: `docs/spec/znca_ios_whitebox_layout.md`, `docs/spec/znca_ios_f_generation.md`
- 使用ツール: Python + capstone（4byte固定スロット逐次デコード）、CFF deflatten ツールチェーン（`analysis/cff/*.py` を移植した `analysis/gen_audio_h/*.py`）、lief（Mach-O / bindings 解決）
- 制約: 追跡不可の項目は「追跡不可」と明記し、推測では埋めない。

新規スクリプト一式: `/home/vscode/app/targets/znca_ios_3.4.1/analysis/gen_audio_h/`
（`common.py`, `disasm_body.py`, `find_dispatch.py`, `resolve_edges.py`, `build_cfg.py`, `trace_simd_loads.py`,
`dump_simd_zone_ops.py`, `find_blob_touch_range.py`, `find_sha256_calls.py`, `scan_k_table_refs.py`,
`check_imports_and_bl_targets.py`, `resolve_stub_targets.py`, `find_pthread_create.py`,
`inspect_thread_routine.py`, `resolve_thread_routine_calls.py`）

## 0. 関数の基本構造（前提の再確認）

プロローグ (func+0x0 〜 func+0x24):

```
stp x28, x27, [sp, #-0x60]!
stp x26, x25, [sp, #0x10]
stp x24, x23, [sp, #0x20]
stp x22, x21, [sp, #0x30]
stp x20, x19, [sp, #0x40]
stp x29, x30, [sp, #0x50]
add x29, sp, #0x50
sub sp, sp, #0x45, lsl #12      ; -0x45000
sub sp, sp, #0x380              ; -0x380
mov x19, sp                     ; x19 = 呼び出しごとのフレームベース
```

- ローカルスタックフレームは **0x45380 バイト（283,520 バイト、約 276.9 KiB）** の巨大な領域。
- `x19 = sp`（サブ2回適用後）を全編を通した基準レジスタとして使用。`x29 = x19 + 0x453d0`（旧sp+0x50）。
- 以降、x20〜x28・x15 等の「エイリアスレジスタ」が `add xD, x19, #H, lsl#12` + `add xD, xD, #L` の2命令ペアでプロローグ直後に多数構築される（func+0x28〜）。CFF (Control-Flow-Flattening) による分岐先の中でも同型の `add` ペアが繰り返し出現する。
- CFF 統計（`find_dispatch.py` / `resolve_edges.py` / `build_cfg.py` の結果）:
  - dispatch サイト 1965（Type B 直接 858 + Type A 間接 1107）、distinct state slot 1313
  - 書き込み（edge）総数 2889、うちコンパイル時定数に解決できたもの 2203、**解決不能（動的/データ依存）686 件（23.7%）**
  - pseudo-block（leader）37,439、CFF 分岐エッジ 7376、動的エッジ 686、invalid 381、直接分岐 28,161、`bl` 呼び出しサイト 573（distinct 呼び出し先 64）
  - `initGenAudioH`（先行セッションの `analysis/cff/`）の動的エッジ比率 ~1.8% と比べて `_gen_audio_h` は 23.7% と大幅に高く、より入力依存の強い分岐構造を持つ。

---

## 1. SIMD `ldr qN, [Xbase, Xindex]` 8箇所のベースレジスタ追跡

前セッションの `scan_gen_audio_h_refs.py` が検出した「レジスタ+レジスタ形式の 128bit ロード」8箇所すべてについて、`trace_simd_loads.py`（CFG述語ウォークによる後方レジスタ定義追跡、CFF解決済みエッジのみを辿る）で base/index レジスタの由来を特定した。結果は全件、**whitebox blob（`0x100f70000`-`0x101192000`）ではなく `x19`（= 呼び出し毎スタックフレーム）由来**であり、事前仮説（blob直接インデックス）は明確に反証された。

| # | site (VA) | func offset | base 構成 | base = x19+offset | index 構成 |
|---|---|---|---|---|---|
| 1 | 0x10095c6c8 | +0x4d4bc | `add x9,x19,#0x43,lsl#12` / `add x9,x9,#0x68` | **x19+0x43068** | `lsl x8,x11,#3` |
| 2 | 0x1009e73b0 | +0xd81a4 | `add x9,x19,#0x44,lsl#12` / `add x9,x9,#0x5c8` | **x19+0x445c8** | `lsl x8,x11,#3` |
| 3 | 0x1009ec2e0 | +0xdd0d4 | `add x9,x19,#0x3b,lsl#12` / `add x9,x9,#0xf8c` | **x19+0x3bf8c** | `lsl x8,x11,#3` |
| 4 | 0x1009ece78 | +0xddc6c | `add x9,x19,#0x3c,lsl#12` / `add x9,x9,#0xc` | **x19+0x3c00c** | `lsl x8,x11,#3` |
| 5 | 0x1009ef5a4 | +0xe0398 | `add x10,x19,#0x3b,lsl#12` / `add x10,x10,#0xfcc` | **x19+0x3bfcc** | `lsl x9,x8,#3` |
| 6 | 0x100a0d8d4 | +0xfe6c8 | `ldr x9,[x19,#0x49f8]`（ポインタ間接） | **x19+0x49f8 の中身**（未解決） | CFFの分岐先2系統で `mov x8,#0` または `ldr x8,[x19,#0x4a28]` — **実行時パス依存（動的）** |
| 7 | 0x100a1cdac | +0x10dba0 | `sub x9,x29,#0xa8` = x19+0x453d0-0xa8 | **x19+0x45328** | `lsl x8,x11,#3` |
| 8 | 0x100a1dff8 | +0x10edec | `ldr x8,[x19,#0x11c8]`（ポインタ間接） | **x19+0x11c8 の中身**（未解決） | CFF述語チェーンを4ホップ遡っても predecessor が尽き `UNRESOLVED(no predecessors found)` — **追跡不可** |

観測事実:

- 8箇所中 **6箇所**（#1-5, #7）は `x19` からの直接オフセットで、その値はフレーム末尾寄りの狭い帯 **`[0x3bf8c, 0x45328]`（約 37.8 KiB, フレーム全体 276.9 KiB の末尾約 13.6%）** に集中する。
- 残り **2箇所**（#6, #8）は `x19+0x49f8` / `x19+0x11c8` という、フレーム冒頭寄り（それぞれオフセット 18,936 / 4,552 バイト）の**ポインタスロット**から値をロードし、それを base として使う間接参照。このポインタの指す先（whitebox blob 内か、フレーム内の別領域か、ヒープか）は **本セッションでは追跡不可**。
- index レジスタは全 8 箇所とも `xN << 3`（8バイト単位）。読み出しは 128bit（16バイト）幅なので、**8バイト刻みの隣接2エントリをまとめて1回のSIMDロードで取得する**アクセスパターンになっている（AES系Tテーブル実装で隣接2ワードをまとめて読む手法に外形的に類似するが、内容がテーブルであることを裏付けるデータ検証は本セッションでは未実施 — 外形パターンの指摘に留める）。
- `[0x3bf8c, 0x45328]` 帯を x19 リテラルオフセットで書き込む命令は関数全体を通して **0件**（3658件の全 x19+imm STR/STUR/STP を走査、到達範囲は `[0x4, 0x7fa8]` のみ）。一方、`add xD,x19,#H,lsl#12[+L]` 型のエイリアスレジスタ経由では **118件のメモリ操作（load 63 / store 54）がこの帯に到達**することを確認（`dump_simd_zone_ops.py` 出力、`analysis/gen_audio_h/simd_zone_ops_output.txt`）。うち目立つパターンとして、stack_off `0x412e8+{0x7f,0xff,0x17f,...,0xaff}`（128バイト間隔、22件）に `strb wzr, [x8, #N]` が連続する箇所がある — 128バイト境界ごとの末尾1バイトをゼロクリアする配列初期化に見えるが、**用途（パディング長マーカー等)は未確認、推測を避け「観測されたパターン」として記録するに留める**。
- `pthread_create` 呼び出し（下記）の `arg` は `x19+0x3fe4f` で、これも上記帯の範囲内 `[0x3bf8c,0x45328]` に収まる。ただし後述の通り、この呼び出し先スレッドルーチンは crypto/table 処理とは無関係（CFStringGetCString 等ファイルパス系API呼び出しのみ）と判明しており、**このアドレス一致は偶然の可能性が高く、テーブル生成との関連性の証拠にはならない**（前セッション時点での仮説は本セッションで反証・撤回）。

**結論（項目1）**: 8箇所の SIMD ロードのうち 6 箇所は blob ではなく `_gen_audio_h` 自身の巨大ローカルスタックフレーム（277KiB）末尾約38KiBの領域を読む。残り2箇所はポインタ間接であり、そのポインタの指す先（whitebox blobである可能性を含む）は**追跡不可**。この帯を linear body 内で literal に書き込む命令が存在しないため、**この帯へのデータ供給元（blob からの一括コピーの有無を含む）は本セッションでは特定できていない＝追跡不可**。

---

## 2. `_set_platform_for_gen_audio` (0x1007788ec) 呼び出し時の入力

呼び出しサイト: `0x1009593e8`（`_gen_audio_h` 内、単一の call site）。

- この call site は CFF による1命令だけの pseudo-block（`bl` のみ）であり、直前 400 命令の生走査でも x0/w0 への有意な書き込みは検出されなかった。
- callee 自体（`0x1007788ec` 〜 `ret`＠`0x100778a3c`、約 0x150 バイト）を実際に逆アセンブルした結果、**x0 レジスタを一切読まない**ことを確認した。呼び出し内部は `__bss` 上のグローバル（VA ≈ `0x1013d5d30`）のみを操作し、`bl 0x1007e1998(ptr, mode, flag)` を固定の即値ペア（`w1=3,w2=1` → `w1=0xf,w2=0`）で 3 回呼ぶだけの、**実質パラメータなし（自己完結型）の関数**であることが確認できた。

**結論（項目2）**: `_gen_audio_h` からのこの呼び出しは、可変の「プラットフォームID」等を x0 経由で渡していない。callee は入力非依存。

補足: 隣接するアドレス `0x100778a60` に x0 を消費する別関数（`mov x19,x0` あり）が存在し、命名規則（`znca_ios_f_generation.md` の RVA テーブル）から見て `_set_platform_for_gen_audio2` に相当する可能性が高いが、これは `_gen_audio_h` からは呼ばれていない（未検証の別経路）。

---

## 3. 9-subtable 仮説の裏取り結果

前セッションの仮説: whitebox blob の pure-table 領域サイズ（1.76 MiB）÷ Netflix TFIT-AES11 テーブルセットサイズ（203,904 B）≈ 9.06 という統計的推測を、8 個の SIMD ロード＝「プラットフォーム別サブテーブル選択」の物理的根拠として補強できるか、というのが検証対象だった。

- 項目1の追跡結果により、**8箇所の SIMD ロードのうち少なくとも6箇所は blob を直接インデックスしていない**（`_gen_audio_h` 自身のスタックフレーム末尾約38KiB帯を読む）ことが確定した。したがって「8個のSIMDロード = 9サブテーブルのプラットフォーム選択機構」という具体的メカニズムは**反証（refute）**する。
- 残り2箇所（ポインタ間接、#6・#8）については、そのポインタが最終的に whitebox blob 内アドレスを指すか否かは**追跡不可**であり、9-subtable仮説そのもの（blobサイズの統計的根拠）を積極的に否定する材料ではない。あくまで「今回追跡した8個のSIMDロードがその根拠にはならない」という限定的な反証にとどまる。
- blob サイズ比（1.76 MiB ÷ 203,904 B ≈ 9.06）という統計的観察自体は本セッションで再検証していない（`znca_ios_whitebox_layout.md` に記載のまま、独立した弱い状況証拠として存置）。

**結論（項目3）**: 8-SIMD-load による 9-subtable 選択という具体的メカニズム仮説は**反証**。統計的サイズ比の仮説自体の真偽は**追跡不可（本セッション範囲外）**。

---

## 4. whitebox blob への最初/最後の参照命令オフセットと phase 分割

`find_blob_touch_range.py`（全 `ADRP+ADD` によるデータアドレス形成のうち、着地先が `[0x100f70000, 0x101192000)` に入るものを全走査）の結果:

- **総ヒット数 14,750 件、distinct ターゲット 1,194 個**
- **最初の参照**: `0x10090f40c`（func+0x200） → target `0x1010b59a0`（blob+0x1459a0）
- **最後の参照**: `0x100a20698`（func+0x11148c） → target `0x101034c58`（blob+0xc4c58）
- 参照は関数の **func+0x200 から func+0x11148c まで、関数全体（0x1116f0）のほぼ全域（99.97%）** に渡って分布しており、20分割したバケット密度もほぼ一様（各バケット 400〜985件、明確な偏りなし）。

上位ターゲットの内訳（`Counter` 集計）:

```
0x101034204 (blob+0xc4204) count=1385 (9.4%)  ← CFF_STATE_VAR_MAIN（initGenAudioH解析で既知の共有CFF状態変数）
0x101034810 (blob+0xc4810) count=518 (3.5%)
0x101034af0 (blob+0xc4af0) count=502 (3.4%)
... (上位20件すべてが blob+0xc4000〜0xc5000 の約3.5KiB帯に集中)
上位20件の累積: 65.2%
distinct ターゲットのうち1回しかヒットしないもの: 788 / 1194
```

- 上位ヒットは全て `znca_ios_whitebox_layout.md` が「CFF-plumbing」（17.4%、間接分岐用ステートアイランド）と分類した領域に一致しており、**genuine な whitebox テーブルセル参照ではなく、CFF ディスパッチ機構自体のステート変数アクセスである**ことがほぼ確実。
- 1回しかヒットしない 788 個の distinct ターゲットの中に、真のテーブルセル参照（"pure table" 82.6% 領域内のもの）が含まれている可能性はあるが、それを CFF-plumbing の残余ノイズと区別するには前セッションのエントロピーベース分類（バイト単位の pure-table / plumbing 境界データ）との突合が必要であり、**本セッションでは実施できていない（追跡不可）**。
- 上記のとおり density に明確な偏りが無いため、**serialize/hash/encrypt/finalize のような phase ブロックへの区分けは、この touch-density データからは視認できない**。CFF による全域フラット化のため、素朴な「命令オフセット順=処理順」という前提も成立しない可能性が高い。

**結論（項目4）**: 最初/最後の blob 参照命令オフセットは特定できた（func+0x200 〜 func+0x11148c）が、その大半（65%超）は CFF ディスパッチ用ステート変数アクセスであり、genuine なテーブル参照ではない。phase 分割は**視認できず、追跡不可**として残す。

---

## 5. SHA-256 K[64] ラウンド定数を起点とした CryptoPP Merkle-Damgard 実装の探索

- バイナリ内に標準 SHA-256 `K[64]` テーブル（`0x428a2f98, 0x71374491, ...`）の完全一致コピーが **3箇所**存在することを確認: `0x100cae7e0`, `0x100cbbcc8`（いずれも `__TEXT`）、`0x100f77da0`（whitebox blob 内、CFF-plumbing アイランド）。
- `__TEXT` 内の2コピーはそれぞれ1つの小関数から ADRP+ADD で参照されている（`0x1006c8c8c` サイズ 0x1f0、`0x1006ec35c` サイズ 0x99c）。
- `_gen_audio_h` の全 `bl` ターゲット（distinct 64件）を走査した結果、**この2関数はどちらも呼ばれていない**ことを確認（`find_sha256_calls.py`）。
- `_gen_audio_h` 自身の ADRP+ADD ターゲット（distinct 11,944件、`scan_k_table_refs.py`）の中に、上記3つの K[64] コピーへの参照は **0件**。K[64] の 256バイトパターン（および先頭8ワードの部分パターン）とのバイト一致も**0件**。
- CommonCrypto の `_CC_SHA256` インポートシンボルも確認したが、その `__stubs` トランポリン（GOTスロット `0x100e57288`）を `_gen_audio_h` が `bl` で呼び出している事実は**なし**（`resolve_stub_targets.py`）。

追加調査: `_gen_audio_h` 内で唯一の `pthread_create` 呼び出し（call site `0x10093b55c`, func+0x2c350）を発見し、その `start_routine = 0x1006f418c` を検証した。

- `lief.function_starts` によるバウンド: `0x1006f418c` - `0x1006f444c`（サイズ 0x2c0 = 704 バイト、176命令）。
- 同ルーチン内の ADRP+ADD データ参照は 1 件のみで、それは `0x101034204`（= 上記 CFF_STATE_VAR_MAIN、テーブルではない）。
- `bl` 呼び出し先は3件で、`__stubs` トランポリン解決の結果、以下のインポートシンボルであることを確認した（`resolve_thread_routine_calls.py`）:
  - `0x100c32fdc` → `_CFArrayGetValueAtIndex`
  - `0x100c330a8` → `_CFStringGetCString`
  - `0x100c33414` → `_NSSearchPathForDirectoriesInDomains`

これは **ファイルパス/ディレクトリ解決系の処理**（例: Documents/Caches ディレクトリパスの取得）であり、暗号処理・whitebox テーブル生成とは無関係と判断できる。前セッションで立てていた「この pthread がスタックスクラッチ帯 `[0x3bf8c,0x45328]` を埋めている可能性」という仮説は、**本セッションで明確に反証・撤回する**（`arg` アドレスが当該帯に落ちるのは偶然の一致であり、スレッドルーチン自体はその帯を全く触れない）。

**結論（項目5）**: `_gen_audio_h` 自身の線形コード本体には、SHA-256 K[64] テーブルへの参照も `_CC_SHA256` 呼び出しも**存在しない**（十分な根拠を伴う確認済みの否定的所見）。唯一の `pthread_create` 呼び出しも SHA-256/whitebox 処理とは無関係と判明した。したがって、`docs/spec/znca_ios_f_generation.md` に記載の「CryptoPP SHA-256 が使われている可能性」は、**少なくとも `_gen_audio_h` の直接呼び出しグラフ（bl 64種、pthread routine 含む）の範囲では確認できず**、以下のいずれかであると考えられる:
  (a) SHA-256 は使われておらず別のプリミティブ（whitebox テーブル自体がハッシュ相当の拡散/混合を担う設計）である、
  (b) `_gen_audio_h` からさらに深い間接呼び出し（未解決の `bl` 先の先、あるいは項目1で追跡不可だったポインタ間接ロードの供給元）に存在する、
  のいずれかであり、**本セッションでは両者を区別できず、追跡不可**として残す。

---

## 総括

| 項目 | 結果 |
|---|---|
| 1. SIMDロードの base 由来 | 6/8 は `_gen_audio_h` 自身のスタックフレーム末尾 ~38KiB 帯 (`x19+0x3bf8c`〜`x19+0x45328`)。2/8 はポインタ間接で指し先未解決（追跡不可）。**blob 直接インデックスは確認されず**。 |
| 2. `_set_platform_for_gen_audio` 入力 | x0 は読まれない。callee は自己完結型（`__bss` グローバルのみ操作）。可変プラットフォームIDは渡されていない。 |
| 3. 9-subtable 仮説 | SIMDロード起因の具体的メカニズムとしては**反証**。blobサイズ比の統計的仮説自体は再検証しておらず**追跡不可**。 |
| 4. blob touch 範囲・phase | 参照は func+0x200〜func+0x11148c（ほぼ全域）。65%超が CFF ステート変数アクセスで table 参照ではない。phase 分割は**視認できず追跡不可**。 |
| 5. SHA-256 K[64] 起点探索 | `_gen_audio_h` 本体・唯一の pthread routine ともに K[64] 参照/CC_SHA256 呼び出しなし（根拠十分な否定的所見）。深い間接呼び出し先の可能性は**追跡不可**。 |

追跡不可として明示的に残した項目:
- SIMD site #6 (`x19+0x49f8`) と #8 (`x19+0x11c8`) のポインタが指す先。
- スタックスクラッチ帯 `[0x3bf8c,0x45328]` へのデータ供給元（blob からの一括コピーの有無を含む）。
- `strb wzr` 128バイト刻みパターンの意味論的用途。
- 1回のみヒットする 788 distinct blob ターゲットのうち、真のテーブルセル参照と CFF-plumbing 残余ノイズの切り分け。
- SHA-256（またはCryptoPP相当のMerkle-Damgard実装）が存在するとすれば、それが存在しうるさらに深い間接呼び出し経路。
