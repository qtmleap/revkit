# znca (Nintendo Switch Online) iOS 3.4.1 — whitebox table 内部レイアウト解析

対象: `/home/vscode/app/targets/znca_ios_3.4.1/Crew` (arm64 Mach-O, `__TEXT` vmaddr=`0x100000000`)
抽出済みブロブ: `targets/znca_ios_3.4.1/whitebox/whitebox_data_0x100f70000_0x101192000.bin`
VA 範囲: `0x100f70000` .. `0x101192000`（2,236,416 バイト、2.133 MiB）、`__DATA.__data` 内。

前提となる静的解析: [`znca_ios_init_gen_audio_h_static.md`](./znca_ios_init_gen_audio_h_static.md)（`+[VoIPClient initGenAudioH]` の CFF 構造・64KiB 窓エントロピー走査で本ブロブ範囲を最初に特定）。
f-token 生成の全体像: [`znca_ios_f_generation.md`](./znca_ios_f_generation.md)。

このドキュメントは前セッションで生成されたが計算コードを失った 5 種の `.npy`
（`entropy_256`, `perm_cols_1024`, `distinct_rows_1024`, `rebase_per_4k`, `chain_per_4k`/`chain_mask`）
を shape・値域から逆算して `whitebox/tools/*.py` として書き起こし、その上で
**新規のポインタ fixup 解析** を追加してブロブの内部構造を大きく前進させた記録。

---

## 1. 復元した生成コード

全スクリプトは `targets/znca_ios_3.4.1/whitebox/tools/` に配置。`common.py` が共通定数
(`VA_LO=0x100f70000`, `VA_HI=0x101192000`, ブロブ/バイナリパス) を提供する。

| スクリプト | 再現対象 npy | 検証結果 |
|---|---|---|
| `gen_entropy_256.py` | `entropy_256.npy` (8736,) float64 | **`--verify` で完全一致** (256B 非重複窓の Shannon entropy) |
| `gen_distinct_rows_1024.py` | `distinct_rows_1024.npy` (2184,) int32 | **`--verify` で完全一致** (1024B ブロックを 256 行 x 4 バイトに reshape → distinct row 数) |
| `gen_perm_cols_1024.py` | `perm_cols_1024.npy` (2184,) int32 | **`--verify` で完全一致**（32x32 バイト行列の各列が `0..31` の順列かを判定。全 0 は妥当 — 後述） |
| `gen_pointer_fixups.py` | ~~`rebase_per_4k.npy` / `chain_per_4k.npy` / `chain_mask.npy`~~ → 新規 `pointer_fixup_*.npy` | **旧 npy とは一致しない（後述）。LIEF による正しい chained-fixups 解析で置き換え** |
| `gen_layout_segments.py` | (新規) | ブロブを "pure table" / "CFF plumbing" に分割する要約ツール |
| `scan_gen_audio_h_refs.py` | (新規) | `_gen_audio_h`/`_gen_audio_h2` 本体の ADRP+ADD / LDRB / 添字 LDR を capstone で走査 |

再現・検証コマンド:

```bash
cd targets/znca_ios_3.4.1/whitebox/tools
python3 gen_entropy_256.py --verify
python3 gen_distinct_rows_1024.py --verify
python3 gen_perm_cols_1024.py --verify
python3 gen_pointer_fixups.py --save
python3 gen_layout_segments.py
python3 scan_gen_audio_h_refs.py
```

### 1.1 `entropy_256` / `distinct_rows_1024` — パラメータ確定の経緯

- `entropy_256`: ブロブサイズ `2236416 / 256 = 8736` と shape が完全一致するため、
  256B 非重複窓と確定。Shannon entropy (bits/byte) をそのまま計算し、`np.allclose` で完全一致。
- `distinct_rows_1024`: shape `2184 = 2236416/1024`。row 幅を `{4,8,16,32,64}` バイトで総当たりし、
  **row 幅 4 バイト (= 256 行/ブロック) のときのみ** saved npy の `max=256` と一致
  （row 幅 N バイトなら行数は `1024/N` なので、`max` が厳密に 256 になるのは行数がちょうど 256 のときだけ）。
  4 バイト粒度は AES ラウンド鍵ワードや T-box 列エントリの典型サイズと一致し、
  「1KB ブロック内で 4B ワードがどれだけ重複しているか」を見るテストと解釈できる。
- `perm_cols_1024`: 1024B を 32x32 行列とみなし、各列 (32 バイト) をソートして `[0..31]` と
  一致するかを数える定義で **saved npy（全ブロックで 0）と完全一致**。ただしこの基準は
  バイト値域が `0..255` である実データに対しては事実上成立しえない（32 バイトが `0..31` の
  狭い範囲に収まり、かつ完全一致する確率は `32!/32^32 ~ 1e-14`）。**全 0 は「順列構造が
  存在しない」ことの証明ではなく、「row-major 32x32・mod-32 という枠組みでは見つからなかった」
  ことの証明**に過ぎない。今回あらためて **256B 窓でのフルバイト順列（`0..255`）を
  固定境界・スライディング窓の両方で全域探索**したが、こちらもヒット 0 件だった（§3 参照）。

---

## 2. ポインタ fixup 解析（新規・legacy npy を置き換え）

### 2.1 legacy npy の不整合

前セッションの `rebase_per_4k.npy`（sum=69, max=6）と `chain_per_4k.npy` / `chain_mask.npy`
（sum=2149, max=261, True count=2149）は、生成コード紛失につき厳密な再現ができなかった。
LIEF (`lief.MachO.Binary.relocations`) で `LC_DYLD_CHAINED_FIXUPS` を正規にたどった
グラウンドトゥルースと比較すると、**どちらの npy とも一致しない**:

| ソース | ブロブ範囲内の rebase 数 |
|---|---|
| legacy `rebase_per_4k` (sum) | 69 |
| legacy `chain_per_4k` / `chain_mask` (sum / True count) | 2149 |
| legacy 合計 | 2218 |
| **LIEF 正規 chained-fixups 解析（本セッションで新規取得）** | **2775** |

legacy の値は恐らく手書きの chain-walk（page_size を 4KiB と誤認、あるいは chain の
一部だけを辿る等のバグ）による部分的な結果と推定される。本セッションでは
**LIEF の `dyld_chained_fixups` パーサ（`page_start` + `next` delta の正規リンクリスト走査）**
を直接使い、`gen_pointer_fixups.py` で全 2775 件を確定させた。念のため
`DYLD_CHAINED_PTR_64_OFFSET` のビットレイアウトを手動でデコードして 1 件をクロス検証済み
（`target:36 | high8:8 | reserved:7 | next:12 | bind:1`、`next` は 4 バイト単位ストライド）。

```
raw   = 0x10000000f6ba3c  @ VA 0x100f77ec0
target(offset) = 0xf6ba3c -> VA 0x100f6ba3c   # LIEF の r.target と完全一致
high8=0 reserved=0 next=2(=8B先) bind=0        # 純粋 rebase (bind無し)
```

### 2.2 新しい成果物

`gen_pointer_fixups.py --save` が生成:

| ファイル | shape | 内容 |
|---|---|---|
| `pointer_fixup_per_4k.npy` | (546,) int64 | 4KiB bin ごとの fixup 数（グラウンドトゥルース） |
| `pointer_fixup_mask.npy` | (279552,) bool | 8B スロット単位で fixup 位置かどうか（True count = 2775） |
| `pointer_fixup_targets.npy` | (2775, 2) int64 | 各 fixup の `(address, target)` VA ペア |

**全 2775 件は `has_symbol=False`（純粋 rebase、import bind なし）**。
うち 2734 件はブロブ内部を指し（自己参照）、41 件のみブロブ外
（`0x100eb3cb8` 付近 / `0x1013cfd04` 付近 = 静的解析ドキュメントで既知の `__bss` フラグ領域・
`__common` C++ オブジェクトスロット領域）を指す。

### 2.3 決定的な発見: fixup 位置は "CFF ディスパッチ用ポインタ変数" と一致する

`znca_ios_init_gen_audio_h_static.md` §3 が列挙した「ホットな `__DATA.__data` 参照先
(疑いなく CFF ディスパッチ state 変数)」12 個のうち **11 個が、まさに chained-fixup の
ポインタスロットそのもの** だった:

| アドレス | initGenAudioH からの参照回数 | fixup 位置か |
|---|---|---|
| `0x101034204` | 628 | **いいえ**（真の int32 state 変数） |
| `0x10113a520` | 108 | **はい** |
| `0x10103d998` | 24 | **はい** |
| `0x10103f9e0` | 20 | **はい** |
| `0x101084300` | 16 | **はい** |
| `0x10110e020` | 16 | **はい** |
| `0x10113a408` | 12 | **はい** |
| `0x10110f1f0` | 12 | **はい** |
| `0x1010426e0` | 12 | **はい** |
| `0x10111c630` | 12 | **はい** |
| `0x101041cd0` | 12 | **はい** |
| `0x10103faa8` | 12 | **はい** |

**解釈**: OLLVM 系 control-flow flattening の一部の実装では、次に飛ぶ基本ブロックの
アドレスを「整数ステートキー」ではなく「rebase 済みポインタ変数」として保持し、
`br xN`（間接分岐）で直接ジャンプする。PIE バイナリではこの手のポインタは
ロード時に ASLR スライドを反映して書き換える必要があるため、**Mach-O ローダの
chained-fixups の対象になる** — これが `__DATA.__data` の同じ VA レンジ内に
「本物の暗号定数テーブル」と「CFF 用の間接分岐ポインタ」が混在している理由。
`0x101034204` だけ fixup でないのは、これが唯一の**真の整数ステートキー**
（`initGenAudioH` 冒頭で観測された `br x8` ディスパッチの `state` そのもの）だからと考えられる。

### 2.4 `_gen_audio_h` 側でも同一クラスタを再利用

`scan_gen_audio_h_refs.py` で `_gen_audio_h`/`_gen_audio_h2` tail-merged 本体
(`0x10090f20c`..`0x100a208fc`, 約 1.07 MiB, capstone で 279,996 命令) の
ADRP+ADD ターゲットを全走査した結果:

- ブロブ内ターゲット: distinct **9323** 種、参照 **14227** 回
- そのうち **fixup スロットに一致するもの**: distinct 306 種、参照 885 回
- **`0x101034204`（initGenAudioH と同一アドレス）が単独で 1385 回参照** — つまり
  `initGenAudioH` と `_gen_audio_h`/`_gen_audio_h2` は **同一の CFF state 変数プールを共有**している。

---

## 3. S-box / permutation テーブル探索（陰性結果）

比較対象として Netflix iOS 15.48.1 の `NFWebCrypto.framework`（同じ Irdeto TFIT 系ホワイトボックス、
`tools/re/analyze_tfit_nfwc.py` で解析済み）を実際に抽出・実行して較正した:

```
TFIT_out_iAES11_0..15 (Netflix, 256B 各, offset 0x1DDBA8 から 0x100 刻みでアライン)
  → is_permutation=True, entropy=8.00 を全 16 テーブルで確認
```

同じ「256B 窓が `0..255` の完全順列かどうか」判定を znca のブロブ全域に適用:

| 探索方法 | ヒット数 |
|---|---|
| 256B 固定境界（8736 窓、非重複） | **0** |
| 256B スライディング窓（全 2,236,161 オフセット、1 バイト刻み） | **0** |

**結論**: znca のホワイトボックス実装には、Netflix TFIT-AES11 の `TFIT_out_*` に相当する
「生の 256 エントリ・バイト置換 S-box」がバイト境界のどこにも存在しない。
これは以下のいずれかを示唆する:
1. スキームが AES Chow-WBC 系ではない、または S-box を別の粒度（nibble 単位、
   ワード単位の合成 T-box のみ）で実装している。
2. `f_generation.md` に記載の通り libvoip は CryptoPP の **SHA-256** 実装を内部に持つ
   （HMAC は使われていない）ため、AES ではなく SHA-256 ベースの独自ホワイトボックス構成である
   可能性がある。
3. テーブルは静的には難読化（XOR マスク等）されており、`initGenAudioH` の
   ランタイム "unlock" パス（§4 参照）を経るまでは真の S-box 値が現れない。

`znca_ios_init_gen_audio_h_static.md` が既に確認済みの「生 AES SBox 定数
(`63 7c 77 7b`) もバイナリ全体で 0 ヒット」と合わせ、**素の AES 定数は静的解析では
一切観測できない**ことが再確認された。

---

## 4. ブロブのセグメンテーション: "pure table" 領域 vs "CFF plumbing" 領域

`gen_layout_segments.py` は fixup 密度が非ゼロの 4KiB bin を（最大 2 bin の隙間を許容して）
連結し、31 個の "CFF-plumbing island" を検出した:

```
CFF-plumbing 合計:  95/546 bins,  380.0 KiB (17.4%)
pure-table 合計:    451/546 bins, 1.76 MiB  (82.6%)
  pure-table entropy:            min=7.075 max=7.217 mean=7.173  (非常に狭い帯域)
  pure-table distinct 4B rows:   min=252.2 max=256.0 mean=256.0  (ほぼ完全にユニーク)
```

対照的に CFF-plumbing island 側は entropy 6.15〜7.13（明確に低い）、distinct-row
217〜254（明確に低い）と、統計的に別集団であることがはっきり分離できる
（table 4-2 参照 — pure 側は分散がほぼゼロで、まさに「等方性の高い擬似乱数ルックアップテーブル」
の指紋。island 側はワードの反復があり構造化データの指紋）。

代表的な island（VA, サイズ, fixup 数）:

| VA 範囲 | サイズ | fixups | 備考 |
|---|---|---|---|
| `0x100f77000`-`0x100f7f000` | 32 KiB | 345 | ブロブ先頭付近、最大密度 bin (`0x100f7b000`, 275/512 slot) を含む |
| `0x10103d000`-`0x101043000` | 24 KiB | 278 | `0x10103d998`/`0x10103f9e0`/`0x101041cd0`/`0x10103faa8` 系の CFF state を含む |
| `0x10110a000`-`0x101111000` | 28 KiB | 250 | `0x10110e020`/`0x10110f1f0` 系 |
| `0x101033000`-`0x101038000` | 20 KiB | 139 | `initGenAudioH` の主要 dispatch (`0x101034204`) を含む窓 |
| `0x1010b5000`-`0x1010bc000` | 28 KiB | 220 | 未対応の追加クラスタ（別の OLLVM 対象関数由来と推定） |

**解釈**: `__DATA.__data` の当該 VA レンジは、Crew バイナリ内の**多数の異なる
OLLVM-CFF 化関数**（`initGenAudioH`, `_gen_audio_h`, `_gen_audio_h2` に限らない）
が共有する「ディスパッチ用ポインタ変数プール」と、**本物のホワイトボックス定数テーブル**
が同居している。真のホワイトボックステーブル候補は **82.6% ≒ 1.76 MiB** に絞り込める。

---

## 5. `_gen_audio_h` の実データアクセスパターン

### 5.1 命令クラス別集計 (capstone, 279,996 命令走査)

| クラス | 件数 |
|---|---|
| ADRP+ADD ペアで解決したデータ参照（distinct target） | 11,944 |
| 同・総参照回数 | 17,474 |
| レジスタ添字 `LDRB` (`[Xn, Wm]` 形式の真の table-lookup) | **0** |
| レジスタ添字 `LDR Qn, [Xn, Xm]`（128bit SIMD、レジスタ+レジスタ addressing） | **8** |

**真のスカラー添字バイトロード（古典的 S-box lookup 命令列）は 1 件も検出されなかった。**
唯一の register-indexed アクセスは 8 箇所の `ldr q0, [x9, x8]` 系 128bit ロードで、
これは「16 バイト単位の行を register offset で読む」パターン — T-box の 1 行
（16B/32B ワードなど）をベクトルレジスタへ一括ロードする実装が候補になる
（8 箇所全ての周辺コンテキストと `x9`/`x10` の base register の由来は CFF に埋もれており未解決。
次の調査ステップ候補として明記）。

### 5.2 immediate-offset LDRB の大量出現（7271 件）はテーブルではなくスタック/CFF フィールド

`ldrb w8, [x28, #0x19e]` のような **即値オフセット**の LDRB が 7271 件観測されたが、
これらは全て小さいオフセット（0x19e など、〜0x400 以下）で `x28` を base にしており、
`initGenAudioH` の巨大スタックフレーム（約 90 KiB、`znca_ios_init_gen_audio_h_static.md` 参照）と
同様の「フレーム内ワーキングバッファへのフィールドアクセス」と解釈するのが妥当。
**ブロブ内アドレスへの参照ではない**（ADRP+ADD 経由の ADRP ベースアドレスとは別系統）。

### 5.3 ADRP+ADD ターゲットの大半は CFF クラスタに集中、残りは疎な "1 参照" アクセス

ブロブ内ターゲット 9323 種のうち、fixup スロットと一致しないもの (9017 種, 13342 参照)
から `0x101034204` を含む主要クラスタ (VA `0x101030000`-`0x101038000`) を除外すると:

```
残り distinct targets: 7301, 総参照: 8507
  ref count == 1 のもの: 6733 (92.2%)
  分布先の 4KiB bin:     420/546 (77%) に及ぶ、bin あたり平均 17.4 箇所
```

**解釈**: 除外後の大多数（92%）は 1 回しか参照されないユニークなアドレスで、
546 bin 中 420 bin（ほぼ全域）に広く分散している。これは「動的な添字計算による
1 つのテーブルへの繰り返しアクセス」ではなく、**CFF によって展開された数千個の
擬似ベーシックブロックそれぞれが、静的に確定した固有オフセットで 1 回だけ
テーブルセルを読む」という、Chow/TFIT ホワイトボックスの典型的な OLLVM 難読化後の姿**と整合する。
つまり「動的インデックス付き lookup」ではなく「コンパイル時に確定した数千通りの
分岐先ごとに 1 セルだけ触る」形へ CFF が変換した結果、動的な `LDRB (register)` が
消失し、代わりに大量の一意な即値オフセット ADRP+ADD/LDR が残っている、という仮説。

---

## 6. サブテーブルサイズの仮説（弱い証拠・要検証）

pure-table 領域サイズ 1.76 MiB (1,847,296 B) を Netflix TFIT-AES11 の
1 セット分の定数サイズ（`tools/re/analyze_tfit_nfwc.py` 実測 = 203,904 B, 199.1 KB）で割ると:

```
1,847,296 / 203,904 ≈ 9.06
```

ほぼ整数の 9 に近い。`_set_platform_for_gen_audio` が Nintendo 側で iOS/Android/ROOT/EMULATOR
等の platform id を区別する（`znca_ios_init_gen_audio_h_static.md` §5）ことを踏まえると、
「プラットフォームや鍵バリアント違いの完全なホワイトボックスセットが複数（候補: 9 セット）
連続配置されている」という仮説が立つ。ただし:

- FFT ベースの自己相関解析では 91 KiB / 183 KiB 付近に弱いピーク（相関係数 0.05〜0.07、
  ノイズに近い水準）が見えるのみで、**205 KiB 周期を裏付ける強い証拠にはなっていない**。
- CFF-plumbing island の除去粒度（4KiB bin, gap tolerance=2）による pure-table サイズの
  見積り誤差が数 % あり、"9.06" という数字自体に丸め誤差が乗っている可能性が高い。

**この仮説は未確定として次セッションへ引き継ぐ**。検証手段の候補:
- pure-table 領域を 205 KiB 刻みで分割し、各セグメントの entropy/distinct-row 分布を
  比較（本当に 9 セットあるなら統計的に酷似するはず）。
- `_set_platform_for_gen_audio` (`0x1007788ec`) の実装を deflatten して platform id →
  テーブルベースアドレスのオフセット計算式を特定する。

---

## 7. まとめ表

| 項目 | 結論 |
|---|---|
| ブロブ全体 | `0x100f70000`-`0x101192000` (2.133 MiB), `__DATA.__data` |
| entropy_256 / distinct_rows_1024 / perm_cols_1024 | 生成コード復元済み・完全一致で再現確認 (`gen_*.py --verify`) |
| legacy rebase_per_4k / chain_per_4k / chain_mask | **再現不能（恐らくバグ入りの手動 chain walk）。LIEF 正規解析で置換** (`gen_pointer_fixups.py`) |
| ブロブ内の chained-fixup ポインタ | **2775 件**（純粋 rebase、bind なし）。79/546 (4KiB bin) に偏在 |
| ポインタ位置の正体 | `initGenAudioH` 静的解析で見つかった「CFF ディスパッチ state 変数」12 個中 11 個と一致 → **間接分岐用のポインタ変数**であり暗号定数ではない |
| ブロブのセグメンテーション | CFF-plumbing 17.4% (380 KiB, 31 island) / pure-table 82.6% (1.76 MiB) — entropy・distinct-row の両方で統計的に明確に分離可能 |
| 素の AES S-box (256B 順列) | 固定境界・スライディング境界どちらの探索でも **0 件**（Netflix TFIT-AES11 の同テストでは 16/16 ヒットしており較正は妥当） |
| `_gen_audio_h` のレジスタ添字 LDRB | **0 件**（古典的動的インデックス lookup 命令列が存在しない） |
| `_gen_audio_h` のレジスタ+レジスタ `LDR Qn` | 8 件（128bit 行ロード候補、base register 由来は未解決） |
| CFF クラスタ除外後の ADRP+ADD ターゲット | 92% が参照 1 回、546 bin 中 420 bin（77%）に分散 — CFF 展開後のテーブルセル単発アクセスと整合 |
| サブテーブル数仮説 | pure-table サイズ ÷ Netflix TFIT-AES11 定数サイズ ≈ 9.06（プラットフォーム変種 9 セット?） — **弱い証拠、未確定** |

## 8. 未解決事項 (次セッションへ)

1. `ldr q0, [x9, x8]` 8 箇所の base register (`x9`/`x10`) が指すブロブ内アドレスの特定
   （CFF に埋もれており線形トレース不可、deflatten が必要）。
2. §6 の「9 サブテーブル」仮説の統計的検証（205 KiB 刻みでの分布比較）。
3. `_set_platform_for_gen_audio` (`0x1007788ec`) の deflatten によるプラットフォーム分岐先アドレス式の特定。
4. ブロブが静的には難読化されている可能性（§3 の SBox 陰性結果を踏まえ、`initGenAudioH` の
   スレッド起動ルーチン内でのマスク解除処理を追う）。`pthread_create` の thread routine VA は
   `znca_ios_init_gen_audio_h_static.md` 未解決事項としても未特定のまま。
5. pure-table 領域の最小構成単位（4B ワード? 16B 行? 4096 エントリ x 4B の Chow T-box?）を
   確定させるための、より高次の統計テスト（列/行方向の線形性検定、GF(2^8) 上の構造検定など）。

## 9. 生成物一覧

- `targets/znca_ios_3.4.1/whitebox/tools/common.py`
- `targets/znca_ios_3.4.1/whitebox/tools/gen_entropy_256.py`
- `targets/znca_ios_3.4.1/whitebox/tools/gen_distinct_rows_1024.py`
- `targets/znca_ios_3.4.1/whitebox/tools/gen_perm_cols_1024.py`
- `targets/znca_ios_3.4.1/whitebox/tools/gen_pointer_fixups.py`
- `targets/znca_ios_3.4.1/whitebox/tools/gen_layout_segments.py`
- `targets/znca_ios_3.4.1/whitebox/tools/scan_gen_audio_h_refs.py`
- `targets/znca_ios_3.4.1/whitebox/analysis/pointer_fixup_per_4k.npy`
- `targets/znca_ios_3.4.1/whitebox/analysis/pointer_fixup_mask.npy`
- `targets/znca_ios_3.4.1/whitebox/analysis/pointer_fixup_targets.npy`
- `targets/znca_ios_3.4.1/whitebox/analysis/gen_audio_h_data_refs.pkl`
