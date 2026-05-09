# KANADE 解析: 進捗サマリ (2026-05-08 時点)

Frontwing 製 KrkrZ ベース ADV ゲーム「KANADE」(Steam App ID 3104270) の
セリフテキスト抽出を目的とした解析の中間まとめ。

## 達成項目

### 1. SteamStub DRM 剥がし
- ツール: `tools/steamless/` (Steamless v3.1.0.5、Mono 経由で実行)
- バリアント: SteamStub Variant 3.1 (x86)
- 結果: `KANADE.exe` (4,603,392 bytes、`.bind` 削除済 6 セクション)
- バックアップ: `KANADE.exe.bak` / `KANADE.exe.original` (元 4,789,712 bytes)

### 2. PE 整合性修正
- セクション名 `\xaa` 痕跡を `\x00` に正規化 (`.text` / `.data` / `.rsrc`)
- `.adata` セクション属性を CODE (0x60000020) → DATA-RO (0x40000040) に修正

### 3. Steam ライセンス回避
- `steam_api.dll` を **Goldberg gbe_fork** (`tools/gbe/`) の `regular/x32/` 版に置換
- `steam_api.dll.bak` に元 Valve 版を保存
- `steam_appid.txt` = `3104270`
- `steam_settings/configs.user.ini` で language=japanese, account_name=Player

### 4. KrkrZ 署名検証スキップ
- `KANADE.exe.sig` → `KANADE.exe.sig.bak` に退避

### 5. PackinOne.dll アンチタンパー突破
- バックアップ: `plugin/PackinOne.dll.bak`
- **Patch 1** (integrity check 強制成功):
  - file offset `0x60300` (`sub_10060f00`) を 20 バイト書き換え
  - 内容: `mov dword [0x1009f03c], 1; mov al, 1; ret; nop×7`
  - 効果: SHA-256 ハッシュ check が常に PASS、`USER32.DLL` 無限ロード阻止
- **Patch 2** (addFont 登録 NULL crash 回避):
  - file offset `0x33c61` を 10 バイト書き換え
  - 内容: `eb 00 83 7f 08 00 75 3b 74 78` (NULL チェック分岐)
  - 効果: `UFontEx::attach` が System dispatch=NULL のとき crash しない
- `plugin/PackinOne.dll.sig.bak` に元署名退避

### 6. PSB v6+ Frontwing 独自フォーマット解明
- `psbfile.dll` 自体には `c1 a2` パーサがなく、KANADE.exe 内蔵
- フォーマット: `\xc1\xa2\x06..\x09 \x00\x00\x00` ヘッダ + TLV (Type-Length-Value) tree
- タイプタグ:
  | tag | 意味 | ペイロード |
  |-----|------|-----------|
  | `c1 6e` | MAP (string-keyed dict) | uint32 count + count×(raw_str_key + value) |
  | `81 XX` | ARRAY | uint32 count + count×value |
  | `02 XX` | STRING (UTF-16LE) | uint32 char_count + char_count×2 bytes |
  | `00 XX` | NULL/scalar | uint32 value |
- Python 実装: `tools/re/parse_psb_tree.py`
- 一部ファイルは byte-level XOR スクランブルあり (H 値ファイル別)

### 7. PSB 141 個の網羅展開
- 全 PSB v6+ (data.xp3: 78個 + patch.xp3: 63個) を JSON 展開
- **日本語 (ひらがな + カタカナ) 出現は全 0 件**
- 内容はすべて UI orchestration (KrkrZ API call、asset 名、フォント設定等)

## 未解決の核心問題

### A. KANADE 起動失敗 (Whisky 上)
- **症状**: `PreRenderFontEx.AddTrueTypeFont: System.addFont not defined` ダイアログ
- **根本原因**: PackinOne.dll の `V2Link` 時点で TJS `System` クラスがまだ初期化されておらず、
  `System.addFont` を生やせない (load order 問題)
- **試行と失敗**:
  - 遅延実行パッチ案 → ユーザー判断で「意味ない」却下
  - ディスク `startup.tjs` / `KANADE.tjs` 配置 → KrkrZ がディスクファイル読まない
  - data.xp3 idx=1546 (PreRenderFontEx.tjs) を空 TJS で in-place 上書き → 様々な
    エンコーディング (BOM 付き UTF-16LE / ASCII / CP932) を試したが全て Syntax error
  - textrender.dll 退避 → 関係なし、`PreRenderFontEx` は textrender じゃなく
    XP3 内 TJS スクリプトでクラス定義されている

### B. シナリオの所在不明
- PSB 141 個には日本語ゼロ
- 未分類 ~1000 件 (XP3 全件) でも UTF-16LE / CP932 で意味のある日本語連続文字列なし
- **仮説**: シナリオは Frontwing 独自スクランブル + KAG/TJS バイトコード化
  - 実行時に KAGEX が復号 + 解釈
  - 静的に文字列として検出できない設計

## ツール / リソース

| パス | 内容 |
|------|------|
| `tools/steamless/` | Steamless v3.1.0.5 (DRM 剥がし) |
| `tools/gbe/` | Goldberg gbe_fork (Steam Emu) |
| `tools/freemote/` | FreeMote v4.5.0 (標準 PSB のみ対応、KANADE は弾く) |
| `tools/re/parse_psb_tree.py` | KANADE PSB v6+ パーサ |
| `src/xp3/` | XP3 + Hxv4 + per-file XOR mask 復号 |
| `packages/frida/hook_kanade_packinone.js` | Frida スクリプト (起動できれば動く想定) |
| `docs/instructions/packinone_static_analysis.md` | PackinOne.dll 静的解析ノート |
| `docs/instructions/kanade_frida_setup.md` | Mac + Whisky + Frida セットアップ手順 |
| `targets/Kanade/run_kanade.sh` | Mac 用 wine64 直接起動スクリプト |
| `targets/Kanade/data.xp3.original` | クリーン data.xp3 バックアップ |

## 次回再開時の選択肢

1. **`extNagano.dll` 解析** — Frontwing 独自プラグイン、シナリオ読み込みの手掛かり
2. **KANADE.exe 内蔵 PSB パーサのリバース** — 実装拡張があれば見える
3. **TJS バイトコード仕様研究** — シナリオがバイトコード化されている前提
4. **CrossOver / Wine vanilla で起動再挑戦** — Whisky の load order 問題が解消する可能性
5. **Frida 動的解析** — Wine 起動さえ通れば、メモリから復号後文字列を直接読める

## ファイル状態 (2026-05-08 時点)

`targets/Kanade/` 配下の改変ファイル:
- `KANADE.exe` (DRM 剥がし版、4.6MB)
- `KANADE.exe.bak` / `.original` (元、4.8MB)
- `KANADE.exe.sig.bak` (元署名)
- `steam_api.dll` (Goldberg、9MB) / `.bak` (Valve、266KB)
- `steam_appid.txt`, `steam_settings/configs.user.ini`
- `data.xp3` (= `.original` から復元、md5 一致確認済)
- `data.xp3.original` (バックアップ)
- `plugin/PackinOne.dll` (パッチ済) / `.bak` (元)
- `plugin/PackinOne.dll.sig.bak` (元署名)
- `plugin/textrender.dll.disabled` (退避中、戻すには `.disabled` を消す)
- `startup.tjs`, `KANADE.tjs` (試行錯誤の残骸、削除可)
