# KANADE 動的解析セットアップ (Apple Silicon Mac + Whisky + Frida)

`packages/frida/hook_kanade_packinone.js` を Mac ホスト上で実行して、
KANADE の復号鍵 (key_string / SHA256 出力 / ChaCha state) と
復号後の生ストリームを丸ごと収集する手順。

## 前提

- Apple Silicon Mac (M1 以降)
- [Whisky](https://getwhisky.app/) インストール済み
- KANADE.exe 一式 (Steam 版でも DMM 版でも可) を Mac 上に展開済み

## 1. KANADE を Whisky で起動できることを確認

1. Whisky.app を起動
2. `+ Create Bottle` で 64-bit Windows 11 ボトルを作る
3. ボトル内で `Run...` から `KANADE.exe` を選択して起動
4. タイトル画面まで進めば OK。落ちる場合:
   - フォントが足りない → `winetricks corefonts` をボトルで実行
   - DRM (krkrsteam.dll) で止まる → Steam を Whisky 内で動かしておく必要あり。回避する場合は krkrsteam.dll を `_steamless_` の deDRM 版に置換するか、Steam ライセンス取得済みの場合は Steam を Whisky 内ログイン

## 2. Mac に Frida をインストール

```bash
# brew 経由 (推奨)
brew install frida

# または pip 経由
pip3 install frida-tools
```

確認:
```bash
frida --version
frida-ps          # 動作テスト
```

## 3. KANADE プロセスに attach

ターミナル A (KANADE 起動中):
```bash
# Whisky で KANADE.exe を起動 (タイトル画面まで)
```

ターミナル B (Frida):
```bash
# プロセス確認
frida-ps | grep -i KANADE
# 例: 12345  KANADE.exe

# attach + フックスクリプトロード
cd /path/to/this/repo
frida -p 12345 -l packages/frida/hook_kanade_packinone.js -o kanade_dump.log
```

`-o kanade_dump.log` に Frida のコンソール出力が保存される。ストリームの実バイトは
Whisky 内の `C:\kanade_dump\` (= ボトルの drive_c フォルダ) に書き出される。

## 4. 取得物

### 鍵 (Mac → ホストへコピー)

Whisky ボトルの drive_c マッピング:
```
~/Library/Containers/com.isaacmarovitz.Whisky/Bottles/<bottle-uuid>/drive_c/kanade_dump/
  ├── keys.log         # ChaCha state setup ごとの key (32B) + extra
  ├── key_strings.log  # BasicCryptFilter ctor で取得した key_string 候補
  └── <ファイル名群>   # 復号後の生ストリーム (PSB / TJS / 画像 etc.)
```

ホストにコピー:
```bash
cp -r ~/Library/Containers/com.isaacmarovitz.Whisky/Bottles/<UUID>/drive_c/kanade_dump/ \
      /path/to/this/repo/targets/Kanade/_decrypted/dynamic/
```

### 復号後ファイル

タイトル画面までで十数ファイル、ゲーム本編に進むと数百ファイル落ちる。シナリオ系は
`scenario.scn` / `*.ks` / `*.psb` のような名前で出てくるはず (KAGEX 仕様)。

## 5. シナリオ取得が目的の場合

タイトル画面で attach すると初期 PSB しか取れない。**ゲーム本編を少し進める**
(プロローグの 1-2 シーンクリック) と、章ごとのシナリオ PSB が `*.scn` 等で
ダンプされる。

シナリオ全件回収は autoplay モードで放置するのが楽 (KAGEX なら通常 `Ctrl` 長押しでスキップ可能)。

## 6. トラブルシュート

### `Module.findModuleByName('PackinOne.dll')` が null

PackinOne.dll は **遅延ロード**される (KANADE 起動 → タイトル画面初期化中にロード)。
スクリプトは `LoadLibraryW` フックで再試行するので、KANADE をタイトル画面まで
進めてから attach すれば確実。

### `TVPCreateStream signature not found`

KANADE のビルドが KrkrZ MSVC 版 (KrkrDump 対応版) と違う場合、シグネチャが一致しない。
対策: シグネチャを再収集する (radare2 / Ghidra で KANADE.exe を解析、エンジン側
`TVPCreateStream` を見つけてその先頭 46 バイトを取り直す)。

### Frida が attach できない (`Failed to attach: unable to communicate with target process`)

- macOS のセキュリティ: SIP が一部関与する場合がある。
  `csrutil status` で disabled/partial を確認 (通常 enabled でも attach できるが、
  プロセスが Hardened Runtime + entitlements 強い場合は要 SIP 緩和)
- Whisky 内のプロセスは Wine の中の x86 翻訳済みプロセス。Frida は macOS arm64
  ホストプロセス (wine64) に attach する必要があるかも。`frida-ps` で表示される
  名前を要確認 (`KANADE.exe` ではなく `wine` や `wineserver` の場合あり)
- 上記でダメなら `frida -n wineserver` を試す

## 7. スクリプトが返す情報の使い方

### key_strings.log
各エントリ = 1 回の `BasicCryptFilter` 構築時の入力。
これがあれば `bruteforce.py` を改造して
`key = SHA256(0x20040101 ⊕ IV \|\| 0…, key_string)` で
オフラインで Hxv4.blob 復号を再現可能。

### keys.log
SHA256 出力 (32B) そのもの。これを直接 ChaCha key として使えば
オフライン復号可能。ただし key_string が分からないと再生成不可。

### 復号後ストリーム
復号レイヤーが終わった**生ファイル**。
中身が PSB なら `psb_strings.py` でそのまま文字列抽出可能。
中身が KAG3 .ks (Shift-JIS テキスト) なら `nkf -w` でも読める。
