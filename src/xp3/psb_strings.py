"""KAGEX/PSB v3+ 文字列抽出スクリプト.

Frontwing/KAGEX 製 KANADE の `data_vN_slot*.psb` から、
`LL 00 00 00 <utf-16-le×LL>` パターン (PSB のノード名 / 短い文字列) を
ヒューリスティックに抽出する。

Usage:
    uv run python /home/vscode/app/src/xp3/psb_strings.py

入力:
    /home/vscode/app/targets/Kanade/_decrypted/scenario/*.psb (141 files)

出力:
    /home/vscode/app/_text/<basename>.txt   各 PSB の抽出文字列 (1 行 1 文字列)
    /home/vscode/app/_text/_japanese_only.txt   日本語 (ひらがな/カタカナ/CJK/句読点) を含む文字列のみ
    /home/vscode/app/_text/_summary.txt   サマリ (総数, JP top5, サンプル)

備考:
    KANADE の v6/v7/v8/v9 PSB には標準ヘッダ後ろにノードツリーが直接続く
    独自バリアントが含まれている。ここではフルパーサを書かず、
    「LL 00 00 00 + UTF-16LE 文字列」パターンだけをスキャンする。
    高バイトが 0xa4 で固定された大きな領域は (見た目は EUC-JP に近いが)
    EUC-JP/SJIS/UTF-16BE どれでもクリーンに復号できなかったため、
    内部ハッシュ識別子か未知のスクランブルとみて抽出対象外とする。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_DIR = ROOT / "targets" / "Kanade" / "_decrypted" / "scenario"
OUT_DIR = ROOT / "_text"

# 「明確な」日本語: ひらがな or カタカナ or CJK 句読点 (3000-303f, ff00-ff60)
# CJK 統合漢字単独だと誤検知が多いので、ひらがな/カタカナ併記時のみ採用
JP_STRICT_RE = re.compile(r"[぀-ゟ゠-ヿ　-〿＀-｠]")
# 漢字 (CJK Unified Ideographs) は併記用 (これ単独だと採用しない)
KANJI_RE = re.compile(r"[一-鿿]")

# 文字列長の上限 (文字数ベース)
MAX_LEN_CHARS = 1024

# 文字列の「健全性」を判定する正規表現
# ASCII 印字可能 + 半角空白
ASCII_PRINTABLE_RE = re.compile(r"^[\x20-\x7e]+$")
# 怪しい CJK 拡張ブロック (PSB 型タグの誤マッチで頻出)
SUSPECT_CJK_RE = re.compile(
    r"[㐀-䶿"  # CJK Ext A (3400-4DBF)
    r"豈-﫿]"  # CJK Compatibility (F900-FAFF)
)


def extract_strings_from_psb(data: bytes) -> list[tuple[int, int, str]]:
    """Return list of (offset, length_chars, text).

    `LL 00 00 00 <utf-16-le bytes×LL>` パターンを線形スキャンする。
    マッチしたら一致末尾までジャンプして次を探すので、文字列内部の偽マッチを抑制できる。
    """
    if len(data) < 6 or data[:2] != b"\xc1\xa2":
        return []

    found: list[tuple[int, int, str]] = []
    i = 6  # マジック (c1 a2 XX 00 00 00) をスキップ
    n = len(data)

    while i < n - 4:
        # uint32 LE のサイズが 1..MAX_LEN_CHARS の範囲ならチェック
        ll = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        if 1 <= ll <= MAX_LEN_CHARS:
            end = i + 4 + ll * 2
            if end <= n:
                raw = data[i + 4 : end]
                try:
                    text = raw.decode("utf-16-le")
                except UnicodeDecodeError:
                    i += 1
                    continue
                # 制御文字 / NUL を含まない、印字可能な文字列だけ採用
                if not text or not all(
                    (c.isprintable() or c in "\t") and c != "\x00" for c in text
                ):
                    i += 1
                    continue
                # PSB 型タグの誤マッチを弾く: ひらがな/カタカナを含まずに
                # CJK Ext A や Compatibility 系を含むものは構造体ノイズとみなす
                has_kana = bool(JP_STRICT_RE.search(text))
                has_suspect = bool(SUSPECT_CJK_RE.search(text))
                if has_suspect and not has_kana:
                    i += 1
                    continue
                found.append((i, ll, text))
                i = end  # ヒットした分はスキップ
                continue
        i += 1
    return found


def main() -> int:
    if not SCENARIO_DIR.is_dir():
        print(f"scenario dir not found: {SCENARIO_DIR}", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    psb_files = sorted(SCENARIO_DIR.glob("*.psb"))
    if not psb_files:
        print(f"no PSB files in {SCENARIO_DIR}", file=sys.stderr)
        return 1

    total_strings = 0
    total_japanese = 0
    per_file_counts: list[tuple[str, int, int]] = []  # (name, total, jp)
    japanese_lines: list[str] = []
    japanese_samples: list[str] = []

    for psb_path in psb_files:
        data = psb_path.read_bytes()
        results = extract_strings_from_psb(data)

        out_path = OUT_DIR / f"{psb_path.name}.txt"
        # 重複は除去 (同じ文字列が複数箇所に出ることがある)
        seen: set[str] = set()
        unique_results: list[tuple[int, int, str]] = []
        for off, ll, txt in results:
            if txt in seen:
                continue
            seen.add(txt)
            unique_results.append((off, ll, txt))

        # 「日本語っぽい」= ひらがな or カタカナ or CJK 記号/全角を含むもの
        # (漢字単独だと PSB 構造体ノイズの誤マッチが多すぎるので除外)
        jp_in_file = [r for r in unique_results if JP_STRICT_RE.search(r[2])]

        with out_path.open("w", encoding="utf-8") as f:
            f.write(f"=== {psb_path.name} ({len(unique_results)} strings, {len(jp_in_file)} japanese) ===\n")
            for off, ll, txt in unique_results:
                f.write(f"{off:08x}\t{ll:4d}\t{txt}\n")

        for off, ll, txt in jp_in_file:
            japanese_lines.append(f"{psb_path.name}\t{off:08x}\t{txt}")
            if len(japanese_samples) < 32:
                japanese_samples.append(f"{psb_path.name}: {txt}")

        total_strings += len(unique_results)
        total_japanese += len(jp_in_file)
        per_file_counts.append((psb_path.name, len(unique_results), len(jp_in_file)))

    # 日本語のみまとめファイル
    jp_path = OUT_DIR / "_japanese_only.txt"
    with jp_path.open("w", encoding="utf-8") as f:
        f.write(f"# Japanese-containing strings: {total_japanese}\n")
        f.write("# columns: filename<TAB>offset<TAB>text\n")
        for line in japanese_lines:
            f.write(line + "\n")

    # サマリファイル
    top5_jp = sorted(per_file_counts, key=lambda x: -x[2])[:5]
    summary_path = OUT_DIR / "_summary.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"PSB files scanned: {len(psb_files)}\n")
        f.write(f"Total strings (unique per file): {total_strings}\n")
        f.write(f"Strings containing Japanese:     {total_japanese}\n")
        f.write("\nTop 5 files by Japanese-string count:\n")
        for name, tot, jp in top5_jp:
            f.write(f"  {name}: {jp} japanese / {tot} total\n")
        f.write("\nJapanese samples (first 5):\n")
        for s in japanese_samples[:5]:
            f.write(f"  {s}\n")

    # コンソール報告
    print(f"scanned {len(psb_files)} PSB files")
    print(f"total strings: {total_strings}")
    print(f"japanese:      {total_japanese}")
    print("top 5 (jp):")
    for name, tot, jp in top5_jp:
        print(f"  {name}: jp={jp} total={tot}")
    print("japanese samples:")
    for s in japanese_samples[:5]:
        print(f"  {s}")
    print(f"\nout: {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
