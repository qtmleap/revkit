#!/usr/bin/env python3
"""Segment the 2.13 MiB whitebox blob into "pure table" vs "CFF plumbing"
regions using the chained-fixup pointer mask, and report aggregate
entropy / distinct-row statistics per segment class.

A "CFF-plumbing island" is a maximal run of 4K bins (with up to 2
consecutive zero-fixup bins tolerated as a gap-merge) that contains at
least one chained-fixup rebase site. These correspond to
control-flow-flattening dispatch-pointer clusters shared by multiple
OLLVM-obfuscated functions (initGenAudioH, _gen_audio_h, _gen_audio_h2,
etc.) that the linker packed into the same __DATA.__data VA range as the
genuine whitebox constant tables — see znca_ios_whitebox_layout.md for
the full analysis and evidence.

Requires pointer_fixup_per_4k.npy (from gen_pointer_fixups.py --save),
entropy_256.npy, distinct_rows_1024.npy (from gen_entropy_256.py /
gen_distinct_rows_1024.py).

Usage:
    python3 gen_layout_segments.py
"""

import numpy as np

from common import ANALYSIS_DIR, VA_LO

GAP_TOLERANCE = 2  # consecutive zero-fixup bins allowed inside an island


def find_islands(nz: np.ndarray) -> list[tuple[int, int]]:
    islands = []
    n = len(nz)
    i = 0
    while i < n:
        if not nz[i]:
            i += 1
            continue
        start = i
        last_true = i
        j = i + 1
        gap = 0
        while j < n:
            if nz[j]:
                last_true = j
                gap = 0
            else:
                gap += 1
                if gap > GAP_TOLERANCE:
                    break
            j += 1
        islands.append((start, last_true))
        i = last_true + 1
    return islands


def main() -> None:
    entropy = np.load(ANALYSIS_DIR / "entropy_256.npy")  # (8736,) 256B windows
    distinct = np.load(ANALYSIS_DIR / "distinct_rows_1024.npy")  # (2184,) 1024B blocks
    fixup_per_4k = np.load(ANALYSIS_DIR / "pointer_fixup_per_4k.npy")  # (546,)

    n_bins = len(fixup_per_4k)
    ent_per_4k = entropy.reshape(n_bins, 16).mean(axis=1)
    dist_per_4k = distinct.reshape(n_bins, 4).mean(axis=1)

    nz = fixup_per_4k > 0
    islands = find_islands(nz)

    island_bins = set()
    for s, e in islands:
        island_bins.update(range(s, e + 1))

    print(f"CFF-plumbing islands (gap tolerance={GAP_TOLERANCE} bins): {len(islands)}")
    print(f"{'bins':>12}  {'VA range':>25}  {'size':>8}  {'fixups':>7}  {'entropy':>8}  {'distinct':>9}")
    total_island_bytes = 0
    for s, e in islands:
        va_lo = VA_LO + s * 4096
        va_hi = VA_LO + (e + 1) * 4096
        size = va_hi - va_lo
        total_island_bytes += size
        tot_fixups = int(fixup_per_4k[s : e + 1].sum())
        me = ent_per_4k[s : e + 1].mean()
        md = dist_per_4k[s : e + 1].mean()
        print(
            f"[{s:4d}:{e:4d}]  0x{va_lo:x}-0x{va_hi:x}  0x{size:<6x}  {tot_fixups:7d}  "
            f"{me:8.3f}  {md:9.1f}"
        )

    pure_bins = [i for i in range(n_bins) if i not in island_bins]
    pure_bytes = len(pure_bins) * 4096
    pure_entropy = ent_per_4k[pure_bins]
    pure_distinct = dist_per_4k[pure_bins]

    print(f"\nCFF-plumbing total: {len(island_bins)}/{n_bins} bins, {total_island_bytes} bytes "
          f"({total_island_bytes / 1024:.1f} KiB, {100 * total_island_bytes / (n_bins * 4096):.1f}%)")
    print(f"Pure-table total:   {len(pure_bins)}/{n_bins} bins, {pure_bytes} bytes "
          f"({pure_bytes / 1024 / 1024:.2f} MiB, {100 * pure_bytes / (n_bins * 4096):.1f}%)")
    print(f"  pure-table entropy: min={pure_entropy.min():.3f} max={pure_entropy.max():.3f} "
          f"mean={pure_entropy.mean():.3f}")
    print(f"  pure-table distinct-4B-rows/1024B: min={pure_distinct.min():.1f} "
          f"max={pure_distinct.max():.1f} mean={pure_distinct.mean():.1f}")


if __name__ == "__main__":
    main()
