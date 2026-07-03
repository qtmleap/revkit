#!/usr/bin/env python3
"""Ground-truth chained-fixup (rebase) pointer scan over the whitebox VA range.

This supersedes the lost rebase_per_4k.npy / chain_per_4k.npy / chain_mask.npy
from the previous session. Those three arrays do not sum to a count that is
reproducible from any single well-defined chain-walk of the real
LC_DYLD_CHAINED_FIXUPS data (see znca_ios_whitebox_layout.md for the
discrepancy analysis: legacy sum = 69 + 2149 = 2218 vs. ground truth = 2775),
so rather than guess the exact (probably buggy/partial) legacy algorithm,
this script re-derives the fixup locations authoritatively via LIEF's
Mach-O chained-fixups parser (which walks the real page_start + next-delta
linked lists per Apple's dyld3 chained-fixups format) and produces:

  - pointer_fixup_per_4k.npy   (546,)   int64  — fixup count per 4 KiB bin
  - pointer_fixup_mask.npy     (279552,) bool  — True at each 8-byte-aligned
                                                   slot index that is a real
                                                   chained-fixup rebase site
  - pointer_fixup_targets.npy  (N, 2)   int64  — (address, target) VA pairs
                                                   for every fixup found,
                                                   N == pointer_fixup_mask.sum()

All addresses are whitebox-blob-relative unless noted (VA - VA_LO).

Usage:
    python3 gen_pointer_fixups.py [--save]
"""

import argparse

import lief
import numpy as np

from common import ANALYSIS_DIR, CREW_PATH, VA_HI, VA_LO


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--save", action="store_true")
    args = ap.parse_args()

    b = lief.parse(str(CREW_PATH))
    relocs = list(b.relocations)
    in_range = [r for r in relocs if VA_LO <= r.address < VA_HI]

    n_slots = (VA_HI - VA_LO) // 8
    n_bins = (VA_HI - VA_LO) // 4096

    mask = np.zeros(n_slots, dtype=bool)
    per_4k = np.zeros(n_bins, dtype=np.int64)
    pairs = []

    for r in in_range:
        slot = (r.address - VA_LO) // 8
        mask[slot] = True
        per_4k[(r.address - VA_LO) // 4096] += 1
        pairs.append((r.address, r.target))

    targets = np.array(pairs, dtype=np.int64)

    print(f"total chained-fixup rebase sites in whitebox range: {len(in_range)}")
    print(f"  all origin=CHAINED_FIXUPS, has_symbol=False (pure rebase, no bind): "
          f"{sum(1 for r in in_range if not r.has_symbol)}")
    print(f"  targets pointing back into whitebox range: "
          f"{sum(1 for _, t in pairs if VA_LO <= t < VA_HI)}")
    print(f"  targets pointing outside whitebox range: "
          f"{sum(1 for _, t in pairs if not (VA_LO <= t < VA_HI))}")
    print(f"per-4K bin: nonzero={np.count_nonzero(per_4k)}/{n_bins}, max={per_4k.max()}")

    top = np.argsort(per_4k)[::-1][:15]
    print("\ntop 15 densest 4K bins:")
    for i in top:
        if per_4k[i] == 0:
            break
        print(f"  bin {i:4d}  VA=0x{VA_LO + i * 4096:x}  count={per_4k[i]}")

    if args.save:
        np.save(ANALYSIS_DIR / "pointer_fixup_per_4k.npy", per_4k)
        np.save(ANALYSIS_DIR / "pointer_fixup_mask.npy", mask)
        np.save(ANALYSIS_DIR / "pointer_fixup_targets.npy", targets)
        print(f"\nsaved to {ANALYSIS_DIR}")


if __name__ == "__main__":
    main()
