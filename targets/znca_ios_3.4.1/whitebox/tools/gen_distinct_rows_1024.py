#!/usr/bin/env python3
"""Reproduce distinct_rows_1024.npy — distinct 4-byte "row" count per 1024B block.

Interpretation: each non-overlapping 1024-byte block is reshaped as a
256 x 4 byte matrix (256 rows of 4 bytes = one machine word each), and the
number of *distinct* rows (as 4-byte tuples) is counted.

Rationale for row width = 4: verified empirically — this is the only row
width in {4, 8, 16, 32, 64} that reproduces the saved npy's max value of
exactly 256 (== number of rows only when row width is 4, since
1024 / 4 = 256 rows). This granularity is consistent with scanning for
repeated 32-bit table entries (round-key words / T-box column entries are
typically u32-sized in Chow/TFIT-style whiteboxes).

min=136 in the saved data means some 1024B blocks have heavy 4-byte-word
repetition (candidate: sparse/structured regions, padding, or zero-heavy
areas), while most blocks (mean=253.45) are close to fully distinct
(consistent with high-entropy round-table data where collisions among
256 random 4-byte words are still statistically likely to leave a handful
of duplicates - birthday-bound expectation for 256 draws from 2^32 space
is ~0 collisions, so any many-collision block indicates non-random content).

Usage:
    python3 gen_distinct_rows_1024.py [--verify]
"""

import argparse
import sys

import numpy as np

from common import ANALYSIS_DIR, load_bin

BLOCK = 1024
ROWLEN = 4
ROWS = BLOCK // ROWLEN  # 256


def compute(data: bytes) -> np.ndarray:
    assert len(data) % BLOCK == 0
    n_blocks = len(data) // BLOCK
    arr = np.frombuffer(data, dtype=np.uint8).reshape(n_blocks, ROWS, ROWLEN)
    out = np.empty(n_blocks, dtype=np.int32)
    for i, block in enumerate(arr):
        # view rows as opaque 4-byte tuples for uniqueness counting
        out[i] = len({row.tobytes() for row in block})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--out", default=str(ANALYSIS_DIR / "distinct_rows_1024.npy"))
    args = ap.parse_args()

    data = load_bin()
    result = compute(data)
    print(
        f"computed {result.shape[0]} blocks, min={result.min()} max={result.max()} "
        f"mean={result.mean():.2f}"
    )

    if args.verify:
        saved = np.load(ANALYSIS_DIR / "distinct_rows_1024.npy")
        if np.array_equal(result, saved):
            print("VERIFY OK: exact match with saved distinct_rows_1024.npy")
        else:
            mismatches = np.flatnonzero(result != saved)
            print(f"VERIFY MISMATCH: {len(mismatches)} blocks differ, first={mismatches[:10]}")
            sys.exit(1)
    else:
        np.save(args.out, result)
        print(f"saved to {args.out}")


if __name__ == "__main__":
    main()
