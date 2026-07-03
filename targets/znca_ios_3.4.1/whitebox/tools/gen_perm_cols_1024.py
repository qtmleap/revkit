#!/usr/bin/env python3
"""Reproduce perm_cols_1024.npy — count of "permutation columns" per 1024B block.

Interpretation (reconstructed): each 1024-byte block is reshaped as a
32x32 byte matrix (row-major). For each of the 32 columns (32 bytes each),
check whether the column, once sorted, equals exactly [0, 1, ..., 31]
(i.e. the column is literally a permutation of the 5-bit index space
0..31). Count how many of the 32 columns satisfy this per block.

CAVEAT (documented in znca_ios_whitebox_layout.md): this criterion is
essentially impossible to satisfy on real table data because byte values
are drawn from 0..255, not 0..31 — a column would need all 32 bytes to
land in the narrow 0..31 range AND be a complete bijection, which for
near-random high-entropy data has probability ~32!/32^32 ~ 1e-14 per
column. This is almost certainly why the saved npy is all zero: the
original probe was testing for a "5-bit permutation table" structure
(e.g. an S5-style substitution box embedded byte-aligned in row-major
32x32 layout) and found none. It does NOT prove no permutation structure
exists — only that it doesn't exist in this specific (32x32, mod-32,
row-major) framing. A follow-up should retry with:
  - permutation of 0..255 (full byte permutation, i.e. is this 1024B
    block itself a bijection __DATA -> __DATA, columns are irrelevant)
  - column-major instead of row-major
  - narrower row shapes (e.g. 4x256, 8x128) matching AES T-box strides

Usage:
    python3 gen_perm_cols_1024.py [--verify]
"""

import argparse
import sys

import numpy as np

from common import ANALYSIS_DIR, load_bin

BLOCK = 1024
DIM = 32  # 32x32 byte matrix


def compute(data: bytes) -> np.ndarray:
    assert len(data) % BLOCK == 0
    n_blocks = len(data) // BLOCK
    arr = np.frombuffer(data, dtype=np.uint8).reshape(n_blocks, DIM, DIM)
    target = np.arange(DIM, dtype=np.uint8)
    out = np.zeros(n_blocks, dtype=np.int32)
    for i in range(n_blocks):
        cols = arr[i].T
        sorted_cols = np.sort(cols, axis=1)
        out[i] = int(np.all(sorted_cols == target, axis=1).sum())
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--out", default=str(ANALYSIS_DIR / "perm_cols_1024.npy"))
    args = ap.parse_args()

    data = load_bin()
    result = compute(data)
    print(f"computed {result.shape[0]} blocks, min={result.min()} max={result.max()} sum={result.sum()}")

    if args.verify:
        saved = np.load(ANALYSIS_DIR / "perm_cols_1024.npy")
        if np.array_equal(result, saved):
            print("VERIFY OK: exact match (both all-zero)")
        else:
            sys.exit(1)
    else:
        np.save(args.out, result)
        print(f"saved to {args.out}")


if __name__ == "__main__":
    main()
