#!/usr/bin/env python3
"""Reproduce entropy_256.npy — Shannon entropy over non-overlapping 256B windows.

whitebox blob size = 2236416 bytes -> 2236416 / 256 = 8736 windows exactly,
matching the saved entropy_256.npy shape (8736,).

For each 256-byte block, computes Shannon entropy in bits/byte:
    H = -sum(p_i * log2(p_i)) for each byte value 0..255 present in the block.

Usage:
    python3 gen_entropy_256.py [--verify]
"""

import argparse
import math
import sys

import numpy as np

from common import ANALYSIS_DIR, load_bin

WINDOW = 256


def shannon_entropy(block: bytes) -> float:
    if not block:
        return 0.0
    counts = np.bincount(np.frombuffer(block, dtype=np.uint8), minlength=256)
    n = len(block)
    probs = counts[counts > 0] / n
    return float(-(probs * np.log2(probs)).sum())


def compute(data: bytes) -> np.ndarray:
    n_windows = len(data) // WINDOW
    assert len(data) % WINDOW == 0, "blob size must be a multiple of 256"
    out = np.empty(n_windows, dtype=np.float64)
    for i in range(n_windows):
        block = data[i * WINDOW : (i + 1) * WINDOW]
        out[i] = shannon_entropy(block)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="compare against saved npy")
    ap.add_argument("--out", default=str(ANALYSIS_DIR / "entropy_256.npy"))
    args = ap.parse_args()

    data = load_bin()
    result = compute(data)
    print(f"computed {result.shape[0]} windows, min={result.min():.4f} max={result.max():.4f} mean={result.mean():.4f}")

    if args.verify:
        saved = np.load(ANALYSIS_DIR / "entropy_256.npy")
        if np.allclose(result, saved):
            print("VERIFY OK: matches saved entropy_256.npy exactly (within float tolerance)")
        else:
            diff = np.abs(result - saved)
            print(f"VERIFY MISMATCH: max abs diff = {diff.max()} at index {diff.argmax()}")
            sys.exit(1)
    else:
        np.save(args.out, result)
        print(f"saved to {args.out}")


if __name__ == "__main__":
    main()
