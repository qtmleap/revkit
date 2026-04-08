#!/usr/bin/env python3
"""
Static analysis script for NFWebCrypto TFIT WB-AES encoding.
Extracts TFIT lookup tables, key schedules, and output S-boxes from
the NFWebCrypto.framework binary.

Usage:
    python3 analyze_tfit_nfwc.py <path_to_NFWebCrypto_binary>
"""

import struct
import sys
import math
from pathlib import Path


# --- Address map (file offsets, NOT virtual addresses) ---
# These are for Netflix iOS 15.48.1 (arm64)

TFIT_SYMBOLS = {
    # Device-specific WB-AES key schedules (224 bytes each)
    "TFIT_key_iAES11_mgkATV": 0x1ACF28,
    "TFIT_key_iAES11_mgkiPad": 0x1AD008,
    "TFIT_key_iAES11_mgkiPhone": 0x1AD0E8,
    # Round 9 re-encoding matrices (0x60 = 96 bytes each)
    "TFIT_rmat_iAES11_9_0": 0x1AD630,
    "TFIT_rmat_iAES11_9_1": 0x1AD690,
    "TFIT_rmat_iAES11_9_2": 0x1AD6F0,
    "TFIT_rmat_iAES11_9_3": 0x1AD750,
    "TFIT_rmat_iAES11_9_4": 0x1AD7B0,
    "TFIT_rmat_iAES11_9_5": 0x1AD810,
    # Round 10 re-encoding matrices (0x60 = 96 bytes each)
    "TFIT_rmat_iAES11_10_0": 0x1AD870,
    "TFIT_rmat_iAES11_10_1": 0x1AD8D0,
    "TFIT_rmat_iAES11_10_2": 0x1AD930,
    "TFIT_rmat_iAES11_10_3": 0x1AD990,
    "TFIT_rmat_iAES11_10_4": 0x1AD9F0,
    "TFIT_rmat_iAES11_10_5": 0x1ADA50,
    "TFIT_rmat_iAES11_10_6": 0x1ADAB0,
    "TFIT_rmat_iAES11_10_7": 0x1ADB10,
    # Round masks (4 bytes each)
    "TFIT_rmask_iAES11_9_0": 0x1ADB70,
    "TFIT_rmask_iAES11_10_0": 0x1ADB88,
    # Round lookup tables (16KB = 4096 x u32 each)
    "TFIT_rlut_iAES11_0": 0x1ADBA8,
    "TFIT_rlut_iAES11_1": 0x1B1BA8,
    "TFIT_rlut_iAES11_2": 0x1B5BA8,
    "TFIT_rlut_iAES11_3": 0x1B9BA8,
    "TFIT_rlut_iAES11_4": 0x1BDBA8,
    "TFIT_rlut_iAES11_5": 0x1C1BA8,
    "TFIT_rlut_iAES11_6": 0x1C5BA8,
    "TFIT_rlut_iAES11_7": 0x1C9BA8,
    "TFIT_rlut_iAES11_8": 0x1CDBA8,
    "TFIT_rlut_iAES11_9": 0x1D1BA8,
    "TFIT_rlut_iAES11_10": 0x1D5BA8,
    "TFIT_rlut_iAES11_11": 0x1D9BA8,
    # Output S-box tables (256 bytes each)
    "TFIT_out_iAES11_0": 0x1DDBA8,
    "TFIT_out_iAES11_1": 0x1DDCA8,
    "TFIT_out_iAES11_2": 0x1DDDA8,
    "TFIT_out_iAES11_3": 0x1DDEA8,
    "TFIT_out_iAES11_4": 0x1DDFA8,
    "TFIT_out_iAES11_5": 0x1DE0A8,
    "TFIT_out_iAES11_6": 0x1DE1A8,
    "TFIT_out_iAES11_7": 0x1DE2A8,
    "TFIT_out_iAES11_8": 0x1DE3A8,
    "TFIT_out_iAES11_9": 0x1DE4A8,
    "TFIT_out_iAES11_10": 0x1DE5A8,
    "TFIT_out_iAES11_11": 0x1DE6A8,
    "TFIT_out_iAES11_12": 0x1DE7A8,
    "TFIT_out_iAES11_13": 0x1DE8A8,
    "TFIT_out_iAES11_14": 0x1DE9A8,
    "TFIT_out_iAES11_15": 0x1DEAA8,
}

# Function addresses
FUNCTIONS = {
    "genModelGroupKeys": 0x1DB74,
    "encryptAes128Ecb": 0x1DDB8,  # encryptAes128Ecb(MGKType, u8*, u8*)
    "TFIT_wbaes_ecb_encrypt_iAES11": 0x248C4,
    "TFIT_r9_op_iAES11": 0x248DC,
    "TFIT_op_iAES11": 0x25CB0,
    "TFIT_wbaes_ecb_cipher_iAES11": 0x26C9C,
}


def entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            ent -= p * math.log2(p)
    return ent


def dump_key_schedule(binary: bytes, name: str, offset: int):
    """Dump a 224-byte WB-AES key schedule."""
    data = binary[offset : offset + 0xE0]
    print(f"\n{'='*60}")
    print(f"  {name} @ 0x{offset:06X} (224 bytes)")
    print(f"{'='*60}")
    for i in range(0, len(data), 16):
        row = data[i : i + 16]
        hexstr = " ".join(f"{b:02x}" for b in row)
        print(f"  [{i:3d}] {hexstr}")
    print(f"  Entropy: {entropy(data):.2f} bits/byte")


def dump_rlut_stats(binary: bytes, name: str, offset: int):
    """Analyze a 16KB round lookup table."""
    data = binary[offset : offset + 0x4000]
    values = struct.unpack("<4096I", data)
    unique = len(set(values))
    ent = entropy(data)
    print(f"  {name}: offset=0x{offset:06X}, entries=4096, "
          f"unique={unique}, entropy={ent:.2f} bits/byte")


def dump_output_sbox(binary: bytes, name: str, offset: int):
    """Dump a 256-byte output S-box."""
    data = binary[offset : offset + 0x100]
    ent = entropy(data)
    # Check if it's a permutation
    is_perm = len(set(data)) == 256
    print(f"  {name}: offset=0x{offset:06X}, entropy={ent:.2f}, "
          f"is_permutation={is_perm}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <NFWebCrypto binary>")
        sys.exit(1)

    binary_path = Path(sys.argv[1])
    binary = binary_path.read_bytes()
    print(f"Binary: {binary_path} ({len(binary)} bytes)")

    # Key schedules
    print("\n" + "=" * 60)
    print("  DEVICE-SPECIFIC KEY SCHEDULES")
    print("=" * 60)
    for name in ["TFIT_key_iAES11_mgkATV", "TFIT_key_iAES11_mgkiPad",
                  "TFIT_key_iAES11_mgkiPhone"]:
        dump_key_schedule(binary, name, TFIT_SYMBOLS[name])

    # Check if iPad and iPhone tables are identical
    ipad = binary[TFIT_SYMBOLS["TFIT_key_iAES11_mgkiPad"]:
                   TFIT_SYMBOLS["TFIT_key_iAES11_mgkiPad"] + 0xE0]
    iphone = binary[TFIT_SYMBOLS["TFIT_key_iAES11_mgkiPhone"]:
                     TFIT_SYMBOLS["TFIT_key_iAES11_mgkiPhone"] + 0xE0]
    print(f"\n  iPad == iPhone: {ipad == iphone}")

    # Round LUTs
    print("\n" + "=" * 60)
    print("  ROUND LOOKUP TABLES (rlut)")
    print("=" * 60)
    for i in range(12):
        name = f"TFIT_rlut_iAES11_{i}"
        dump_rlut_stats(binary, name, TFIT_SYMBOLS[name])

    # Output S-boxes
    print("\n" + "=" * 60)
    print("  OUTPUT S-BOX TABLES")
    print("=" * 60)
    for i in range(16):
        name = f"TFIT_out_iAES11_{i}"
        dump_output_sbox(binary, name, TFIT_SYMBOLS[name])

    # Round masks
    print("\n" + "=" * 60)
    print("  ROUND MASKS")
    print("=" * 60)
    for rnd in [9, 10]:
        count = 6 if rnd == 9 else 8
        base = TFIT_SYMBOLS[f"TFIT_rmask_iAES11_{rnd}_0"]
        for j in range(count):
            off = base + j * 4
            val = struct.unpack("<I", binary[off : off + 4])[0]
            print(f"  rmask_{rnd}_{j}: 0x{val:08X}")

    # Summary
    print("\n" + "=" * 60)
    print("  TFIT DATA SEGMENT SUMMARY")
    print("=" * 60)
    total_start = TFIT_SYMBOLS["TFIT_key_iAES11_mgkATV"]
    total_end = TFIT_SYMBOLS["TFIT_out_iAES11_15"] + 0x100
    total_size = total_end - total_start
    print(f"  Range: 0x{total_start:06X} - 0x{total_end:06X}")
    print(f"  Total size: {total_size} bytes ({total_size/1024:.1f} KB)")
    ent = entropy(binary[total_start:total_end])
    print(f"  Overall entropy: {ent:.2f} bits/byte")


if __name__ == "__main__":
    main()
