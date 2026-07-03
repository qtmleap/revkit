"""Shared constants for znca iOS 3.4.1 whitebox analysis tools.

All tools operate on the extracted __DATA.__data slice:
    targets/znca_ios_3.4.1/whitebox/whitebox_data_0x100f70000_0x101192000.bin

which corresponds to Crew (arm64 Mach-O, __TEXT vmaddr=0x100000000) VA range
0x100f70000 .. 0x101192000 (2236416 bytes / 2.133 MiB), file offset 0xf70000.
"""

from pathlib import Path

WHITEBOX_DIR = Path(__file__).resolve().parent.parent
BIN_PATH = WHITEBOX_DIR / "whitebox_data_0x100f70000_0x101192000.bin"
ANALYSIS_DIR = WHITEBOX_DIR / "analysis"

VA_LO = 0x100F70000
VA_HI = 0x101192000

CREW_PATH = WHITEBOX_DIR.parent / "Crew"

assert VA_HI - VA_LO == 2236416


def load_bin() -> bytes:
    return BIN_PATH.read_bytes()
