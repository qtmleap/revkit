#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import read_bytes, BASE
import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

def dump(va, size):
    b = read_bytes(va, size)
    print(f"--- dump @ {hex(va)} size={hex(size)} ---")
    for insn in md.disasm(b, va):
        print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")

# the tiny function containing target
dump(0x10007d5ac, 0x18)
print()
dump(0x10007d5bc, 0x10)
print()
dump(0x10007d5c4, 0x44)

print("=== objc stub 0x100c40240 full ===")
dump(0x100c40240, 0x30)
