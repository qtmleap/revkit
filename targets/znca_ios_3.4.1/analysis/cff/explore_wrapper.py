#!/usr/bin/env python3
"""Disassemble the small wrapper (0x100a29528..+0x7c) with capstone, to
validate our understanding of the CFF dispatch idiom before tackling the
335 KiB main body."""
import sys
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import read_bytes, WRAPPER_START, WRAPPER_END
import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

blob = read_bytes(WRAPPER_START, WRAPPER_END - WRAPPER_START)
for insn in md.disasm(blob, WRAPPER_START):
    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
