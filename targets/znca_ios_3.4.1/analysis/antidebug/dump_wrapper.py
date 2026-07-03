#!/usr/bin/env python3
from common import disasm_range

START = 0x100a29528
END = 0x100a29528 + 0x7c

for i in disasm_range(START, END):
    print(f"0x{i.address:09x}: {i.mnemonic}\t{i.op_str}")
