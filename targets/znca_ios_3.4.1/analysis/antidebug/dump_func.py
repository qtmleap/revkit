#!/usr/bin/env python3
"""Disassemble the initGenAudioH body [0x100783fc8, 0x1007d594c) and dump to text."""
from common import disasm_range

START = 0x100783fc8
END = 0x1007d594c

def main():
    insns = disasm_range(START, END)
    out_path = "/tmp/initgenaudioh_body.txt"
    with open(out_path, "w") as f:
        for i in insns:
            f.write(f"0x{i.address:09x}: {i.mnemonic}\t{i.op_str}\n")
    print(f"wrote {len(insns)} insns to {out_path}")

if __name__ == "__main__":
    main()
