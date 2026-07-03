#!/usr/bin/env python3
"""Find backward (address-decreasing) branch targets within the function range,
which indicate genuine loops (as opposed to forward CFF dispatch)."""
from common import disasm_range

START = 0x100783fc8
END = 0x1007d594c

BRANCH_MNEM = {"b", "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge", "b.lo",
               "b.hs", "b.hi", "b.ls", "b.mi", "b.pl", "b.vs", "b.vc",
               "cbz", "cbnz", "tbz", "tbnz", "bl"}

def main():
    insns = disasm_range(START, END)
    loops = []
    for i in insns:
        mnem = i.mnemonic
        if mnem not in BRANCH_MNEM:
            continue
        # operand: for b/bl it's just target; for cbz/cbnz it's reg,target; for tbz/tbnz reg,bit,target
        parts = i.op_str.split(",")
        target_str = parts[-1].strip()
        if not target_str.startswith("#0x") and not target_str.startswith("0x"):
            continue
        try:
            target = int(target_str.replace("#", ""), 16)
        except ValueError:
            continue
        if START <= target < i.address:
            dist = i.address - target
            loops.append((i.address, mnem, i.op_str, target, dist))
    loops.sort(key=lambda t: t[4])
    print(f"total backward branches: {len(loops)}")
    for addr, mnem, op, target, dist in loops:
        if dist <= 0x80:
            print(f"0x{addr:09x}: {mnem} {op}  <- target 0x{target:09x} dist=0x{dist:x}")

if __name__ == "__main__":
    main()
