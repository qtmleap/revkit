#!/usr/bin/env python3
"""Static scan: find every `svc #0x80` in the initGenAudioH body, identify the
syscall number via the nearest preceding `movz/mov w16,#imm` (or via a
constant assigned to x16/w16 through mov reg,reg -- best effort), and dump
the surrounding ~12 instructions before each SVC to look for movz #imm
literals feeding x0-x5 (candidate MIB words / signal numbers)."""
from common import disasm_range

START = 0x100783fc8
END = 0x1007d594c

def main():
    insns = list(disasm_range(START, END))
    addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}

    svc_sites = [ins for ins in insns if ins.mnemonic == "svc"]
    print(f"total svc instructions in range: {len(svc_sites)}")
    print()

    for svc in svc_sites:
        idx = addr_to_idx[svc.address]
        window = insns[max(0, idx - 14):idx]
        # find nearest movz/mov to w16/x16 for syscall number
        sysno = None
        sysno_addr = None
        for ins in reversed(window):
            if ins.mnemonic in ("movz", "mov") and ins.op_str.startswith(("w16,", "x16,")):
                sysno = ins.op_str
                sysno_addr = ins.address
                break
        print(f"=== SVC @ 0x{svc.address:09x}  (x16 setup: {sysno_addr and hex(sysno_addr)} -> {sysno}) ===")
        for ins in window:
            marker = ""
            if ins.mnemonic == "movz":
                marker = "  <-- movz"
            print(f"  0x{ins.address:09x}: {ins.mnemonic}\t{ins.op_str}{marker}")
        print()

if __name__ == "__main__":
    main()
