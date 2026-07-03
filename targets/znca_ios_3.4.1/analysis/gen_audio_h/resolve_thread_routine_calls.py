#!/usr/bin/env python3
"""Resolve the 3 bl targets found inside the pthread_create thread routine
(0x1006f418c-0x1006f444c) to import symbol names, reusing the stub->GOT->name
map building logic from resolve_stub_targets.py.
"""
import sys
sys.path.insert(0, '.')
import lief
from common import read_bytes
import capstone

b = lief.parse('/home/vscode/app/targets/znca_ios_3.4.1/Crew')
stub_map = {}
for bnd in b.bindings:
    sym = bnd.symbol
    addr = bnd.address
    if sym is not None:
        stub_map[addr] = sym.name

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False

STUBS_LO = 0x100c2fbec
STUBS_SZ = 0x5850
STUBS_HI = STUBS_LO + STUBS_SZ

blob = read_bytes(STUBS_LO, STUBS_SZ)
stub_to_gotaddr = {}
insns_list = list(md.disasm(blob, STUBS_LO))
i = 0
while i < len(insns_list):
    ins = insns_list[i]
    if ins.mnemonic == 'adrp' and i + 1 < len(insns_list):
        nxt = insns_list[i + 1]
        if nxt.mnemonic == 'ldr':
            parts_a = ins.op_str.split(',')
            page = int(parts_a[1].strip().lstrip('#'), 0)
            # parse ldr operand2 "[xN, #off]"
            import re
            m = re.search(r'#(0x[0-9a-f]+|\d+)\]', nxt.op_str)
            if m:
                off_imm = int(m.group(1), 0)
                got = page + off_imm
                stub_to_gotaddr[ins.address] = got
    i += 1

print(f"parsed {len(stub_to_gotaddr)} stub adrp+ldr pairs")

targets = [0x100c32fdc, 0x100c330a8, 0x100c33414]
for t in targets:
    if STUBS_LO <= t < STUBS_HI:
        got = stub_to_gotaddr.get(t)
        if got is not None:
            name = stub_map.get(got, '???')
            print(f"0x{t:x} (in __stubs) -> got=0x{got:x} -> {name}")
        else:
            print(f"0x{t:x} (in __stubs) -> no GOT resolved at this exact adrp addr; scanning nearby")
            # stub entries are typically 12 bytes (adrp+ldr+br); locate closest <= t
            cands = sorted(a for a in stub_to_gotaddr if a <= t)
            if cands:
                near = cands[-1]
                print(f"   nearest stub adrp at 0x{near:x} (delta {t-near}) -> got=0x{stub_to_gotaddr[near]:x} -> {stub_map.get(stub_to_gotaddr[near], '???')}")
    else:
        print(f"0x{t:x} -> NOT inside __stubs range [0x{STUBS_LO:x},0x{STUBS_HI:x}); it is a direct/local function")
