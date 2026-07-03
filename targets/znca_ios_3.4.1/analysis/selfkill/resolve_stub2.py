#!/usr/bin/env python3
import lief
import capstone, sys
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import read_bytes

b = lief.parse('/home/vscode/app/targets/znca_ios_3.4.1/Crew')

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

def got_slot_for_stub(stub_va):
    code = read_bytes(stub_va, 12)
    insns = list(md.disasm(code, stub_va))
    adrp = insns[0]; ldr = insns[1]
    page = adrp.operands[1].imm
    off = ldr.operands[1].mem.disp
    return page + off

targets = [0x100c34fbc, 0x100c35004, 0x100c34470, 0x100c40240]
slots = {}
for t in targets:
    g = got_slot_for_stub(t)
    slots[t] = g

addr2sym = {}
for bnd in b.bindings:
    try:
        addr2sym[bnd.address] = bnd.symbol.name if bnd.symbol else None
    except Exception:
        pass

with open('/tmp/resolve_stub2_out.txt', 'w') as f:
    f.write(f"total bindings: {len(addr2sym)}\n")
    for t, g in slots.items():
        f.write(f"{hex(t)} GOT {hex(g)} -> sym: {addr2sym.get(g, 'NOT FOUND')}\n")
