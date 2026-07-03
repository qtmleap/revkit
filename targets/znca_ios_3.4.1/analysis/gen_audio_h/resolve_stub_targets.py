#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
import lief
from disasm_body import disasm_range
from common import FUNC_START, FUNC_END, read_bytes
from collections import Counter
import struct

b = lief.parse('/home/vscode/app/targets/znca_ios_3.4.1/Crew')

# Map __stubs entries to symbol names via the chained/lazy bindings.
# lief exposes b.symbols with a .value / .is_imported; for stub resolution,
# use dyld bind info: iterate b.dyld_chained_fixups or b.bindings.
stub_map = {}
try:
    for bnd in b.bindings:
        sym = bnd.symbol
        addr = bnd.address
        if sym is not None:
            stub_map[addr] = sym.name
except Exception as e:
    print("bindings iteration failed:", e)

print(f"resolved {len(stub_map)} bind records")

# find _CC_SHA256 related bind addresses
sha_binds = {a: n for a, n in stub_map.items() if 'SHA256' in n or 'SHA1' in n or 'MD5' in n}
print("crypto-related bind addresses (these are GOT/lazy-pointer slots, not stub code addrs):")
for a, n in sha_binds.items():
    print(f"  0x{a:x}  {n}")

# __stubs are short trampolines; each stub loads its GOT/lazy pointer and branches.
# Disassemble each stub in the __stubs section and record which GOT slot it loads from,
# to map stub_code_address -> symbol name.
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

STUBS_LO = 0x100c2fbec
STUBS_SZ = 0x5850
STUBS_HI = STUBS_LO + STUBS_SZ

blob = read_bytes(STUBS_LO, STUBS_SZ)
stub_to_gotaddr = {}
addr = STUBS_LO
off = 0
insns_list = list(md.disasm(blob, STUBS_LO))
i = 0
while i < len(insns_list):
    ins = insns_list[i]
    if ins.mnemonic == 'adrp' and i + 1 < len(insns_list):
        nxt = insns_list[i+1]
        if nxt.mnemonic in ('ldr',) :
            try:
                page = ins.operands[1].imm
                off_imm = nxt.operands[1].mem.disp
                got = page + off_imm
                stub_to_gotaddr[ins.address] = got
            except Exception:
                pass
    i += 1

print(f"\nparsed {len(stub_to_gotaddr)} stub adrp+ldr pairs")

# now cross reference stub start addresses against gen_audio_h's bl targets
insns = disasm_range(FUNC_START, FUNC_END)
addrs = sorted(insns)
bl_targets = Counter()
for a in addrs:
    ins = insns[a]
    if ins.mnemonic == 'bl':
        try:
            t = int(ins.op_str.strip().lstrip('#'), 0)
        except ValueError:
            continue
        bl_targets[t] += 1

print("\n_gen_audio_h bl targets that land inside __stubs, resolved to import symbol if possible:")
for t, c in sorted(bl_targets.items()):
    if STUBS_LO <= t < STUBS_HI:
        got = stub_to_gotaddr.get(t)
        if got is not None:
            name = stub_map.get(got, '???')
            print(f"  0x{t:x}  calls={c}  got=0x{got:x}  -> {name}")
        else:
            print(f"  0x{t:x} calls={c} (no got resolved)")

print("\n--- reverse lookup: stub address for _CC_SHA256 specifically ---")
sha256_got = 0x100e57288
sha256_stub = None
for stub_addr, got in stub_to_gotaddr.items():
    if got == sha256_got:
        sha256_stub = stub_addr
        break
print(f"_CC_SHA256 GOT slot = 0x{sha256_got:x}, stub trampoline address = {hex(sha256_stub) if sha256_stub else 'NOT FOUND'}")
if sha256_stub is not None:
    print(f"is this stub called (bl) from _gen_audio_h? calls={bl_targets.get(sha256_stub, 0)}")
