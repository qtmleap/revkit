#!/usr/bin/env python3
import sys, bisect
sys.path.insert(0, '.')
import lief
from common import read_bytes, VA_LO, VA_HI
import capstone

THREAD_FN = 0x1006f418c

b = lief.parse('/home/vscode/app/targets/znca_ios_3.4.1/Crew')
fs = sorted(b.function_starts.functions)
BASE = 0x100000000
fs_va = [BASE + x for x in fs]
i = bisect.bisect_right(fs_va, THREAD_FN) - 1
func_start = fs_va[i]
func_end = fs_va[i+1] if i+1 < len(fs_va) else None
print(f"thread routine enclosing func_start=0x{func_start:x} func_end={hex(func_end)} size={hex(func_end-func_start)}")

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False

blob = read_bytes(func_start, min(func_end - func_start, 0x4000))
print(f"\n=== first 80 instructions of thread routine (from actual entry point 0x{THREAD_FN:x} search) ===")
count = 0
pending = {}
data_refs = {}
bl_targets = {}
for insn in md.disasm(blob, func_start):
    if insn.address < THREAD_FN:
        continue
    if count < 80:
        print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
    count += 1
    if insn.mnemonic == 'adrp':
        parts = insn.op_str.split(',')
        pending[parts[0].strip()] = int(parts[1].strip().lstrip('#'), 0)
    elif insn.mnemonic == 'add' and ',' in insn.op_str:
        parts = [p.strip() for p in insn.op_str.split(',')]
        if len(parts) == 3 and parts[1] in pending and parts[2].startswith('#'):
            try:
                imm = int(parts[2].lstrip('#'), 0)
                tgt = pending[parts[1]] + imm
                data_refs[tgt] = data_refs.get(tgt, 0) + 1
                pending[parts[0]] = tgt
            except ValueError:
                pass
    elif insn.mnemonic == 'bl':
        try:
            t = int(insn.op_str.strip().lstrip('#'), 0)
            bl_targets[t] = bl_targets.get(t, 0) + 1
        except ValueError:
            pass

print(f"\ntotal instructions decoded in this thread-routine func range: {count}")
print(f"distinct ADRP+ADD data targets: {len(data_refs)}")
wb = {a: c for a, c in data_refs.items() if VA_LO <= a < VA_HI}
print(f"of which fall in whitebox blob 0x{VA_LO:x}-0x{VA_HI:x}: {len(wb)}")
for a, c in sorted(wb.items())[:20]:
    print(f"  0x{a:x} (blob+0x{a-VA_LO:06x}) refs={c}")

print(f"\ndistinct bl targets: {len(bl_targets)}")
for t, c in sorted(bl_targets.items()):
    print(f"  0x{t:x} calls={c}")
