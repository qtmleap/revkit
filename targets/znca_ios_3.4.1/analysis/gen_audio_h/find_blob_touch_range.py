#!/usr/bin/env python3
"""Task item #4: find the first and last instruction (by address / func offset)
where _gen_audio_h references the whitebox blob VA range [VA_LO, VA_HI) via
ADRP+ADD data-address formation, and dump the full ordered list for phase
inspection.
"""
import sys
sys.path.insert(0, '.')
from disasm_body import disasm_range
from common import FUNC_START, FUNC_END, VA_LO, VA_HI

insns = disasm_range(FUNC_START, FUNC_END)
addrs = sorted(insns)
idx = {a: i for i, a in enumerate(addrs)}

pending = {}
hits = []  # (addr_of_add, target)
for i, a in enumerate(addrs):
    ins = insns[a]
    if ins.mnemonic == 'adrp':
        parts = ins.op_str.split(',')
        reg = parts[0].strip()
        try:
            pending[reg] = int(parts[1].strip().lstrip('#'), 0)
        except ValueError:
            pass
    elif ins.mnemonic == 'add' and ',' in ins.op_str:
        parts = [p.strip() for p in ins.op_str.split(',')]
        if len(parts) == 3 and parts[1] in pending and parts[2].startswith('#'):
            try:
                imm = int(parts[2].lstrip('#'), 0)
                tgt = pending[parts[1]] + imm
                if VA_LO <= tgt < VA_HI:
                    hits.append((a, tgt))
            except ValueError:
                pass

print(f"total ADRP+ADD refs landing inside whitebox blob [0x{VA_LO:x},0x{VA_HI:x}): {len(hits)}")
if hits:
    first_a, first_t = hits[0]
    last_a, last_t = hits[-1]
    print(f"FIRST touch: addr=0x{first_a:x} (func+0x{first_a-FUNC_START:x})  target=0x{first_t:x} (blob+0x{first_t-VA_LO:x})")
    print(f"LAST  touch: addr=0x{last_a:x} (func+0x{last_a-FUNC_START:x})  target=0x{last_t:x} (blob+0x{last_t-VA_LO:x})")
    print(f"span across function body: func+0x{first_a-FUNC_START:x} .. func+0x{last_a-FUNC_START:x}  (function total size 0x{FUNC_END-FUNC_START:x})")

print(f"\ndistinct targets touched: {len(set(t for _,t in hits))}")
print("\nfirst 15 and last 15 touches (address order):")
for a, t in hits[:15]:
    print(f"  func+0x{a-FUNC_START:07x}  -> blob+0x{t-VA_LO:07x}")
print("  ...")
for a, t in hits[-15:]:
    print(f"  func+0x{a-FUNC_START:07x}  -> blob+0x{t-VA_LO:07x}")

# rough phase segmentation: bucket touches into 20 equal-width slices of the function
# and report density, to see if blob access clusters in particular regions.
FSIZE = FUNC_END - FUNC_START
NBUCKET = 20
buckets = [0] * NBUCKET
for a, t in hits:
    off = a - FUNC_START
    b = min(NBUCKET - 1, off * NBUCKET // FSIZE)
    buckets[b] += 1
print("\ndensity across function body (20 buckets):")
for i, c in enumerate(buckets):
    lo = FSIZE * i // NBUCKET
    hi = FSIZE * (i + 1) // NBUCKET
    print(f"  func+0x{lo:07x}-0x{hi:07x}: {c} touches" + ("  " + "#" * min(c, 60) if c else ""))
