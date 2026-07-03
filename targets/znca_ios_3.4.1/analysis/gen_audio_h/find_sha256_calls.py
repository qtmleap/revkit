#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from disasm_body import disasm_range
from common import FUNC_START, FUNC_END
from collections import Counter

insns = disasm_range(FUNC_START, FUNC_END)
addrs = sorted(insns)

bl_targets = Counter()
bl_sites = []
for a in addrs:
    ins = insns[a]
    if ins.mnemonic == 'bl':
        try:
            t = int(ins.op_str.strip().lstrip('#'), 0)
        except ValueError:
            continue
        bl_targets[t] += 1
        bl_sites.append((a, t))

print(f"total bl instructions: {len(bl_sites)}, distinct targets: {len(bl_targets)}")

funcs = {0x1006c8c8c: 'sha256_fn_A (references __TEXT K copy 0xcae7e0)',
         0x1006ec35c: 'sha256_fn_B (references whitebox-blob K copy 0xf77da0)'}
for addr, name in funcs.items():
    print(f"\n{name} @ 0x{addr:x}: called {bl_targets.get(addr,0)} times from _gen_audio_h")
    sites = [s for s in bl_sites if s[1] == addr]
    for s in sites[:30]:
        print(f"  call site 0x{s[0]:x} (func+0x{s[0]-FUNC_START:x})")

print("\ntop 30 most-called bl targets overall:")
for t, c in bl_targets.most_common(30):
    print(f"  0x{t:x}  calls={c}")
