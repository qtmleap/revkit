#!/usr/bin/env python3
"""Print the small set of CFF dispatch edges that actually matter:
  - the 2 non-zero constant redirects (real long-range unconditional jumps
    materialized through the dispatch idiom instead of a plain `b`)
  - the 13 dynamic (data-dependent) writers, with their immediate defining
    context, which are the only truly runtime-dependent forks routed
    through the CFF machinery in this function.

Reproduces the evidence cited in
docs/spec/znca_ios_init_gen_audio_h_cff.md.
"""
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import FUNC_START, FUNC_END
from disasm_body import disasm_range

with open(Path(__file__).parent / 'cfg.pkl', 'rb') as f:
    g = pickle.load(f)

insns = disasm_range(FUNC_START, FUNC_END)
addrs = sorted(insns)
idx = {a: i for i, a in enumerate(addrs)}


def dump(addr, before=8, after=0):
    i = idx[addr]
    for k in range(max(0, i - before), i + 1 + after):
        aa = addrs[k]
        print(f"    0x{aa:x}: {insns[aa].mnemonic} {insns[aa].op_str}")


print("=== non-zero constant redirects (real jumps, not fallthrough no-ops) ===")
for w, target, val, slot in g['dispatch_edges']:
    if val != 0:
        print(f"write=0x{w:x} val={val} slot={slot} -> target=0x{target:x}")
        dump(w, before=4)
        print()

print("=== dynamic (data-dependent) writers ===")
for w, slot in g['dynamic_edges']:
    print(f"write=0x{w:x} slot={slot}")
    dump(w, before=10)
    print()
