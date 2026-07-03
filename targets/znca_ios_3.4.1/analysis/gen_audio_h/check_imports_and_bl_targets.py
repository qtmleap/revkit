#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
import lief
from disasm_body import disasm_range
from common import FUNC_START, FUNC_END
from collections import Counter

b = lief.parse('/home/vscode/app/targets/znca_ios_3.4.1/Crew')

print("=== imported symbols matching crypto/hash keywords ===")
for sym in b.imported_symbols:
    name = sym.name
    low = name.lower()
    if any(k in low for k in ('sha', 'hmac', 'aes', 'crypt', 'hash', 'cc_', 'digest')):
        print(f"  {name}")

print("\n=== __stubs section entries (if resolvable) ===")
for sec in b.sections:
    if sec.name in ('__stubs', '__stub_helper'):
        print(sec.name, hex(sec.virtual_address), hex(sec.size))

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

print(f"\n_gen_audio_h distinct bl targets: {len(bl_targets)}")
for t, c in sorted(bl_targets.items()):
    print(f"  0x{t:x}  calls={c}")
