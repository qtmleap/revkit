#!/usr/bin/env python3
"""Full-detail dump of every memory operation (through an x19-derived alias
register) whose resolved stack offset falls inside [0x3b000, 0x45380] -- the
zone the 8 SIMD `ldr q0,[Xbase,Xindex]` sites read from. Prints exact source
instruction addresses and both the alias-defining `add` instructions and the
consuming memory op, for direct inspection.
"""
import sys, re
sys.path.insert(0, '.')
from disasm_body import disasm_range
from common import FUNC_START, FUNC_END
from find_dispatch import parse_ops

insns = disasm_range(FUNC_START, FUNC_END)
addrs = sorted(insns)
idx = {a: i for i, a in enumerate(addrs)}

pat_add12 = re.compile(r'^(x\d+|x19),\s*x19,\s*#(0x[0-9a-f]+|\d+),\s*lsl\s*#12$')

LO, HI = 0x3b000, 0x45380

n = len(addrs)
rows = []
for ii in range(n):
    a = addrs[ii]
    ins = insns[a]
    if ins.mnemonic != 'add':
        continue
    m = pat_add12.match(ins.op_str)
    if not m:
        continue
    dst = m.group(1)
    hi = int(m.group(2), 0) << 12
    total = hi
    last_addr = a
    add1_addr = a
    add2_addr = None
    if ii + 1 < n:
        nxt = insns[addrs[ii + 1]]
        if nxt.mnemonic == 'add':
            ops2 = parse_ops(nxt.op_str)
            if len(ops2) == 3 and ops2[0] == dst and ops2[1] == dst and ops2[2].startswith('#'):
                try:
                    lo = int(ops2[2].lstrip('#'), 0)
                    total += lo
                    last_addr = addrs[ii + 1]
                    add2_addr = last_addr
                except ValueError:
                    pass
    if not (LO <= total <= HI):
        continue
    i2 = idx[last_addr]
    if i2 + 1 >= n:
        continue
    use_addr = addrs[i2 + 1]
    use = insns[use_addr]
    m2 = re.search(r'\[([^\]]+)\]', use.op_str)
    if not m2:
        continue
    parts = [p.strip() for p in m2.group(1).split(',')]
    if parts[0] != dst:
        continue
    rows.append((total, add1_addr, add2_addr, use_addr, use.mnemonic, use.op_str))

rows.sort()
print(f"total ops: {len(rows)}\n")
for total, a1, a2, ua, m, o in rows:
    print(f"stack_off=0x{total:06x}  alias_def=0x{a1:x}{'/0x'+format(a2,'x') if a2 else ''}  use=0x{ua:x} (func+0x{ua-FUNC_START:x}): {m} {o}")
