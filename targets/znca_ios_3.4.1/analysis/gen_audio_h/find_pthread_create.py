#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')
from disasm_body import disasm_range
from common import FUNC_START, FUNC_END
from find_dispatch import parse_ops

insns = disasm_range(FUNC_START, FUNC_END)
addrs = sorted(insns)
idx = {a: i for i, a in enumerate(addrs)}

PTHREAD_CREATE_STUB = 0x100c347d0

call_addr = None
for a in addrs:
    ins = insns[a]
    if ins.mnemonic == 'bl':
        try:
            t = int(ins.op_str.strip().lstrip('#'), 0)
        except ValueError:
            continue
        if t == PTHREAD_CREATE_STUB:
            call_addr = a
            break

print(f"pthread_create call site: 0x{call_addr:x} (func+0x{call_addr-FUNC_START:x})" if call_addr else "NOT FOUND")

i = idx[call_addr]
print("\n=== context (60 before, 20 after) ===")
for k in range(max(0, i-60), i+20):
    a = addrs[k]
    marker = " <== bl pthread_create" if a == call_addr else ""
    print(f"0x{a:x} (func+0x{a-FUNC_START:x}): {insns[a].mnemonic} {insns[a].op_str}{marker}")
