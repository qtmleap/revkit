#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import read_bytes, read_u64

with open('/tmp/read_refs_out.txt', 'w') as f:
    # selref at 0x100f1e000+0xc30
    selref_addr = 0x100f1e000 + 0xc30
    selref_ptr = read_u64(selref_addr)
    f.write(f"selref @ {hex(selref_addr)} -> {hex(selref_ptr) if selref_ptr else None}\n")
    if selref_ptr:
        s = read_bytes(selref_ptr, 64)
        if s:
            z = s.split(b'\x00')[0]
            f.write(f"  selector string: {z!r}\n")

    # class ref at 0x100f26000+0xe70
    classref_addr = 0x100f26000 + 0xe70
    classref_ptr = read_u64(classref_addr)
    f.write(f"classref @ {hex(classref_addr)} -> {hex(classref_ptr) if classref_ptr else None}\n")

    # second selref pair at 0x100c40260 (0xc38)
    selref_addr2 = 0x100f1e000 + 0xc38
    selref_ptr2 = read_u64(selref_addr2)
    f.write(f"selref2 @ {hex(selref_addr2)} -> {hex(selref_ptr2) if selref_ptr2 else None}\n")
    if selref_ptr2:
        s = read_bytes(selref_ptr2, 64)
        if s:
            z = s.split(b'\x00')[0]
            f.write(f"  selector2 string: {z!r}\n")
