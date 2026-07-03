#!/usr/bin/env python3
"""Scan __DATA_CONST + __DATA for ALL chained-fixup pointer slots whose rebase target
equals the 'initGenAudioH' selector string address (0x100d60d7a), to find every selref
to this selector anywhere in the binary (not just the one already found)."""
import sys, struct
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import data, SEGMENTS, BASE

TARGET_STR_VA = 0x100d60d7a

d = data()
results = []
for vaddr, vsize, fileoff, filesize, name in SEGMENTS:
    if name not in ('__DATA_CONST', '__DATA'):
        continue
    n = filesize // 8
    for i in range(n):
        off = fileoff + i * 8
        raw = struct.unpack_from('<Q', d, off)[0]
        bind = (raw >> 63) & 1
        if bind:
            continue
        target36 = raw & 0xFFFFFFFFF
        va = BASE + target36
        if va == TARGET_STR_VA:
            slot_va = vaddr + i * 8
            results.append((slot_va, name))

with open('/tmp/all_selrefs_out.txt', 'w') as f:
    f.write(f'total selref slots pointing to "initGenAudioH" string @ {hex(TARGET_STR_VA)}: {len(results)}\n')
    for slot_va, seg in results:
        f.write(f'  {hex(slot_va)} (seg {seg})\n')
