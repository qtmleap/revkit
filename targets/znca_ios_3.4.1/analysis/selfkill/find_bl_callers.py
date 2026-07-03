#!/usr/bin/env python3
"""Find all `bl <target>` call sites for a given target VA, across the whole __TEXT segment
(manual encoding decode, does not rely on r2/capstone's control-flow recovery which fails on
CFF-obscured functions with indirect `br` dispatch)."""
import sys, struct
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import data, SEGMENTS

TARGETS = [0x1007d94d0, 0x1007d594c]  # the func containing the 2 brk sites; the func right after initGenAudioH body

vaddr, vsize, fileoff, filesize, name = SEGMENTS[0]
assert name == '__TEXT'
d = data()
n = filesize // 4

results = {t: [] for t in TARGETS}
targets_set = set(TARGETS)

for i in range(n):
    off = fileoff + i * 4
    word = struct.unpack_from('<I', d, off)[0]
    if (word >> 26) != 0b100101:
        continue
    imm26 = word & 0x3FFFFFF
    if imm26 & 0x2000000:
        imm26 -= 0x4000000
    va = vaddr + i * 4
    target = va + (imm26 << 2)
    if target in targets_set:
        results[target].append(va)

with open('/tmp/bl_callers_out.txt', 'w') as f:
    for t, callers in results.items():
        f.write(f'target={hex(t)}: {len(callers)} callers\n')
        for c in callers[:50]:
            f.write(f'  bl-site {hex(c)}\n')
