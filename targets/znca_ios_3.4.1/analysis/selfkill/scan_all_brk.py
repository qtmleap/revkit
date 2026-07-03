#!/usr/bin/env python3
"""Scan the ENTIRE Crew binary (all executable segments) for BRK #imm instructions.

BRK encoding (A64): bits [31:21] = 1101 0100 001, bits [4:0] = 00000
mask 0xFFE0001F == 0xD4200000, imm16 in bits [20:5].
"""
import sys, struct
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import data, SEGMENTS, BASE

FUNC_START = 0x100783fc8
FUNC_END = 0x1007d594c
WRAPPER_START = 0x100a29528
WRAPPER_END = 0x100a29528 + 0x7c

d = data()
results = []

# only scan __TEXT (0x100000000, size 0xe54000) since that's the only executable segment
vaddr, vsize, fileoff, filesize, name = SEGMENTS[0]
assert name == '__TEXT'

n = filesize // 4
for i in range(n):
    off = fileoff + i * 4
    word = struct.unpack_from('<I', d, off)[0]
    if (word & 0xFFE0001F) == 0xD4200000:
        imm16 = (word >> 5) & 0xFFFF
        va = vaddr + i * 4
        results.append((va, imm16))

with open('/tmp/all_brk_out.txt', 'w') as f:
    f.write(f'total BRK instructions found in __TEXT: {len(results)}\n\n')
    for va, imm16 in results:
        in_body = FUNC_START <= va < FUNC_END
        in_wrapper = WRAPPER_START <= va < WRAPPER_END
        tag = 'INSIDE initGenAudioH body' if in_body else ('INSIDE wrapper' if in_wrapper else '')
        f.write(f'{hex(va)}  brk #{hex(imm16)}  {tag}\n')
