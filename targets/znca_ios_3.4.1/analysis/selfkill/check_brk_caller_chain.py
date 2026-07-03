#!/usr/bin/env python3
import lief, bisect, sys, struct
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import data, SEGMENTS

b = lief.parse('/home/vscode/app/targets/znca_ios_3.4.1/Crew')
BASE = 0x100000000
starts = sorted(BASE + f for f in b.function_starts.functions)

FUNC_START = 0x100783fc8
FUNC_END = 0x1007d594c


def containing_func(va):
    idx = bisect.bisect_right(starts, va) - 1
    fs = starts[idx]
    fe = starts[idx + 1] if idx + 1 < len(starts) else None
    return fs, fe


def find_bl_callers(target):
    vaddr, vsize, fileoff, filesize, name = SEGMENTS[0]
    d = data()
    n = filesize // 4
    out = []
    for i in range(n):
        off = fileoff + i * 4
        word = struct.unpack_from('<I', d, off)[0]
        if (word >> 26) != 0b100101:
            continue
        imm26 = word & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        va = vaddr + i * 4
        t = va + (imm26 << 2)
        if t == target:
            out.append(va)
    return out


out_lines = []
fs, fe = containing_func(0x1007f17fc)
out_lines.append(f'0x1007f17fc belongs to function {hex(fs)}..{hex(fe)} size={hex(fe-fs) if fe else None}')
out_lines.append(f'  is this inside initGenAudioH body ({hex(FUNC_START)}..{hex(FUNC_END)})? {FUNC_START <= 0x1007f17fc < FUNC_END}')

callers2 = find_bl_callers(fs)
out_lines.append(f'callers of function {hex(fs)} (which itself calls the brk-func 0x1007d94d0): {len(callers2)}')
for c in callers2[:30]:
    cfs, cfe = containing_func(c)
    in_body = FUNC_START <= c < FUNC_END
    out_lines.append(f'  bl-site {hex(c)} in function {hex(cfs)} in_body={in_body}')

with open('/tmp/check_brk_caller_chain_out.txt', 'w') as f:
    f.write('\n'.join(out_lines) + '\n')
