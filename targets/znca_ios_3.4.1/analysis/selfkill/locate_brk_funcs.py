#!/usr/bin/env python3
import lief, bisect

b = lief.parse('/home/vscode/app/targets/znca_ios_3.4.1/Crew')
BASE = 0x100000000
starts = sorted(BASE + f for f in b.function_starts.functions)

targets = [0x1007d98b0, 0x1007d9a68, 0x100783fc8, 0x1007d594c, 0x100a29528]

with open('/tmp/locate_brk_funcs_out.txt', 'w') as f:
    for t in targets:
        idx = bisect.bisect_right(starts, t) - 1
        func_start = starts[idx]
        func_end = starts[idx + 1] if idx + 1 < len(starts) else None
        f.write(f'{hex(t)} -> containing function start={hex(func_start)} end(next start)={hex(func_end) if func_end else None} size={hex(func_end-func_start) if func_end else None}\n')
