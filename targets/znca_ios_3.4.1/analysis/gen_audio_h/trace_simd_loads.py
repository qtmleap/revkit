#!/usr/bin/env python3
"""Trace the base/index register origin of the 8 SIMD `ldr qN, [Xbase, Xindex]`
register+register loads in _gen_audio_h, walking backward across CFF-resolved
pseudo-basic-block boundaries using cfg.pkl's dispatch_edges/branches to find
true predecessors (since the immediately-preceding bytes in file order are
NOT necessarily the actual predecessor once CFF has scrambled block layout).
"""
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import FUNC_START, FUNC_END, VA_LO, VA_HI
from disasm_body import disasm_range
from find_dispatch import parse_ops

insns = disasm_range(FUNC_START, FUNC_END)
addrs = sorted(insns)
idx = {a: i for i, a in enumerate(addrs)}

with open(Path(__file__).parent / 'cfg.pkl', 'rb') as f:
    g = pickle.load(f)

leaders = g['leaders']
blocks = g['blocks']
leader_arr = leaders  # sorted list

import bisect

def block_containing(addr):
    i = bisect.bisect_right(leader_arr, addr) - 1
    if i < 0:
        return None
    return leader_arr[i]

# build predecessor map: for every block, who points to it?
preds = {}
for leader, b in blocks.items():
    for e in b['out']:
        kind = e[0]
        tgt = e[1]
        if kind in ('cff', 'b', 'fallthrough') and tgt is not None:
            preds.setdefault(tgt, []).append((leader, kind))
        elif kind.startswith('b.') or kind in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            if tgt is not None:
                preds.setdefault(tgt, []).append((leader, kind))

TARGETS = [
    (0x10095c6c8, 'ldr q0, [x9, x8]'),
    (0x1009e73b0, 'ldr q0, [x9, x8]'),
    (0x1009ec2e0, 'ldr q0, [x9, x8]'),
    (0x1009ece78, 'ldr q0, [x9, x8]'),
    (0x1009ef5a4, 'ldr q0, [x10, x9]'),
    (0x100a0d8d4, 'ldr q0, [x9, x8]'),
    (0x100a1cdac, 'ldr q0, [x9, x8]'),
    (0x100a1dff8, 'ldr q0, [x8, x11]'),
]


def instrs_in_block(leader):
    b = blocks[leader]
    end = b['end']
    i = idx[leader]
    j = idx[end]
    return addrs[i:j+1]


def dump_block(leader, upto=None, tail=40):
    ins_list = instrs_in_block(leader)
    if upto is not None:
        ins_list = [a for a in ins_list if a <= upto]
    ins_list = ins_list[-tail:]
    lines = []
    for a in ins_list:
        ins = insns[a]
        lines.append(f"    0x{a:x}: {ins.mnemonic} {ins.op_str}")
    return lines


def find_def_in_block(leader, upto_addr, reg):
    """Scan block backward from upto_addr (exclusive) for last write to reg."""
    ins_list = [a for a in instrs_in_block(leader) if a < upto_addr]
    for a in reversed(ins_list):
        ins = insns[a]
        ops = parse_ops(ins.op_str)
        if not ops:
            continue
        dst = ops[0]
        # normalize wN vs xN name match loosely (same reg number, ignore width)
        if dst == reg:
            return a, ins
        # also match if dst is w-form of an x-form reg name request or vice versa
        if dst[0] in 'wx' and reg[0] in 'wx' and dst[1:] == reg[1:]:
            return a, ins
    return None


def trace_register(leader, use_addr, reg, depth=0, visited=None, max_depth=6):
    """Backward walk: find where `reg` is defined, following predecessor
    blocks (via CFF-resolved edges) if not defined within the current block."""
    if visited is None:
        visited = set()
    result = []
    definition = find_def_in_block(leader, use_addr, reg)
    if definition is not None:
        a, ins = definition
        result.append((leader, a, ins.mnemonic, ins.op_str))
        # if it's a mov/adrp/add-immediate we can stop; if it's `mov reg, otherreg`
        # or add reg, otherreg, ... follow the source register too (one more hop)
        ops = parse_ops(ins.op_str)
        if ins.mnemonic in ('mov',) and len(ops) == 2 and ops[1] and ops[1][0] in 'wx' and not ops[1].lstrip('-').isdigit():
            # register-to-register mov; keep tracing that source reg from same point
            src = ops[1]
            if depth < max_depth:
                sub = trace_register(leader, a, src, depth + 1, visited, max_depth)
                result.extend(sub)
        return result
    # not defined in this block -> walk predecessors
    key = (leader, reg)
    if key in visited or depth >= max_depth:
        return [(leader, None, 'UNRESOLVED(depth/visited limit)', reg)]
    visited.add(key)
    pred_list = preds.get(leader, [])
    if not pred_list:
        return [(leader, None, 'UNRESOLVED(no predecessors found)', reg)]
    for pred_leader, kind in pred_list[:3]:  # cap fan-in explored
        pend = blocks[pred_leader]['end']
        sub = trace_register(pred_leader, pend + 4, reg, depth + 1, visited, max_depth)
        result.append((leader, None, f'-> pred block 0x{pred_leader:x} via {kind}', reg))
        result.extend(sub)
    return result


for site_addr, mnem_op in TARGETS:
    print("=" * 100)
    print(f"SITE 0x{site_addr:x}: {mnem_op}")
    leader = block_containing(site_addr)
    print(f"  containing pseudo-block leader: 0x{leader:x}  (offset from func start: 0x{site_addr - FUNC_START:x})")
    print(f"  preceding instructions in block:")
    for l in dump_block(leader, upto=site_addr, tail=25):
        print(l)
    ops = parse_ops(insns[site_addr].op_str)
    # ops[-1] like "[x9, x8]" -> split
    membrace = ops[-1] if len(ops) == 2 else ','.join(ops[1:])
    inner = membrace.strip('[]')
    parts = [p.strip() for p in inner.split(',')]
    base_reg, idx_reg = parts[0], parts[1]
    print(f"\n  base register = {base_reg}, index register = {idx_reg}")

    print(f"\n  --- tracing base register {base_reg} ---")
    trace = trace_register(leader, site_addr, base_reg)
    for t in trace:
        l, a, m, o = t
        if a is not None:
            print(f"    [block 0x{l:x}] 0x{a:x}: {m} {o}")
        else:
            print(f"    [block 0x{l:x}] {m}")

    print(f"\n  --- tracing index register {idx_reg} ---")
    trace2 = trace_register(leader, site_addr, idx_reg)
    for t in trace2:
        l, a, m, o = t
        if a is not None:
            print(f"    [block 0x{l:x}] 0x{a:x}: {m} {o}")
        else:
            print(f"    [block 0x{l:x}] {m}")
    print()
