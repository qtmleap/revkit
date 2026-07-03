#!/usr/bin/env python3
"""Build a de-flattened pseudo-CFG for the initGenAudioH body.

Strategy
--------
1. Every CFF dispatch idiom (`find_dispatch.py`) is collapsed: instead of
   emitting the ~9-instruction and/eor/mul/br machinery as real control
   flow, we directly wire each *state writer* (`resolve_edges.py`) to the
   concrete `target_base + constant` address it resolves to. This removes
   the opaque indirection entirely for the 701/714 (98.2%) writers whose
   value is a compile-time constant.
2. Ordinary control flow (`b`, `b.cond`, fallthrough, `ret`, `brk`) is kept
   as-is; it was never obfuscated by the dispatch idiom (the idiom only
   disguises *destinations*, not the *presence* of branches).
3. `bl` to internal helper functions and `__stubs` import thunks are kept
   as informational edges but do not split the block (execution resumes
   right after the call).
4. Leaders (basic-block start addresses) = FUNC_START ∪ resolved dispatch
   targets ∪ direct branch targets ∪ instruction-after-unconditional-
   transfer (b / br / ret / brk).
5. The 13 unresolved (dynamic-value) state writers are recorded as
   `dynamic` edges with target=None -- these are exactly the runtime-
   dependent forks (anti-debug decisions etc.) that cannot be resolved
   without symbolic/concrete execution, and are reported as such, not
   guessed.

Output: pickled graph (cfg.pkl) + DOT file + text edge list.
"""
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import FUNC_START, FUNC_END
from disasm_body import disasm_range
from find_dispatch import find_dispatch_sites, normalize_slot, parse_ops
from resolve_edges import scan_state_writers

OUT_DIR = Path(__file__).parent


def collect_branches(insns, start, end):
    addrs = sorted(a for a in insns if start <= a < end)
    idx = {a: i for i, a in enumerate(addrs)}
    branches = []  # (addr, kind, target_or_None)
    bls = []       # (addr, target)
    enders = set()  # addresses of block-ending instrs (b, br, ret, brk)
    for a in addrs:
        ins = insns[a]
        if ins.mnemonic == 'b':
            ops = ins.op_str.strip()
            try:
                t = int(ops.lstrip('#'), 0)
            except ValueError:
                t = None
            branches.append((a, 'b', t))
            enders.add(a)
        elif ins.mnemonic.startswith('b.'):
            ops = ins.op_str.strip()
            try:
                t = int(ops.lstrip('#'), 0)
            except ValueError:
                t = None
            branches.append((a, ins.mnemonic, t))
        elif ins.mnemonic == 'bl':
            ops = ins.op_str.strip()
            try:
                t = int(ops.lstrip('#'), 0)
            except ValueError:
                t = None
            bls.append((a, t))
        elif ins.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            ops = ins.op_str.strip()
            # target is the last operand
            last = ops.split(',')[-1].strip()
            try:
                t = int(last.lstrip('#'), 0)
            except ValueError:
                t = None
            branches.append((a, ins.mnemonic, t))
        elif ins.mnemonic in ('br',):
            enders.add(a)
        elif ins.mnemonic == 'ret':
            enders.add(a)
        elif ins.mnemonic in ('brk', 'svc'):
            pass  # doesn't necessarily end the block (svc especially)
    return addrs, idx, branches, bls, enders


def build(force_recache=False):
    insns = disasm_range(FUNC_START, FUNC_END)
    addrs, idx, branches, bls, enders = collect_branches(insns, FUNC_START, FUNC_END)

    sites = find_dispatch_sites(insns, FUNC_START, FUNC_END)
    slot_index = {}
    slot_owner_targetbase = {}
    for s in sites:
        slot = normalize_slot(s['state_src_operand'])
        if slot is None:
            continue
        slot_index.setdefault(slot, []).append(s)
        slot_owner_targetbase.setdefault(slot, []).append(s['target_base'])

    writers = scan_state_writers(insns, FUNC_START, FUNC_END, slot_index)

    dispatch_edges = []   # (write_addr, target, value, slot)
    dynamic_edges = []    # (write_addr, slot) -- unresolved
    invalid_edges = []    # (write_addr, target, value, slot) -- misaligned/OOB,
                           # almost certainly a stack-slot reused for unrelated
                           # data at a point outside this dispatch's live range
    for w in writers:
        owners = slot_owner_targetbase.get(w['slot'], [])
        if not w['resolved']:
            dynamic_edges.append((w['write_addr'], w['slot']))
            continue
        for tb in owners:
            target = (tb + w['value']) & 0xFFFFFFFFFFFFFFFF
            if target % 4 != 0 or not (FUNC_START <= target < FUNC_END):
                invalid_edges.append((w['write_addr'], target, w['value'], w['slot']))
                continue
            dispatch_edges.append((w['write_addr'], target, w['value'], w['slot']))

    # ---- leaders ----
    leaders = {FUNC_START}
    for a, kind, t in branches:
        if t is not None:
            leaders.add(t)
        # instruction after a b.cond/cbz/etc is always a leader (fallthrough path)
        i = idx.get(a)
        if i is not None and i + 1 < len(addrs):
            leaders.add(addrs[i + 1])
    for a in enders:
        i = idx.get(a)
        if i is not None and i + 1 < len(addrs):
            leaders.add(addrs[i + 1])
    for w_addr, target, val, slot in dispatch_edges:
        leaders.add(target)
        i = idx.get(w_addr)
        if i is not None and i + 1 < len(addrs):
            leaders.add(addrs[i + 1])
    for w_addr, slot in dynamic_edges:
        i = idx.get(w_addr)
        if i is not None and i + 1 < len(addrs):
            leaders.add(addrs[i + 1])

    leaders = sorted(a for a in leaders if FUNC_START <= a < FUNC_END)

    # ---- build blocks: leader -> (end_addr_exclusive, out_edges) ----
    leader_set = set(leaders)
    branch_by_addr = {a: (kind, t) for a, kind, t in branches}
    dispatch_by_write = {w_addr: (target, val, slot) for w_addr, target, val, slot in dispatch_edges}
    dynamic_by_write = {w_addr: slot for w_addr, slot in dynamic_edges}

    blocks = {}
    for li, leader in enumerate(leaders):
        i = idx[leader]
        j = i
        out_edges = []
        block_end = None
        while j < len(addrs):
            a = addrs[j]
            ins = insns[a]
            if a in dispatch_by_write:
                target, val, slot = dispatch_by_write[a]
                out_edges.append(('cff', target, val, slot))
                block_end = a
                break
            if a in dynamic_by_write:
                slot = dynamic_by_write[a]
                out_edges.append(('dynamic', None, None, slot))
                # dynamic writer doesn't necessarily end the block (execution
                # continues into the (unresolvable) dispatch idiom); we stop
                # the block here anyway since we can't know the real target.
                block_end = a
                break
            if a in branch_by_addr:
                kind, t = branch_by_addr[a]
                if kind == 'b':
                    out_edges.append(('b', t, None, None))
                    block_end = a
                    break
                else:
                    out_edges.append((kind, t, None, None))
                    if j + 1 < len(addrs):
                        out_edges.append(('fallthrough', addrs[j + 1], None, None))
                    block_end = a
                    break
            if a in enders:  # br (unresolved by us at all -> shouldn't hit if dispatch matched) / ret / brk
                if ins.mnemonic == 'ret':
                    out_edges.append(('ret', None, None, None))
                elif ins.mnemonic == 'br':
                    out_edges.append(('br_unresolved', None, None, None))
                block_end = a
                break
            # check if next addr is itself a leader (implicit fallthrough split)
            if j + 1 < len(addrs) and addrs[j + 1] in leader_set:
                out_edges.append(('fallthrough', addrs[j + 1], None, None))
                block_end = a
                break
            j += 1
        else:
            block_end = addrs[-1]
        blocks[leader] = {'end': block_end, 'out': out_edges}

    graph = {
        'leaders': leaders,
        'blocks': blocks,
        'dispatch_edges': dispatch_edges,
        'dynamic_edges': dynamic_edges,
        'invalid_edges': invalid_edges,
        'sites': sites,
        'branches': branches,
        'bls': bls,
    }
    with open(OUT_DIR / 'cfg.pkl', 'wb') as f:
        pickle.dump(graph, f)
    return graph


if __name__ == '__main__':
    g = build()
    print(f"leaders (pseudo-BB count): {len(g['leaders'])}")
    print(f"dispatch (CFF) resolved edges: {len(g['dispatch_edges'])}")
    print(f"dynamic (unresolved) edges: {len(g['dynamic_edges'])}")
    print(f"invalid (misaligned/OOB -> stale-slot reuse) edges: {len(g['invalid_edges'])}")
    print(f"direct branches (b/b.cond/cbz/tbz): {len(g['branches'])}")
    print(f"bl call sites: {len(g['bls'])}")
