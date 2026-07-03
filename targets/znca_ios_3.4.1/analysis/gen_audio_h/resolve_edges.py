#!/usr/bin/env python3
"""Resolve CFF dispatch edges.

For each dispatch idiom site found by find_dispatch.py we know:
  - target_base (a fixed VA, computable at rest, "this site's own home
    address" essentially -- always target_base == br_addr + 4 for type B,
    or (adr TT) + word_at(TT) for type A, which in every sample we saw also
    reduces to the instruction immediately following the site's own embedded
    word, i.e. target_base is basically "the address physically following
    this dispatch instance").
  - state_reg, and the exact (base_reg, imm_offset) memory slot that feeds
    state_reg for this particular site.

The actual jump target executed at runtime is `target_base + state`, where
`state` was written into that private slot by a `str` instruction reached
earlier along the executed path. We scan the *entire* function body for every
`str`/`stur` that targets one of the known dispatch slots, backward-trace its
source register to a literal constant (mov/movz/movn, optionally
movz+movk pairs, or wzr/xzr), and -- if resolvable -- compute the concrete
edge `write_site -> target_base + constant`.

Writes whose source cannot be reduced to a compile-time constant in a short
backward window are flagged `dynamic` (this is exactly where genuine
runtime-dependent control flow, e.g. anti-debug results, would show up) and
are reported, not guessed.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import FUNC_START, FUNC_END
from disasm_body import disasm_range
from find_dispatch import find_dispatch_sites, parse_ops, normalize_slot

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def const_from_mov(ins):
    """Return (width, value) if `ins` is a mov/movz/movn/orr-with-xzr style
    constant load, else None. Does not handle movk (caller chains)."""
    ops = parse_ops(ins.op_str)
    if not ops:
        return None
    dst = ops[0]
    width = 64 if dst.startswith('x') else 32
    if ins.mnemonic in ('mov', 'movz'):
        if len(ops) == 2:
            try:
                val = int(ops[1].lstrip('#'), 0)
            except ValueError:
                # e.g. `mov x8, x9` register-to-register, not constant
                if ops[1] in ('xzr', 'wzr'):
                    return dst, width, 0
                return None
            return dst, width, val & (MASK64 if width == 64 else MASK32)
        elif len(ops) == 3 and 'lsl' in ops[2]:
            try:
                val = int(ops[1].lstrip('#'), 0)
                shift = int(ops[2].split('#')[1].rstrip(')'), 0)
            except (ValueError, IndexError):
                return None
            return dst, width, (val << shift) & (MASK64 if width == 64 else MASK32)
    elif ins.mnemonic == 'movn':
        if len(ops) == 2:
            try:
                val = int(ops[1].lstrip('#'), 0)
            except ValueError:
                return None
            inv = (~val) & (MASK64 if width == 64 else MASK32)
            return dst, width, inv
        elif len(ops) == 3 and 'lsl' in ops[2]:
            try:
                val = int(ops[1].lstrip('#'), 0)
                shift = int(ops[2].split('#')[1].rstrip(')'), 0)
            except (ValueError, IndexError):
                return None
            inv = (~(val << shift)) & (MASK64 if width == 64 else MASK32)
            return dst, width, inv
    return None


def movk_apply(base_val, width, ins):
    ops = parse_ops(ins.op_str)
    if ins.mnemonic != 'movk' or len(ops) not in (2, 3):
        return None
    try:
        val = int(ops[1].lstrip('#'), 0)
    except ValueError:
        return None
    shift = 0
    if len(ops) == 3 and 'lsl' in ops[2]:
        try:
            shift = int(ops[2].split('#')[1].rstrip(')'), 0)
        except (ValueError, IndexError):
            return None
    mask = MASK64 if width == 64 else MASK32
    clear_mask = ~(0xFFFF << shift) & mask
    return (base_val & clear_mask) | ((val << shift) & mask)


def trace_const_backward(insns, addrs, idx, str_addr, src_reg, window=6):
    """Backward-trace src_reg from the instruction at str_addr to find a
    constant definition. Returns (value, def_addrs) or None."""
    i = idx[str_addr]
    j = i - 1
    steps = 0
    # collect any movk chain first (movk instrs closest to the str, applied
    # on top of an earlier movz/mov), then the base mov
    movk_chain = []
    while j >= 0 and steps < window:
        a = addrs[j]
        ins = insns[a]
        ops = parse_ops(ins.op_str)
        if ins.mnemonic == 'movk' and ops and ops[0] == src_reg:
            movk_chain.append(ins)
            j -= 1
            steps += 1
            continue
        base = const_from_mov(ins)
        if base is not None and base[0] == src_reg:
            _, width, val = base
            def_addrs = [ins.addr]
            for mk in reversed(movk_chain):
                newval = movk_apply(val, width, mk)
                if newval is None:
                    return None
                val = newval
                def_addrs.append(mk.addr)
            return val, def_addrs
        j -= 1
        steps += 1
    return None


def scan_state_writers(insns, start, end, slot_index):
    """slot_index: dict (base_reg, off) -> list of site dicts.
    Returns list of resolved/unresolved writer records."""
    addrs = sorted(a for a in insns if start <= a < end)
    idx = {a: i for i, a in enumerate(addrs)}
    records = []
    for a in addrs:
        ins = insns[a]
        if ins.mnemonic not in ('str', 'stur'):
            continue
        ops = parse_ops(ins.op_str)
        if len(ops) < 2:
            continue
        src_reg = ops[0]
        slot = normalize_slot(','.join(ops[1:]))
        if slot is None or slot not in slot_index:
            continue
        # immediate wzr/xzr write
        if src_reg in ('wzr', 'xzr'):
            records.append({
                'write_addr': a, 'slot': slot, 'value': 0,
                'def_addrs': [a], 'resolved': True,
            })
            continue
        res = trace_const_backward(insns, addrs, idx, a, src_reg)
        if res is None:
            records.append({
                'write_addr': a, 'slot': slot, 'value': None,
                'def_addrs': [], 'resolved': False,
            })
        else:
            val, def_addrs = res
            records.append({
                'write_addr': a, 'slot': slot, 'value': val,
                'def_addrs': def_addrs, 'resolved': True,
            })
    return records


if __name__ == '__main__':
    insns = disasm_range(FUNC_START, FUNC_END)
    sites = find_dispatch_sites(insns, FUNC_START, FUNC_END)

    slot_index = {}
    for s in sites:
        slot = normalize_slot(s['state_src_operand'])
        if slot is None:
            continue
        slot_index.setdefault(slot, []).append(s)

    records = scan_state_writers(insns, FUNC_START, FUNC_END, slot_index)
    resolved = [r for r in records if r['resolved']]
    unresolved = [r for r in records if not r['resolved']]
    print(f"total state-slot writers found: {len(records)}")
    print(f"resolved (constant) writers: {len(resolved)}")
    print(f"unresolved (dynamic-value) writers: {len(unresolved)}")

    print("\nsample unresolved writers (first 20):")
    for r in unresolved[:20]:
        print(f"  0x{r['write_addr']:x} slot={r['slot']}")
