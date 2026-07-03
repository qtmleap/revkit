#!/usr/bin/env python3
"""Find every occurrence of the CFF dispatch idiom in the initGenAudioH body
and resolve each site's `target_base`.

Two idiom variants observed:

  Type A (indirect, with an embedded delta word):
    adr   xA, #TT
    ldrsw xB, [xA]
    add   xA, xB, xA          ; xA = TT + word_at(TT)   == target_base
    and   xC2, xA, xSTATE
    mov   xD, #2
    mul   xC2, xC2, xD
    eor   xA, xA, xSTATE
    add   xA, xA, xC2         ; xA = target_base + state   (a^b + 2*(a&b) == a+b)
    br    xA

  Type B (direct, no indirection word):
    adr   xA, #TT              ; target_base = TT directly
    and   xC2, xA, xSTATE
    mov   xD, #2
    mul   xC2, xC2, xD
    eor   xA, xA, xSTATE
    add   xA, xA, xC2
    br    xA

There is also a decoy/opaque "cancelling sub/add" idiom that is NOT a real
keyed dispatch (target is constant regardless of state); we detect and tag
those separately as `kind='opaque'`.

For each real dispatch site we then walk backward a short window to find the
`ldr xSTATE, [base, #off]` that loaded the state register, to identify which
private state slot (base register + stack offset, or global address) drives
that particular site.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import read_i32, FUNC_START, FUNC_END
from disasm_body import disasm_range


def parse_ops(op_str):
    return [o.strip() for o in op_str.split(',')] if op_str else []


def find_dispatch_sites(insns, start, end):
    addrs = sorted(a for a in insns if start <= a < end)
    idx = {a: i for i, a in enumerate(addrs)}
    sites = []

    for i, a in enumerate(addrs):
        ins = insns[a]
        if ins.mnemonic != 'br':
            continue
        # walk backward: add, eor, mov(#2), mul, and, [ldrsw, add,] adr
        if i < 8:
            continue
        seq = [insns[addrs[i - k]] for k in range(1, 9) if i - k >= 0]
        # seq[0] = instr right before br (should be 'add')
        m_add2 = seq[0]
        m_eor = seq[1]
        m_mul = seq[2]
        m_movd = seq[3]
        m_and = seq[4]

        if m_add2.mnemonic != 'add':
            continue
        if m_eor.mnemonic != 'eor':
            continue
        if m_mul.mnemonic != 'mul':
            continue
        if m_movd.mnemonic not in ('mov', 'movz'):
            continue
        if m_and.mnemonic != 'and':
            continue

        and_ops = parse_ops(m_and.op_str)
        eor_ops = parse_ops(m_eor.op_str)
        if len(and_ops) != 3 or len(eor_ops) != 3:
            continue
        state_reg = and_ops[2]
        if eor_ops[2] != state_reg:
            continue
        # movd should be `mov xD, #2`
        movd_ops = parse_ops(m_movd.op_str)
        if len(movd_ops) != 2 or movd_ops[1].lstrip('#') != '2':
            continue

        # now determine type A vs B by looking further back
        m_next = seq[5] if len(seq) > 5 else None
        m_next2 = seq[6] if len(seq) > 6 else None

        kind = None
        TT = None
        word_val = None
        adr_addr = None

        if m_next is not None and m_next.mnemonic == 'adr':
            kind = 'B'
            ops = parse_ops(m_next.op_str)
            if len(ops) == 2:
                try:
                    TT = int(ops[1].lstrip('#'), 0)
                    adr_addr = m_next.addr
                except ValueError:
                    continue
        elif (m_next is not None and m_next.mnemonic == 'add' and
              m_next2 is not None and m_next2.mnemonic == 'ldrsw'):
            # need one more further back for adr (k=6 -> merge-add, k=7 -> ldrsw, k=8 -> adr)
            k = 8
            if i - k < 0:
                continue
            m_adr = insns[addrs[i - k]]
            if m_adr.mnemonic != 'adr':
                continue
            kind = 'A'
            ops = parse_ops(m_adr.op_str)
            if len(ops) == 2:
                try:
                    TT = int(ops[1].lstrip('#'), 0)
                    adr_addr = m_adr.addr
                except ValueError:
                    continue
        else:
            continue

        if TT is None:
            continue

        if kind == 'A':
            word_val = read_i32(TT)
            if word_val is None:
                continue
            target_base = (TT + word_val) & 0xFFFFFFFFFFFFFFFF
        else:
            target_base = TT

        # search backward from adr_addr for the ldr of state_reg
        state_load_addr = None
        state_src_operand = None
        j = idx[adr_addr] - 1
        back_window = 0
        while j >= 0 and back_window < 6:
            back_a = addrs[j]
            back_ins = insns[back_a]
            back_ops = parse_ops(back_ins.op_str)
            if back_ins.mnemonic in ('ldr', 'ldur') and back_ops and back_ops[0] == state_reg:
                state_load_addr = back_a
                if len(back_ops) >= 2:
                    state_src_operand = ','.join(back_ops[1:])
                break
            j -= 1
            back_window += 1

        sites.append({
            'kind': kind,
            'adr_addr': adr_addr,
            'br_addr': a,
            'TT': TT,
            'word_val': word_val,
            'target_base': target_base,
            'state_reg': state_reg,
            'state_load_addr': state_load_addr,
            'state_src_operand': state_src_operand,
        })

    return sites


def normalize_slot(operand):
    """Turn '[x19,#0x278]' into ('x19', 0x278); '[x19]' into ('x19', 0)."""
    if operand is None:
        return None
    op = operand.strip('[]')
    parts = [p.strip() for p in op.split(',')]
    base = parts[0]
    off = 0
    if len(parts) > 1 and parts[1].startswith('#'):
        try:
            off = int(parts[1].lstrip('#'), 0)
        except ValueError:
            off = None
    return (base, off)


if __name__ == '__main__':
    insns = disasm_range(FUNC_START, FUNC_END)
    sites = find_dispatch_sites(insns, FUNC_START, FUNC_END)
    from collections import Counter
    kinds = Counter(s['kind'] for s in sites)
    print(f"found {len(sites)} dispatch idiom instances: {dict(kinds)}")
    unresolved_state = sum(1 for s in sites if s['state_load_addr'] is None)
    print(f"sites where state load could not be found in backward window: {unresolved_state}")
    slots = Counter(normalize_slot(s['state_src_operand']) for s in sites if s['state_src_operand'])
    print(f"distinct state slots referenced by dispatch sites: {len(slots)}")
    for slot, cnt in slots.most_common(20):
        print(slot, cnt)
