#!/usr/bin/env python3
"""Export the de-flattened pseudo-CFG (from build_cfg.py) to graphviz DOT.

Produces:
  - cfg_full.dot        : the entire de-flattened graph (13k+ nodes; too big
                           to eyeball, but useful for tooling / `dot -Tsvg`
                           on a subrange, or grep-based path queries).
  - cfg_zone_<reg>.dot   : one DOT per stack "zone" base register (x19, x20,
                           x21, x22, x23, x24, x25, x26, x28), restricted to
                           blocks whose address falls inside that zone's
                           observed dispatch-site address span. This is the
                           closest approximation to "副次ディスパッチ変数ごと
                           の疑似関数" available, since (unlike the doc's
                           original hypothesis) there is no small family of
                           shared global dispatch variables -- see the
                           accompanying markdown for the correction.
"""
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import FUNC_START, FUNC_END
from find_dispatch import normalize_slot

OUT_DIR = Path(__file__).parent


def load_graph():
    with open(OUT_DIR / 'cfg.pkl', 'rb') as f:
        return pickle.load(f)


def node_label(addr):
    return f'n_{addr:x}'


def emit_dot(path, blocks, leaders_subset=None):
    leaders = leaders_subset if leaders_subset is not None else blocks.keys()
    lines = ['digraph cfg {', '  rankdir=TB;', '  node [shape=box, fontname="monospace", fontsize=9];']
    for leader in leaders:
        b = blocks.get(leader)
        if b is None:
            continue
        lines.append(f'  {node_label(leader)} [label="0x{leader:x}"];')
        for kind, target, val, slot in b['out']:
            if kind == 'cff' and target is not None:
                lines.append(f'  {node_label(leader)} -> {node_label(target)} '
                              f'[label="cff state={val}", color=red];')
            elif kind in ('b', 'fallthrough') and target is not None:
                color = 'black' if kind == 'b' else 'gray'
                lines.append(f'  {node_label(leader)} -> {node_label(target)} [color={color}];')
            elif kind.startswith('b.') or kind in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                if target is not None:
                    lines.append(f'  {node_label(leader)} -> {node_label(target)} '
                                  f'[label="{kind}", color=blue];')
            elif kind == 'dynamic':
                lines.append(f'  {node_label(leader)} -> dynamic_unresolved '
                              f'[label="dyn slot={slot}", color=orange, style=dashed];')
            elif kind in ('ret', 'br_unresolved'):
                lines.append(f'  {node_label(leader)} -> {kind}_{leader:x} [color=green];')
                lines.append(f'  {kind}_{leader:x} [shape=doublecircle, label="{kind}"];')
    lines.append('  dynamic_unresolved [shape=diamond, style=filled, fillcolor=orange, label="DYNAMIC\\n(unresolved)"];')
    lines.append('}')
    path.write_text('\n'.join(lines))


def compute_zone_spans(sites):
    spans = {}
    for s in sites:
        slot = normalize_slot(s['state_src_operand'])
        if slot is None:
            continue
        base = slot[0]
        lo, hi = spans.get(base, (s['br_addr'], s['br_addr']))
        spans[base] = (min(lo, s['br_addr']), max(hi, s['br_addr']) + 0x10)
    return spans


if __name__ == '__main__':
    g = load_graph()
    blocks = g['blocks']

    emit_dot(OUT_DIR / 'cfg_full.dot', blocks)
    print(f"wrote cfg_full.dot with {len(blocks)} nodes")

    spans = compute_zone_spans(g['sites'])
    for zone, (lo, hi) in sorted(spans.items()):
        subset = [l for l in blocks if lo <= l < hi]
        emit_dot(OUT_DIR / f'cfg_zone_{zone}.dot', blocks, subset)
        print(f"wrote cfg_zone_{zone}.dot with {len(subset)} nodes (span 0x{lo:x}-0x{hi:x}, "
              f"{sum(1 for s in g['sites'] if normalize_slot(s['state_src_operand']) and normalize_slot(s['state_src_operand'])[0]==zone)} dispatch sites)")
