#!/usr/bin/env python3
"""Linear per-4-byte-slot capstone disassembly of _gen_audio_h/_gen_audio_h2
tail-merged body (0x10090f20c..0x100a208fc, ~1.07 MiB).

Same technique as analysis/cff/disasm_body.py: decode every 4-byte slot
independently so embedded CFF delta words never desync the byte alignment.
"""
import pickle
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import read_bytes, FUNC_START, FUNC_END

import capstone

CACHE = Path(__file__).parent / 'insns.pkl'


class Insn:
    __slots__ = ('addr', 'mnemonic', 'op_str', 'size', 'bytes_')

    def __init__(self, addr, mnemonic, op_str, size, bytes_):
        self.addr = addr
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.size = size
        self.bytes_ = bytes_

    def __repr__(self):
        return f"0x{self.addr:x}: {self.mnemonic} {self.op_str}"


def disasm_range(start, end, force=False):
    if CACHE.exists() and not force:
        with open(CACHE, 'rb') as f:
            cached_start, cached_end, insns = pickle.load(f)
        if cached_start == start and cached_end == end:
            return insns

    t0 = time.time()
    blob = read_bytes(start, end - start)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False
    insns = {}
    addr = start
    off = 0
    n = len(blob)
    while off < n:
        chunk = blob[off:off + 4]
        if len(chunk) < 4:
            break
        decoded = list(md.disasm(chunk, addr))
        if decoded:
            ins = decoded[0]
            insns[addr] = Insn(addr, ins.mnemonic, ins.op_str, ins.size, chunk)
        else:
            word = struct.unpack('<I', chunk)[0]
            insns[addr] = Insn(addr, '.word', f'0x{word:x}', 4, chunk)
        addr += 4
        off += 4
    with open(CACHE, 'wb') as f:
        pickle.dump((start, end, insns), f)
    print(f"disasm_range: {len(insns)} slots in {time.time()-t0:.1f}s", file=sys.stderr)
    return insns


if __name__ == '__main__':
    insns = disasm_range(FUNC_START, FUNC_END, force=True)
    print(f"decoded {len(insns)} 4-byte slots from 0x{FUNC_START:x} to 0x{FUNC_END:x}")
    n_word = sum(1 for i in insns.values() if i.mnemonic == '.word')
    print(f"undecodable (.word / embedded data) slots: {n_word}")
