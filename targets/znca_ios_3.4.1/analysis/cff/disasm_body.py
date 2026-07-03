#!/usr/bin/env python3
"""Linear capstone disassembly of the initGenAudioH body (0x100783fc8..0x1007d594c).

ARM64 has a fixed 4-byte instruction width, so a *linear* sweep stays
byte-aligned even across embedded data words (the per-dispatch-site jump
delta that follows each `br` idiom). We exploit that: decode every 4-byte
slot with capstone (skip-invalid=False semantics via CS_MODE_ARM, but treat
CS_ERR entries as raw 4-byte data by manual struct fallback) and cache the
whole instruction stream once so every other script in this directory can
reuse it quickly (pickle cache).
"""
import pickle
import struct
import sys
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
            # undecodable -> treat as raw data word
            word = struct.unpack('<I', chunk)[0]
            insns[addr] = Insn(addr, '.word', f'0x{word:x}', 4, chunk)
        addr += 4
        off += 4
    with open(CACHE, 'wb') as f:
        pickle.dump((start, end, insns), f)
    return insns


if __name__ == '__main__':
    insns = disasm_range(FUNC_START, FUNC_END, force=True)
    print(f"decoded {len(insns)} 4-byte slots from 0x{FUNC_START:x} to 0x{FUNC_END:x}")
    n_word = sum(1 for i in insns.values() if i.mnemonic == '.word')
    print(f"undecodable (.word / embedded data) slots: {n_word}")
