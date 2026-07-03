#!/usr/bin/env python3
"""Common helpers: va<->file offset mapping via lief, capstone disassembler."""
import lief
import capstone
from pathlib import Path

BIN_PATH = "/home/vscode/app/targets/znca_ios_3.4.1/Crew"

_binary = None
_segments = None

def get_binary():
    global _binary
    if _binary is None:
        _binary = lief.parse(BIN_PATH)
    return _binary

def get_segments():
    global _segments
    if _segments is None:
        b = get_binary()
        segs = []
        for seg in b.segments:
            segs.append((seg.virtual_address, seg.virtual_size, seg.file_offset, seg.name))
        _segments = segs
    return _segments

def va_to_off(va):
    for vaddr, vsize, foff, name in get_segments():
        if vaddr <= va < vaddr + vsize:
            return foff + (va - vaddr)
    return None

def get_section_for_va(va):
    b = get_binary()
    for seg in b.segments:
        if seg.virtual_address <= va < seg.virtual_address + seg.virtual_size:
            for sec in seg.sections:
                if sec.virtual_address <= va < sec.virtual_address + sec.size:
                    return f"{seg.name}.{sec.name}"
            return f"{seg.name}.<none>"
    return None

_raw = None

def get_raw():
    global _raw
    if _raw is None:
        _raw = Path(BIN_PATH).read_bytes()
    return _raw

def read_bytes(va, size):
    off = va_to_off(va)
    if off is None:
        return None
    return get_raw()[off:off+size]

def cstr_at(va, maxlen=256):
    off = va_to_off(va)
    if off is None:
        return None
    raw = get_raw()
    end = raw.find(b'\x00', off, off+maxlen)
    if end == -1:
        end = off + maxlen
    return raw[off:end]

def make_cs():
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    return md

def disasm_range(start_va, end_va):
    """Return list of capstone insns for [start_va, end_va)."""
    data = read_bytes(start_va, end_va - start_va)
    md = make_cs()
    return list(md.disasm(data, start_va))

def shannon_entropy(data):
    import math
    if not data:
        return 0.0
    from collections import Counter
    c = Counter(data)
    n = len(data)
    ent = 0.0
    for v in c.values():
        p = v / n
        ent -= p * math.log2(p)
    return ent

def printable_ratio(data):
    if not data:
        return 0.0
    cnt = sum(1 for b in data if 0x20 <= b < 0x7f)
    return cnt / len(data)

if __name__ == "__main__":
    print("segments:")
    for s in get_segments():
        print(f"  va=0x{s[0]:x} size=0x{s[1]:x} foff=0x{s[2]:x} name={s[3]}")
