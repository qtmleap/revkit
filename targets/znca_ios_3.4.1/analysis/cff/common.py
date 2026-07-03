#!/usr/bin/env python3
"""Common helpers for CFF de-flatten analysis of znca iOS 3.4.1 Crew binary."""
import struct
from pathlib import Path

BINARY = Path('/home/vscode/app/targets/znca_ios_3.4.1/Crew')
BASE = 0x100000000

SEGMENTS = [
    # (vaddr, vsize, fileoff, filesize, name)
    (0x100000000, 0xe54000, 0x0, 0xe54000, '__TEXT'),
    (0x100e54000, 0x88000, 0xe54000, 0x88000, '__DATA_CONST'),
    (0x100edc000, 0x50c000, 0xedc000, 0x2bc000, '__DATA'),
    (0x1013e8000, 0x70000, 0x1198000, 0x70000, '__ETC'),
    (0x101458000, 0x138000, 0x1208000, 0x136410, '__LINKEDIT'),
]

_data = None

def data():
    global _data
    if _data is None:
        _data = BINARY.read_bytes()
    return _data


def va_to_off(va):
    for vaddr, vsize, fileoff, filesize, name in SEGMENTS:
        if vaddr <= va < vaddr + vsize:
            delta = va - vaddr
            if delta < filesize:
                return fileoff + delta
            return None  # in bss / zerofill, no file backing
    return None


def read_bytes(va, size):
    off = va_to_off(va)
    if off is None:
        return None
    return data()[off:off + size]


def read_u32(va):
    b = read_bytes(va, 4)
    if b is None or len(b) < 4:
        return None
    return struct.unpack('<I', b)[0]


def read_i32(va):
    b = read_bytes(va, 4)
    if b is None or len(b) < 4:
        return None
    return struct.unpack('<i', b)[0]


def read_u64(va):
    b = read_bytes(va, 8)
    if b is None or len(b) < 8:
        return None
    return struct.unpack('<Q', b)[0]

# initGenAudioH body bounds
FUNC_START = 0x100783fc8
FUNC_END = 0x1007d594c  # exclusive-ish (next LC_FUNCTION_STARTS entry)

WRAPPER_START = 0x100a29528
WRAPPER_END = 0x100a29528 + 0x7c

CFF_STATE_VAR_MAIN = 0x101034204
