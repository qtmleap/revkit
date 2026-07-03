#!/usr/bin/env python3
import lief, sys
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import read_bytes

BASE = 0x100000000

def decode_rebase(raw):
    bind = (raw >> 63) & 1
    target36 = raw & 0xFFFFFFFFF
    return bind, target36

def read_u64(va):
    return int.from_bytes(read_bytes(va, 8), 'little')

def cstr(va, maxlen=128):
    data = read_bytes(va, maxlen)
    end = data.find(b'\x00')
    if end == -1:
        end = maxlen
    return data[:end]

# candidate ref addresses found near the swizzle functions
refs = {
    'e04_ref_1 (0x100e99000+0xd98)': 0x100e99000 + 0xd98,
    'e04_ref_2 (0x100f26000+0xd30)': 0x100f26000 + 0xd30,
    '947e8_ref_donor (0x100da9000+0xfa1)': 0x100da9000 + 0xfa1,
    '947e8_ref_1 (0x100ec2000+0xee0)': 0x100ec2000 + 0xee0,
    '947e8_ref_2 (0x100ec3000+0x1c0)': 0x100ec3000 + 0x1c0,
    '947e8_ref_3 (0x100ec3000+0x20)': 0x100ec3000 + 0x20,
    '947e8_ref_4 (0x100ec6000+0x780)': 0x100ec6000 + 0x780,
}

with open('/tmp/swizzle_refs_out.txt', 'w') as f:
    for name, addr in refs.items():
        raw = read_u64(addr)
        bind, target36 = decode_rebase(raw)
        va = BASE + target36
        if bind:
            f.write(f"{name} @ {hex(addr)}: raw={hex(raw)} BIND (import) target36={hex(target36)}\n")
            continue
        s = cstr(va)
        f.write(f"{name} @ {hex(addr)}: raw={hex(raw)} -> VA={hex(va)} str={s!r}\n")
