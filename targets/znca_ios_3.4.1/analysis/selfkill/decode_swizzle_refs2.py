#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import read_bytes, read_u64, BASE, SEGMENTS


def decode_rebase(raw):
    bind = (raw >> 63) & 1
    target36 = raw & 0xFFFFFFFFF
    return bind, target36


def cstr(va, maxlen=200):
    if va is None:
        return None
    data = read_bytes(va, maxlen)
    if data is None:
        return None
    end = data.find(b'\x00')
    if end == -1:
        end = maxlen
    return data[:end]


def which_seg(va):
    for vaddr, vsize, fileoff, filesize, name in SEGMENTS:
        if vaddr <= va < vaddr + vsize:
            return name
    return '???'


out = []

# --- direct literal string addresses (adrp+add used directly as pointer arg, no extra deref) ---
direct_strs = {
    '947e8_x2_donor_msg (0x100da9000+0xfa1)': 0x100da9000 + 0xfa1,
    '947e8_x4_filename  (0x100ec6000+0x780)': 0x100ec6000 + 0x780,
    'e04_x2_filename    (0x100ec3000+0x20)':  0x100ec3000 + 0x20,
}
out.append('=== direct literal C-strings ===')
for name, addr in direct_strs.items():
    s = cstr(addr)
    out.append(f'{name} @ {hex(addr)} seg={which_seg(addr)}: {s!r}')

# --- pointer-table slots (ldr [addr]) requiring chained-fixup decode ---
ptr_slots = {
    'e04_x20_classref? (0x100e99000+0xd98)': 0x100e99000 + 0xd98,
    'e04_x0_selref?    (0x100f26000+0xd30)': 0x100f26000 + 0xd30,
}
out.append('')
out.append('=== chained-fixup pointer slots ===')
for name, addr in ptr_slots.items():
    raw = read_u64(addr)
    if raw is None:
        out.append(f'{name} @ {hex(addr)}: UNREADABLE')
        continue
    bind, t36 = decode_rebase(raw)
    va = BASE + t36
    out.append(f'{name} @ {hex(addr)}: raw={hex(raw)} bind={bind} -> VA={hex(va)} seg={which_seg(va)}')
    if bind:
        continue
    # dump first 64 bytes raw hex + try cstr
    raw_bytes = read_bytes(va, 64)
    s = cstr(va)
    out.append(f'    raw64={raw_bytes.hex() if raw_bytes else None}')
    out.append(f'    cstr={s!r}')
    # try treating content as ANOTHER chained pointer (double indirection, e.g. classref->class_t)
    q0 = read_u64(va)
    if q0 is not None:
        b2, t2 = decode_rebase(q0)
        va2 = BASE + t2
        out.append(f'    first_qword={hex(q0)} as-chainedptr-> bind={b2} VA={hex(va2)} seg={which_seg(va2)}')

with open('/tmp/swizzle_refs2_out.txt', 'w') as f:
    f.write('\n'.join(out) + '\n')
