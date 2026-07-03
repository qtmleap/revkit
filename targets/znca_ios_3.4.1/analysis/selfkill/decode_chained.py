#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '/home/vscode/app/targets/znca_ios_3.4.1/analysis/cff')
from common import read_u64, read_bytes, BASE

def decode_rebase(raw):
    # DYLD_CHAINED_PTR_64 generic rebase: target is low 36 bits (target VMaddr from... )
    # bit63=bind(0), bits[51:62]=next(12), bits[36:43]=high8(unused here), bits[0:35]=target(36 bit)
    bind = (raw >> 63) & 1
    target36 = raw & 0xFFFFFFFFF  # 36 bits
    return bind, target36

with open('/tmp/decode_chained_out.txt', 'w') as f:
    known_classref = 0x100f26e70
    raw = read_u64(known_classref)
    f.write(f"raw classref value = {hex(raw)}\n")
    bind, t36 = decode_rebase(raw)
    f.write(f"bind={bind} target36={hex(t36)} -> VA={hex(BASE + t36)}\n")
    f.write(f"expected VoIPClient class @ 0x100f3e468\n\n")

    selref_addr = 0x100f1ec30
    raw2 = read_u64(selref_addr)
    bind2, t36_2 = decode_rebase(raw2)
    va2 = BASE + t36_2
    f.write(f"selref raw={hex(raw2)} bind={bind2} target36={hex(t36_2)} -> VA={hex(va2)}\n")
    s = read_bytes(va2, 64)
    if s:
        f.write(f"  selector string @ {hex(va2)}: {s.split(chr(0).encode())[0]!r}\n")

    selref_addr2 = 0x100f1ec38
    raw3 = read_u64(selref_addr2)
    bind3, t36_3 = decode_rebase(raw3)
    va3 = BASE + t36_3
    f.write(f"selref2 raw={hex(raw3)} bind={bind3} target36={hex(t36_3)} -> VA={hex(va3)}\n")
    s = read_bytes(va3, 64)
    if s:
        f.write(f"  selector2 string @ {hex(va3)}: {s.split(chr(0).encode())[0]!r}\n")
