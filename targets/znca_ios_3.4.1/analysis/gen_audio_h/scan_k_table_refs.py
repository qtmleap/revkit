#!/usr/bin/env python3
"""Check whether _gen_audio_h itself (not a callee) directly references any
of the 3 known SHA-256 K[64] constant-table copies via ADRP+ADD, and also
scan more broadly for any as-yet-unknown 4th copy referenced from within
_gen_audio_h (by checking every ADRP+ADD target for the 256-byte K[64] byte
pattern at that address)."""
import sys
sys.path.insert(0, '.')
from disasm_body import disasm_range
from common import FUNC_START, FUNC_END, read_bytes
import capstone

K64 = [
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]
import struct
PAT64 = b''.join(struct.pack('<I', x) for x in K64)

insns = disasm_range(FUNC_START, FUNC_END)
addrs = sorted(insns)

pending = {}
data_refs = {}
for a in addrs:
    ins = insns[a]
    if ins.mnemonic == 'adrp':
        parts = ins.op_str.split(',')
        if len(parts) == 2:
            reg = parts[0].strip()
            try:
                imm = int(parts[1].strip().lstrip('#'), 0)
            except ValueError:
                continue
            pending[reg] = imm
        continue
    if ins.mnemonic == 'add' and ',' in ins.op_str:
        parts = [p.strip() for p in ins.op_str.split(',')]
        if len(parts) == 3 and parts[1] in pending and parts[2].startswith('#'):
            try:
                imm = int(parts[2].lstrip('#'), 0)
            except ValueError:
                continue
            tgt = pending[parts[1]] + imm
            data_refs[tgt] = data_refs.get(tgt, 0) + 1
            pending[parts[0]] = tgt

known = [0x100cae7e0, 0x100cbbcc8, 0x100f77da0]
print("direct refs within _gen_audio_h to known K[64] copies:")
for k in known:
    print(f"  0x{k:x}: {data_refs.get(k, 0)} refs")

print(f"\ntotal distinct ADRP+ADD data targets in _gen_audio_h: {len(data_refs)}")

# check ALL distinct targets for the K64 pattern (may reveal a private 4th copy)
hits = []
for t in data_refs:
    b = read_bytes(t, 256)
    if b == PAT64:
        hits.append(t)
print(f"\ntargets that match full K[64] byte pattern: {hits}")

# also check for PARTIAL match (first 8 words) in case of a truncated/reordered copy
PAT8 = PAT64[:32]
partial = []
for t in data_refs:
    b = read_bytes(t, 32)
    if b == PAT8:
        partial.append(t)
print(f"targets matching first-8-words K pattern: {partial}")
