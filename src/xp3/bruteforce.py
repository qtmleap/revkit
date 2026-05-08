"""
Brute-force ChaCha decryption of PackinOne Hxv4 blobs.

Optimization: only run ONE keystream block (64 bytes) per trial, score
the first 64 plaintext bytes; if promising, run full decrypt.
"""

import collections
import math
import struct
import sys
from pathlib import Path

from .chacha_djb import (
    CHACHA_TYPE_PARAMS,
    chacha_block,
    keystream,
    make_state_packinone,
    make_state_standard,
)


def score_plaintext(pt: bytes) -> tuple[float, list[str]]:
    score = 0.0
    hints = []
    for tag in (b'File', b'info', b'segm', b'adlr', b'time', b'Yuzu', b'feng'):
        idx = pt.find(tag)
        if 0 <= idx < min(64, len(pt)):
            score += 30
            hints.append(f'{tag.decode()}@{idx}')
    if pt[:4] == b'\x04\x22\x4d\x18':
        score += 100
        hints.append('LZ4-frame')
    if pt[:4] == b'\x18\x4d\x22\x04':
        score += 100
        hints.append('LZ4-frame-BE')
    if pt[:4] == b'\x89PNG':
        score += 80
        hints.append('PNG')
    if pt[:4] == b'\x78\xda' or pt[:4] == b'\x78\x9c':
        score += 40
        hints.append('zlib-magic')
    if pt[:4] == b'XP3\r':
        score += 80
        hints.append('XP3')
    seg = pt[:64]
    if seg:
        cnt = collections.Counter(seg)
        H = -sum((c / len(seg)) * math.log2(c / len(seg)) for c in cnt.values() if c)
        if H < 6.5:
            score += (6.5 - H) * 5
        if H < 4.5:
            score += 10
        hints.append(f'H={H:.2f}')
    return score, hints


def first_block_xor(blob: bytes, ctype: int, key: bytes, nonce: bytes, layout: str) -> bytes:
    """XOR first 64 bytes of blob with first ChaCha block."""
    p = CHACHA_TYPE_PARAMS[ctype]
    state_fn = make_state_standard if layout == 'std' else make_state_packinone
    s = state_fn(key, nonce, 0)
    block = chacha_block(s, p['rounds'])
    return bytes(a ^ b for a, b in zip(blob[:64], block))


def trial_set(ctype, kb, nb):
    if kb == 1:
        keys = [bytes([b]) for b in range(256)]
    else:
        keys = [
            b'\x00' * kb,
            b'\xff' * kb,
            bytes(range(kb)),
        ]
        # add ASCII single-byte repeats up to kb
        for c in range(0x20, 0x7f):
            keys.append(bytes([c]) * kb)
    nonces = [
        b'\x00' * nb,
        b'\xff' * nb,
    ]
    # XP3 magic-derived nonce
    xp3_magic = b'XP3\r\n \n\x1a\x8b\x67\x01'
    nonces.append((xp3_magic + b'\x00' * nb)[:nb])
    return keys, nonces


def run_trials(blob_path: str, top_n=15, threshold=20):
    blob = Path(blob_path).read_bytes()
    print(f'\n=== {blob_path} ({len(blob)} bytes) ===')
    print(f'  ciphertext head: {blob[:16].hex()}')

    candidates = []
    n_trials = 0
    for ctype, p in CHACHA_TYPE_PARAMS.items():
        keys, nonces = trial_set(ctype, p['key_bytes'], p['nonce_bytes'])
        for layout in ('std', 'pko'):
            for key in keys:
                for nonce in nonces:
                    n_trials += 1
                    pt = first_block_xor(blob, ctype, key, nonce, layout)
                    sc, hints = score_plaintext(pt)
                    if sc >= threshold:
                        candidates.append((sc, ctype, layout, key, nonce, pt, hints))
    print(f'  trials: {n_trials}')
    candidates.sort(reverse=True, key=lambda x: x[0])
    for sc, ctype, layout, key, nonce, pt, hints in candidates[:top_n]:
        print(f'  score={sc:7.2f} type={ctype} layout={layout} key={key.hex()} nonce={nonce.hex()} head={pt[:32].hex()} hints={hints}')
    if not candidates:
        print('  (no candidates above threshold)')


if __name__ == '__main__':
    paths = sys.argv[1:] or [
        'targets/Kanade/_extracted/steam.xp3.Hxv4.blob',
        'targets/Kanade/_extracted/patch.xp3.Hxv4.blob',
        'targets/Kanade/_extracted/data.xp3.Hxv4.blob',
    ]
    for p in paths:
        run_trials(p)
