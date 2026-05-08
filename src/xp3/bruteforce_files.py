"""
Brute-force ChaCha keys derived from candidate file headers.

For each candidate file, slide a window through its first 256 bytes and
try ChaCha decryption at all 6 cipher types and 2 layouts.
"""

import collections
import math
import sys
from pathlib import Path

from .chacha_djb import (
    CHACHA_TYPE_PARAMS,
    chacha_block,
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
        hints.append(f'H={H:.2f}')
    return score, hints


def first_block_xor(blob, ctype, key, nonce, layout):
    p = CHACHA_TYPE_PARAMS[ctype]
    state_fn = make_state_standard if layout == 'std' else make_state_packinone
    s = state_fn(key, nonce, 0)
    block = chacha_block(s, p['rounds'])
    return bytes(a ^ b for a, b in zip(blob[:64], block))


def run(blob_path, key_source_path, src_window=128):
    blob = Path(blob_path).read_bytes()
    src = Path(key_source_path).read_bytes()[:src_window]
    print(f'\n=== blob={blob_path} key_src={key_source_path} ({len(src)} bytes) ===')
    print(f'  blob head:  {blob[:16].hex()}')
    print(f'  src head:   {src[:32].hex()}')

    candidates = []
    n_trials = 0
    for ctype, p in CHACHA_TYPE_PARAMS.items():
        kb, nb = p['key_bytes'], p['nonce_bytes']
        for ko in range(0, len(src) - kb + 1, 1):
            key = bytes(src[ko:ko + kb])
            for no in range(0, len(src) - nb + 1, 1):
                nonce = bytes(src[no:no + nb])
                for layout in ('std', 'pko'):
                    n_trials += 1
                    pt = first_block_xor(blob, ctype, key, nonce, layout)
                    sc, hints = score_plaintext(pt)
                    if sc >= 30:
                        candidates.append((sc, ctype, layout, ko, no, key, nonce, pt, hints))
    print(f'  trials: {n_trials}')
    candidates.sort(reverse=True, key=lambda x: x[0])
    for sc, ctype, layout, ko, no, key, nonce, pt, hints in candidates[:10]:
        print(f'  score={sc:7.2f} type={ctype} layout={layout} key@+{ko} nonce@+{no} head={pt[:32].hex()} hints={hints}')
    if not candidates:
        print('  (no candidates)')
    return candidates


if __name__ == '__main__':
    blobs = [
        'targets/Kanade/_extracted/steam.xp3.Hxv4.blob',
    ]
    sources = [
        'targets/Kanade/plugin/PackinOne.hop',
        'targets/Kanade/KANADE.exe',
        'targets/Kanade/KANADE.cf',
        'targets/Kanade/steam.xp3',
        'targets/Kanade/data.xp3',
        'targets/Kanade/patch.xp3',
        'targets/Kanade/plugin/PackinOne.dll',
    ]
    if len(sys.argv) >= 3:
        blobs = [sys.argv[1]]
        sources = [sys.argv[2]]
    for blob in blobs:
        for src in sources:
            run(blob, src, src_window=128)
