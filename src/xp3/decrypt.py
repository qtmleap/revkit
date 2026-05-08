"""
Decrypt PackinOne Hxv4 blob: ChaCha (8/12/20 round) + optional zlib.

Usage:
    from src.xp3.decrypt import attempt_decrypt
    result = attempt_decrypt(blob, ctype=1, key=..., nonce=..., layout='std',
                             post_inflate=True)
"""

import collections
import math
import struct
import zlib
from dataclasses import dataclass

from .chacha_djb import (
    CHACHA_TYPE_PARAMS,
    chacha_block,
    keystream,
    make_state_packinone,
    make_state_standard,
)


@dataclass
class DecryptResult:
    plaintext: bytes
    score: float
    hints: list[str]
    inflated: bytes | None = None


def score_xp3_index(pt: bytes) -> tuple[float, list[str]]:
    """Score a candidate plaintext as 'looks like XP3 index data'."""
    score = 0.0
    hints = []
    for tag in (b"File", b"info", b"segm", b"adlr", b"time", b"Yuzu", b"feng"):
        idx = pt.find(tag)
        if 0 <= idx < min(64, len(pt)):
            score += 30
            hints.append(f"{tag.decode()}@{idx}")
    if pt[:4] == b"\x04\x22\x4d\x18":
        score += 100
        hints.append("LZ4-frame")
    if pt[:4] == b"\x18\x4d\x22\x04":
        score += 100
        hints.append("LZ4-frame-BE")
    if pt[:2] in (b"\x78\xda", b"\x78\x9c", b"\x78\x01", b"\x78\x5e"):
        score += 60
        hints.append("zlib-magic")
    if pt[:4] == b"\x89PNG":
        score += 80
        hints.append("PNG")
    seg = pt[: min(128, len(pt))]
    if seg:
        cnt = collections.Counter(seg)
        H = -sum((c / len(seg)) * math.log2(c / len(seg)) for c in cnt.values() if c)
        if H < 6.0:
            score += (6.0 - H) * 8
        hints.append(f"H={H:.2f}")
    return score, hints


def decrypt_chacha(
    blob: bytes,
    ctype: int,
    key: bytes,
    nonce: bytes,
    layout: str = "std",
    counter_init: int = 0,
) -> bytes:
    p = CHACHA_TYPE_PARAMS[ctype]
    state_fn = make_state_standard if layout == "std" else make_state_packinone
    out = bytearray()
    counter = counter_init
    while len(out) < len(blob):
        s = state_fn(key, nonce, counter)
        block = chacha_block(s, p["rounds"])
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(blob, out[: len(blob)]))


def attempt_decrypt(
    blob: bytes,
    ctype: int,
    key: bytes,
    nonce: bytes,
    layout: str = "std",
    counter_init: int = 0,
    post_inflate: bool = True,
) -> DecryptResult:
    pt = decrypt_chacha(blob, ctype, key, nonce, layout, counter_init)
    score, hints = score_xp3_index(pt)
    inflated = None
    if post_inflate:
        try:
            inflated = zlib.decompress(pt)
            score2, hints2 = score_xp3_index(inflated)
            if score2 > score:
                score = score2
                hints += ["[inflated]"] + hints2
        except Exception:
            pass
    return DecryptResult(plaintext=pt, score=score, hints=hints, inflated=inflated)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 5:
        print("usage: decrypt.py <blob> <ctype> <key_hex> <nonce_hex> [layout] [counter]")
        sys.exit(1)
    blob = open(sys.argv[1], "rb").read()
    ctype = int(sys.argv[2])
    key = bytes.fromhex(sys.argv[3])
    nonce = bytes.fromhex(sys.argv[4])
    layout = sys.argv[5] if len(sys.argv) > 5 else "std"
    counter = int(sys.argv[6]) if len(sys.argv) > 6 else 0
    r = attempt_decrypt(blob, ctype, key, nonce, layout, counter)
    print(f"score={r.score:.2f}  hints={r.hints}")
    print(f"plain head (64B): {r.plaintext[:64].hex(' ')}")
    if r.inflated:
        print(f"inflated head: {r.inflated[:64].hex(' ')}")
