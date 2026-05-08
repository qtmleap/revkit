"""
PackinOne-style ChaCha (DJBernsteinStreamCipher) implementation.

Per static analysis (docs/instructions/packinone_static_analysis.md):
- Sigma "expand 32-byte k" stored bit-flipped at .rdata 0x10075c54
- All state words held bit-flipped in memory; pandn used to recover at runtime
- Six cipher types parameterized by (nonce_bytes, key_bytes, rounds):
    type 1: nonce=8,  key=16, rounds=8   (ChaCha8)
    type 2: nonce=12, key=8,  rounds=12  (ChaCha12)
    type 3: nonce=20, key=4,  rounds=20  (ChaCha20)
    type 4: nonce=8,  key=1,  rounds=8
    type 5: nonce=12, key=1,  rounds=12
    type 6: nonce=20, key=1,  rounds=20

Layout (from analyst):
- state[0..3]   nonce piece (16 bytes total addressable; only nonce_bytes valid)
- state[4..11]  key piece (32 bytes addressable; only key_bytes valid)
- state[12..15] additional words
- sigma applied separately

The standard ChaCha state is sigma|key|counter|nonce. The PackinOne layout
appears reversed/permuted; we encode both layouts and let the caller pick.
"""

import struct

CHACHA_TYPE_PARAMS = {
    1: dict(nonce_bytes=8,  key_bytes=16, rounds=8),
    2: dict(nonce_bytes=12, key_bytes=8,  rounds=12),
    3: dict(nonce_bytes=20, key_bytes=4,  rounds=20),
    4: dict(nonce_bytes=8,  key_bytes=1,  rounds=8),
    5: dict(nonce_bytes=12, key_bytes=1,  rounds=12),
    6: dict(nonce_bytes=20, key_bytes=1,  rounds=20),
}

SIGMA = b"expand 32-byte k"  # 16 bytes
SIGMA_WORDS = struct.unpack('<4I', SIGMA)  # ('expa', 'nd 3', '2-by', 'te k') as LE u32


def _rotl32(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _qr(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def chacha_block(state, rounds):
    s = list(state)
    for _ in range(rounds // 2):
        _qr(s, 0, 4, 8, 12)
        _qr(s, 1, 5, 9, 13)
        _qr(s, 2, 6, 10, 14)
        _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15)
        _qr(s, 1, 6, 11, 12)
        _qr(s, 2, 7, 8, 13)
        _qr(s, 3, 4, 9, 14)
    out = [(x + y) & 0xFFFFFFFF for x, y in zip(s, state)]
    return struct.pack('<16I', *out)


def make_state_standard(key, nonce, counter=0):
    """Standard ChaCha20 layout: sigma|key|counter|nonce."""
    key32 = (key + b'\x00' * 32)[:32]
    state = list(SIGMA_WORDS)
    state += list(struct.unpack('<8I', key32))
    if len(nonce) == 8:
        state += [counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF]
        state += list(struct.unpack('<2I', nonce))
    elif len(nonce) == 12:
        state += [counter & 0xFFFFFFFF]
        state += list(struct.unpack('<3I', nonce))
    elif len(nonce) == 16:
        state += list(struct.unpack('<4I', nonce))
    elif len(nonce) == 20:
        # 20 = 4 dwords used as nonce + 1 dword overlapping counter
        # Per analysis: state[12..15] are 'additional words' that may include nonce
        nonce_padded = (nonce + b'\x00' * 20)[:20]
        state += list(struct.unpack('<5I', nonce_padded))[:4]
    else:
        raise ValueError(f'unsupported nonce length {len(nonce)}')
    return state


def make_state_packinone(key, nonce, counter=0):
    """
    PackinOne layout per analyst:
      state[0..3]   = nonce piece (interpreted big-endian per dword?)
      state[4..11]  = key piece
      state[12..15] = additional / counter
      sigma applied as XOR mask elsewhere

    We try a permutation: nonce occupies the LOW 4 dwords, key the next 8,
    extras the last 4. Sigma is added on top by replacing low or top.
    """
    nonce_padded = (nonce + b'\x00' * 16)[:16]
    key_padded = (key + b'\x00' * 32)[:32]
    state = []
    # state[0..3]: nonce as 4 BE u32 (analyst said BE; reversed bytes)
    for i in range(4):
        chunk = nonce_padded[i * 4:i * 4 + 4]
        state.append(struct.unpack('>I', chunk)[0])
    # state[4..11]: key as 8 BE u32
    for i in range(8):
        chunk = key_padded[i * 4:i * 4 + 4]
        state.append(struct.unpack('>I', chunk)[0])
    # state[12..15]: counter, ext
    state += [counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF, 0, 0]
    return state


def keystream(state_fn, key, nonce, rounds, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        s = state_fn(key, nonce, counter)
        block = chacha_block(s, rounds)
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(state_fn, key, nonce, rounds, data):
    ks = keystream(state_fn, key, nonce, rounds, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


decrypt = encrypt


if __name__ == '__main__':
    # quick self-test against a standard ChaCha20 vector (RFC 7539)
    key = bytes(range(32))
    nonce = bytes(range(8))  # 64-bit nonce variant
    pt = b'\x00' * 64
    ks = keystream(make_state_standard, key, nonce, 20, 64)
    print('standard ChaCha20 keystream (key=0..31, nonce=0..7):')
    print(ks.hex())
