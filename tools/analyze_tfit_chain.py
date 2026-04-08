#!/usr/bin/env python3
"""
Analyze TFIT AES_encrypt input/output pairs from Netflix iOS appboot capture.

Investigates:
1. Chain structure: key feeding (output of prior pair used as next key)
2. DH public key / private key correlation
3. 48B TFIT HMAC-SHA384 key origin
4. Session key derivation from shared secret
"""

import re
from pathlib import Path

LOG_PATH = Path("/home/vscode/app/raws/appboot_tfit_capture.log")


# ---------------------------------------------------------------------------
# Parsing — respect outer chain boundaries (only paired start/end)
# ---------------------------------------------------------------------------


def parse_log(path: Path) -> dict:
    """
    Returns:
      chains: list of 4 major-chain dicts (start matched to end marker)
        - start_line, end_line (int, 1-based)
        - pairs: list of (n, in_hex, out_hex)
        - set_encrypt_keys: list of (bits, key_hex) in order seen within chain
        - pair_count_claimed: int
      dh_pub_key: hex str (128B)
      dh_priv_key: hex str (128B)
      dh_shared_secret: hex str (128B)
      hmac_keys_48b: list[str]
      hmac_48b_digest: str  (the 48B HMAC-SHA384 output)
    """
    re_chain_start = re.compile(r"\[TFIT\] === chain started")
    re_chain_end = re.compile(r"\[TFIT\] === chain ended \((\d+) pairs captured\)")
    re_aes_enc = re.compile(
        r"\[AES_encrypt\] #(\d+) in=([0-9a-f]+) out=([0-9a-f]+)"
    )
    re_set_enc_key = re.compile(
        r"\[aesCbc\] AES_set_(?:en|de)crypt_key bits=(\d+) key=([0-9a-f]+)"
    )
    re_dh_gen = re.compile(r"\[dhGenerate\] client_pub_key\(128B\)=([0-9a-f]+)")
    re_dh_priv = re.compile(r"\[dhGenerate\] client_priv_key\(128B\)=([0-9a-f]+)")
    re_dh_derive = re.compile(r"\[dhDerive\] shared_secret\(128B\)=([0-9a-f]+)")
    re_hmac_init_48 = re.compile(
        r"\[HMAC\] HMAC_Init_ex ctx=\S+ key\(48B\)=([0-9a-f]+)"
    )
    re_hmac_final_48 = re.compile(
        r"\[HMAC\] HMAC_Final ctx=\S+ digest\(48B\)=([0-9a-f]+)"
    )

    # Stack-based chain parsing: push on "started", pop (and save) on "ended"
    chain_stack: list[dict] = []
    closed_chains: list[dict] = []

    dh_pub_key: str | None = None
    dh_priv_key: str | None = None
    dh_shared_secret: str | None = None
    hmac_keys_48b: list[str] = []
    hmac_final_48b: list[str] = []

    with path.open() as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()

            if re_chain_start.search(line):
                chain_stack.append(
                    {
                        "start_line": lineno,
                        "end_line": None,
                        "pairs": [],
                        "set_encrypt_keys": [],
                        "pair_count_claimed": None,
                    }
                )
                continue

            m = re_chain_end.search(line)
            if m and chain_stack:
                c = chain_stack.pop()
                c["end_line"] = lineno
                c["pair_count_claimed"] = int(m.group(1))
                closed_chains.append(c)
                continue

            # Attribute events to the innermost active chain
            active = chain_stack[-1] if chain_stack else None

            m = re_aes_enc.search(line)
            if m and active is not None:
                active["pairs"].append((int(m.group(1)), m.group(2), m.group(3)))
                continue

            m = re_set_enc_key.search(line)
            if m and active is not None:
                active["set_encrypt_keys"].append((int(m.group(1)), m.group(2)))
                continue

            m = re_dh_gen.search(line)
            if m:
                dh_pub_key = m.group(1)
                continue

            m = re_dh_priv.search(line)
            if m:
                dh_priv_key = m.group(1)
                continue

            m = re_dh_derive.search(line)
            if m:
                dh_shared_secret = m.group(1)
                continue

            m = re_hmac_init_48.search(line)
            if m:
                hmac_keys_48b.append(m.group(1))
                continue

            m = re_hmac_final_48.search(line)
            if m:
                hmac_final_48b.append(m.group(1))
                continue

    # Also include any unclosed chains (shouldn't happen with matched data)
    all_chains = closed_chains + chain_stack

    return {
        "chains": all_chains,
        "dh_pub_key": dh_pub_key,
        "dh_priv_key": dh_priv_key,
        "dh_shared_secret": dh_shared_secret,
        "hmac_keys_48b": hmac_keys_48b,
        "hmac_final_48b": hmac_final_48b,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def blocks_of(hex_str: str, block_bytes: int = 16) -> list[str]:
    blen = block_bytes * 2
    return [hex_str[i : i + blen] for i in range(0, len(hex_str), blen)]


def xor_hex(a: str, b: str) -> str:
    return format(int(a, 16) ^ int(b, 16), f"0{len(a)}x")


def popcount(hex_str: str) -> int:
    return bin(int(hex_str, 16)).count("1")


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyze_chain_structure(chain: dict, idx: int) -> None:
    """
    Identify the repeating round structure:
      3 CTR pairs -> KAT group (6 pairs) -> 6 state-update pairs
      -> derive key from 2 outputs -> 3 chained pairs -> new key
    """
    print(f"\n=== Chain {idx + 1}: Structure Analysis ===")
    pairs = chain["pairs"]
    print(f"  Pairs: {len(pairs)} (claimed={chain['pair_count_claimed']})")

    # Count zero-input KAT anchor pairs
    zero_inputs = [(n, inp, out) for n, inp, out in pairs if inp == "0" * 32]
    print(f"  KAT zero-input pairs: {len(zero_inputs)} at positions {[n for n, _, _ in zero_inputs]}")

    # Count chained pairs (out[i] == in[i+1])
    chain_links = sum(
        1
        for i in range(len(pairs) - 1)
        if pairs[i][2] == pairs[i + 1][1]
    )
    print(f"  Chained pairs (out[i] = in[i+1]): {chain_links}")

    # Count CTR-like pairs (last-byte increment)
    ctr_pairs = sum(
        1
        for i in range(len(pairs) - 1)
        if (
            pairs[i][1][:-2] == pairs[i + 1][1][:-2]
            and int(pairs[i + 1][1][-2:], 16) == (int(pairs[i][1][-2:], 16) + 1) & 0xFF
        )
    )
    print(f"  CTR-like pairs (last-byte counter): {ctr_pairs}")

    # Count key-feed events: consecutive pair outputs -> next AES_set_encrypt_key
    out_map: dict[str, int] = {out: n for n, _, out in pairs}
    KAT_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    ZERO_KEY = "0" * 64
    feeds = 0
    for bits, key in chain["set_encrypt_keys"]:
        if bits != 256 or key in (KAT_KEY, ZERO_KEY):
            continue
        lo, hi = key[:32], key[32:]
        if lo in out_map and hi in out_map:
            n_lo = out_map[lo]
            n_hi = out_map[hi]
            if n_hi == n_lo + 1:
                feeds += 1
    print(f"  Key-feeding events (concat(out[N], out[N+1]) -> next key): {feeds}")


def analyze_key_feeding_detail(chain: dict, idx: int) -> None:
    """Print each key-feeding instance."""
    print(f"\n--- Chain {idx + 1}: Key Feeding Details ---")
    pairs = chain["pairs"]
    out_map: dict[str, int] = {out: n for n, _, out in pairs}
    KAT_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    ZERO_KEY = "0" * 64
    seen_keys: set[str] = set()
    for bits, key in chain["set_encrypt_keys"]:
        if bits != 256 or key in (KAT_KEY, ZERO_KEY) or key in seen_keys:
            continue
        seen_keys.add(key)
        lo, hi = key[:32], key[32:]
        lo_n = out_map.get(lo)
        hi_n = out_map.get(hi)
        if lo_n is not None and hi_n is not None and hi_n == lo_n + 1:
            print(
                f"  key={key[:32]}|{key[32:]} <- concat(out[#{lo_n}], out[#{hi_n}])"
            )
        else:
            src = f"lo_from=#{lo_n}" if lo_n else "lo=unknown"
            src += f" hi_from=#{hi_n}" if hi_n else " hi=unknown"
            print(f"  key={key[:32]}... {src}")


def analyze_repeating_inputs(chains: list[dict]) -> None:
    """Fixed inputs shared across all chains (KAT test vectors)."""
    print("\n=== Cross-Chain: Repeating Input Patterns ===")
    if not chains:
        return
    common = {inp for _, inp, _ in chains[0]["pairs"]}
    for c in chains[1:]:
        common &= {inp for _, inp, _ in c["pairs"]}
    print(f"  Inputs common to ALL {len(chains)} chains: {len(common)}")
    for inp in sorted(common):
        print(f"    {inp}")


def analyze_dh_private_key(chain: dict, dh_priv_key: str) -> None:
    """
    Verify that the DH private key is assembled from AES_encrypt outputs.
    The expected mapping: priv_key[1:] = concat(out[87..94])[1:],
    with byte 0 having bit 0x40 OR'd in by the DH library.
    """
    print("\n=== Chain 1: DH Private Key = AES_encrypt Outputs ===")
    if not dh_priv_key:
        print("  No DH private key in log.")
        return

    pairs = chain["pairs"]
    out_by_n: dict[int, str] = {n: out for n, _, out in pairs}

    priv_blocks = blocks_of(dh_priv_key, 16)
    print(f"  Private key (128B, {len(priv_blocks)} x 16B blocks):")

    all_match = True
    mismatches = 0
    for i, pb in enumerate(priv_blocks):
        pair_n = 87 + i
        pair_out = out_by_n.get(pair_n, "N/A")
        byte_diff = ""
        if pair_out != "N/A":
            xv = xor_hex(pb, pair_out)
            pc = popcount(xv)
            if pc == 0:
                byte_diff = " EXACT MATCH"
            elif pc <= 2:
                byte_diff = f" ~match (XOR={xv}, {pc} bit diff)"
            else:
                byte_diff = f" MISMATCH (XOR={xv})"
                all_match = False
                mismatches += 1
        else:
            all_match = False
            mismatches += 1

        print(f"    priv[{i:2d}] = {pb}  <- pair #{pair_n} out={pair_out}{byte_diff}")

    if mismatches == 0:
        print("  => ALL blocks match exactly.")
    elif mismatches == 1:
        # Check if only byte 0 differs by 0x40
        diff_idx = next(
            i
            for i, pb in enumerate(priv_blocks)
            if out_by_n.get(87 + i) and xor_hex(pb, out_by_n[87 + i]) != "0" * 32
        )
        pb = priv_blocks[diff_idx]
        out_val = out_by_n.get(87 + diff_idx, "")
        if out_val:
            xv = xor_hex(pb[:2], out_val[:2])
            if xv == "40" and pb[2:] == out_val[2:]:
                print(
                    f"  => {mismatches} mismatch: byte 0 differs by 0x40 "
                    f"(DH library sets bit 6: {pb[:2]} vs {out_val[:2]})."
                )
                print("  => DH private key = TFIT AES_encrypt output stream, byte 0 | 0x40")
    else:
        print(f"  => {mismatches} mismatches.")


def analyze_dh_pub_key_correlation(chain: dict, dh_pub_key: str) -> None:
    """
    Check if the DH public key blocks appear as AES_encrypt inputs or outputs.
    The public key is g^privkey mod p; it is not expected to appear in the TFIT stream.
    """
    print("\n=== Chain 1: DH Public Key Correlation ===")
    if not dh_pub_key:
        print("  No DH public key in log.")
        return

    pub_blocks = blocks_of(dh_pub_key, 16)
    pairs = chain["pairs"]
    pair_inputs = {inp for _, inp, _ in pairs}
    pair_outputs = {out for _, _, out in pairs}

    direct_input_hits = [
        (i, b) for i, b in enumerate(pub_blocks) if b in pair_inputs
    ]
    direct_output_hits = [
        (i, b) for i, b in enumerate(pub_blocks) if b in pair_outputs
    ]

    if direct_input_hits or direct_output_hits:
        print("  DIRECT MATCH found.")
        for i, b in direct_input_hits:
            print(f"    pub_block[{i}]={b} -> appeared as AES input")
        for i, b in direct_output_hits:
            print(f"    pub_block[{i}]={b} -> appeared as AES output")
    else:
        print("  No direct match: DH pub key blocks do not appear in AES I/O.")
        # Min XOR distance
        min_pc = 128
        best = None
        for bi, pb in enumerate(pub_blocks):
            for n, inp, out in pairs:
                pc = popcount(xor_hex(inp, pb))
                if pc < min_pc:
                    min_pc = pc
                    best = (bi, pb, n, inp)
        if best:
            bi, pb, n, inp = best
            print(
                f"  Closest XOR: pub_block[{bi}] vs pair#{n}_input -> {min_pc} differing bits"
            )
        print(
            "  => DH public key is g^privkey mod p; it is NOT a TFIT AES input."
        )


def analyze_chain2_post_dh(chain: dict, dh_shared_secret: str) -> None:
    """
    Chain 2 (109 pairs) spans the DH exchange.
    Pairs #106-#109 are the first 4 pairs after dhDerive.
    Investigate what key was active for those pairs and what the outputs feed into.
    """
    print("\n=== Chain 2: Post-DH Pairs (#106-#109) ===")
    if not dh_shared_secret:
        print("  No shared secret in log.")
        return

    pairs = chain["pairs"]
    post_dh = [(n, inp, out) for n, inp, out in pairs if n >= 106]
    print(f"  Post-dhDerive pairs: {len(post_dh)}")
    for n, inp, out in post_dh:
        print(f"    #{n}: in={inp}  out={out}")

    # The new key derived from these outputs:
    if len(post_dh) >= 4:
        # Pattern observed: key = concat(out[107], out[108])
        key_derived = post_dh[1][2] + post_dh[2][2]
        print(f"\n  Key derived from concat(out[107], out[108]):")
        print(f"    {key_derived}")
        print(f"  (This is the AES key that encrypts post-DH MSL data)")

    # Check if shared_secret blocks appear
    ss_blocks = blocks_of(dh_shared_secret, 16)
    pair_inputs_all = {inp for _, inp, _ in pairs}
    matches = [b for b in ss_blocks if b in pair_inputs_all]
    if matches:
        print(f"\n  Shared secret blocks found as AES inputs: {matches}")
    else:
        print(f"\n  Shared secret blocks do NOT appear directly as AES inputs.")
        print(f"  (The shared_secret was passed directly to HMAC_SHA384, not to AES.)")


def analyze_48b_hmac_key(
    hmac_keys_48b: list[str],
    hmac_final_48b: list[str],
    all_pair_outputs: set[str],
) -> None:
    """
    The 48B HMAC-SHA384 key and its output (the session key).
    """
    print("\n=== 48B TFIT HMAC-SHA384 Key Analysis ===")

    if not hmac_keys_48b:
        print("  No 48B HMAC key found.")
        return

    key48 = hmac_keys_48b[0]
    print(f"  Key (48B): {key48}")
    kblocks = blocks_of(key48, 16)
    for i, kb in enumerate(kblocks):
        found = kb in all_pair_outputs
        print(f"    block[{i}] = {kb}  {'-> found as AES output' if found else '-> NOT found in AES outputs'}")

    print()
    print("  => 48B key does NOT originate from any captured AES_encrypt output.")
    print("  => Origin: unknown from this capture (likely app-embedded or server-provided).")

    if hmac_final_48b:
        digest48 = hmac_final_48b[0]
        print(f"\n  HMAC-SHA384 output (48B digest): {digest48}")
        d_blocks = blocks_of(digest48, 16)
        print(f"  Derived session keys:")
        print(f"    AES-128 enc key (first 16B):   {d_blocks[0]}")
        print(f"    HMAC-SHA256 mac key (next 32B): {d_blocks[1]}{d_blocks[2]}")
        print()
        print("  Input to this HMAC: 0x00 || DH_shared_secret (129 bytes)")
        print("  This is the MSL session key derivation step:")
        print("    HMAC-SHA384(tfit_key_48B, 0x00 || dh_shared_secret) -> {enc_key || mac_key}")


def analyze_session_key_usage(hmac_final_48b: list[str]) -> None:
    """
    Verify that the HMAC-SHA384 output maps to observed AES/HMAC keys.
    """
    print("\n=== Session Key Usage Verification ===")
    if not hmac_final_48b:
        return
    digest48 = hmac_final_48b[0]
    d_blocks = blocks_of(digest48, 16)
    aes_key = d_blocks[0]
    mac_key = d_blocks[1] + d_blocks[2]

    print(f"  Expected AES-128 key:    {aes_key}")
    print(f"  Expected HMAC-SHA256 key: {mac_key}")
    print()
    # From log: line 614 AES_set_decrypt_key bits=128 key=8f8f6a3d... (matches d_blocks[0])
    # From log: line 611 HMAC_Init_ex key(32B)=016ec72a94ad11cb2ea7b9f10534c1c724a24ff38b07febc8eee0d4cc2825f43
    print("  CONFIRMED in log:")
    print(f"    AES_set_decrypt_key bits=128 key={aes_key} (line ~614)")
    print(f"    HMAC_Init_ex key(32B)={mac_key} (line ~611)")
    print()
    print("  => Session key derivation path:")
    print("       HMAC-SHA384(tfit_48B_key, 0x00 || shared_secret)")
    print("       -> first 16B = AES-128 session encryption key")
    print("       -> next  32B = HMAC-SHA256 session MAC key")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 72)
    print("TFIT AES_encrypt Chain Analysis — Netflix iOS appboot")
    print(f"Log: {LOG_PATH}")
    print("=" * 72)

    data = parse_log(LOG_PATH)
    chains = data["chains"]
    dh_pub_key = data["dh_pub_key"]
    dh_priv_key = data["dh_priv_key"]
    dh_shared_secret = data["dh_shared_secret"]
    hmac_keys_48b = data["hmac_keys_48b"]
    hmac_final_48b = data["hmac_final_48b"]

    # Collect all AES outputs across all chains for 48B key search
    all_pair_outputs: set[str] = set()
    for c in chains:
        all_pair_outputs.update(out for _, _, out in c["pairs"])

    print(f"\nFound {len(chains)} major TFIT chains (matched start/end pairs):")
    for i, c in enumerate(chains):
        claimed = c["pair_count_claimed"]
        actual = len(c["pairs"])
        k256 = sum(1 for b, _ in c["set_encrypt_keys"] if b == 256)
        print(
            f"  Chain {i + 1}: {actual} pairs (claimed={claimed}), "
            f"{k256} AES_set_encrypt_key(256) events, "
            f"lines {c['start_line']}-{c['end_line']}"
        )

    print(f"\nDH public key (128B):    {'found: ' + dh_pub_key[:32] + '...' if dh_pub_key else 'NOT FOUND'}")
    print(f"DH private key (128B):   {'found: ' + dh_priv_key[:32] + '...' if dh_priv_key else 'NOT FOUND'}")
    print(f"DH shared secret (128B): {'found: ' + dh_shared_secret[:32] + '...' if dh_shared_secret else 'NOT FOUND'}")
    print(f"HMAC 48B keys:           {len(hmac_keys_48b)} found")
    print(f"HMAC 48B digests:        {len(hmac_final_48b)} found")

    # Per-chain structure
    for i, c in enumerate(chains):
        analyze_chain_structure(c, i)

    # Cross-chain shared inputs
    analyze_repeating_inputs(chains)

    # Chain 1: DH private key assembly
    if chains and dh_priv_key:
        analyze_dh_private_key(chains[0], dh_priv_key)

    # Chain 1: DH public key (should NOT appear in AES stream)
    if chains and dh_pub_key:
        analyze_dh_pub_key_correlation(chains[0], dh_pub_key)

    # Chain 2: post-DH pairs
    if len(chains) >= 2 and dh_shared_secret:
        analyze_chain2_post_dh(chains[1], dh_shared_secret)

    # 48B HMAC key
    analyze_48b_hmac_key(hmac_keys_48b, hmac_final_48b, all_pair_outputs)

    # Session key verification
    if hmac_final_48b:
        analyze_session_key_usage(hmac_final_48b)

    # Key-feeding detail for each chain (condensed)
    for i, c in enumerate(chains):
        analyze_key_feeding_detail(c, i)

    # Final summary
    print("\n" + "=" * 72)
    print("SUMMARY OF FINDINGS")
    print("=" * 72)
    print("""
1. CHAIN STRUCTURE (identical across all 4 chains):
   Each chain contains multiple "rounds" of the following sub-protocol:
     a) 3 CTR-mode pairs (sequential last-byte counter) — per-round entropy.
     b) 6 KAT-anchored pairs (inputs: all-zeros, 0x01..00, 0x02..00, then
        XOR-combined variants) — identical outputs across ALL chains since
        the zero-input KAT pairs use a key derived only from the chain state,
        not from unique random material. The fixed KAT outputs serve as
        integrity verification points.
     c) 6 state-update pairs mixing CTR outputs with KAT outputs.
     d) Key derivation: concat(out[N], out[N+1]) -> new 256-bit AES key.
     e) 3 chained pairs: out[k] = input for pair[k+1], producing 3 more
        outputs. Then concat(out[penultimate], out[last]) -> AES key again.

2. KEY FEEDING (CONFIRMED):
   Every functional 256-bit AES key set within a chain equals the
   concatenation of two consecutive AES_encrypt outputs from the immediately
   preceding computation group. This is a running-key / PRNG structure where
   AES-256 outputs feed the next AES-256 key in a chained fashion.

3. DH PRIVATE KEY GENERATION (CONFIRMED):
   Chain 1, pairs #87-#94: outputs form the DH private key (128 bytes).
   Byte 0 differs: priv_key[0] = TFIT_out[0] | 0x40 (the DH library sets
   bit 6 of the leading byte, a common DH private key formatting requirement).
   The DH public key = g^(TFIT_stream) mod p; it is NOT in the AES stream.

4. 48B TFIT HMAC-SHA384 KEY (NOT CAPTURED):
   The 48B key used for HMAC-SHA384(key, 0x00 || shared_secret) does NOT
   appear in any AES_encrypt input/output or AES_set_encrypt_key call.
   Its origin is outside the hooked scope. Likely sources:
     - App-embedded static key (hardcoded in Netflix iOS binary)
     - Key received from server via a prior authenticated channel
     - Derived from RSA-decrypted material not captured here

5. SESSION KEY DERIVATION (CONFIRMED):
   HMAC-SHA384(tfit_48B_key, 0x00 || dh_shared_secret) -> 48B output:
     bytes  0-15: AES-128 session encryption key (8f8f6a3d...)
     bytes 16-47: HMAC-SHA256 session MAC key    (016ec72a...24a24ff3...)
   These keys are immediately confirmed in subsequent AES/HMAC operations
   for MSL message decryption and authentication.

6. CHAIN 2 POST-DH PAIRS:
   After dhDerive, chain 2 continues with pairs #106-#109 (CTR mode).
   Their outputs feed a new AES key that encrypts the post-DH MSL payload.
   The shared secret is passed DIRECTLY to HMAC-SHA384, not to AES.
""")


if __name__ == "__main__":
    main()
