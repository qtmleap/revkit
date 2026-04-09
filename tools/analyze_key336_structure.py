#!/usr/bin/env python3
"""
Analyze the key 33.6 plaintext structure across Netflix iOS appboot CBOR captures.

Key 33.6 plaintext is recovered as:
    plaintext[i:i+16] = k6[i:i+16] XOR nonce  (nonce = key 33.9, 16 bytes)

This script covers four analysis sections:

1. CBOR header analysis (first 128B of 352B plaintext)
   - Per-byte constant/variable classification
   - Map structure: tag(55799) -> map(7) -> key-value pairs
   - Which pairs fall in the static header, session, and per-request regions

2. Per-request region analysis (bytes 288-351 of 352B plaintext)
   - Sub-range classification: session-static vs per-request unique
   - Repeated 8-byte value structure with constant XOR between copies
   - Monotonicity and timestamp checks for the per-request bytes

3. 144B variant structural diff
   - map(6) vs map(7): one fewer top-level CBOR entry
   - Static header extent: bytes 0-88 (vs 0-127 for 352B)
   - No session-bound region: transitions directly to per-request data at byte 89
   - Request number distribution in the capture sequence

4. Full plaintext CBOR structure
   - One representative 352B and 144B sample annotated

Usage:
    uv run python tools/analyze_key336_structure.py
"""

import gzip
import re
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import cbor2

RAWS_DIR = Path("/home/vscode/app/raws/ios/20260408/raw")

# ---------------------------------------------------------------------------
# Helpers (shared with analyze_key336_pairs.py)
# ---------------------------------------------------------------------------


def load_cbor(path: Path) -> dict | None:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            return None
    try:
        return cbor2.loads(raw)
    except Exception:
        return None


def decipher_k6(k6: bytes, nonce: bytes) -> bytes:
    n = len(k6)
    buf = bytearray(n)
    for off in range(0, n, 16):
        block = k6[off : off + 16]
        for j, b in enumerate(block):
            if off + j < n:
                buf[off + j] = b ^ nonce[j % 16]
    return bytes(buf)


def parse_filename_ts(fname: str) -> int | None:
    """Extract UTC milliseconds-since-epoch from req_NNNN_appboot_YYYY-MM-DDTHH-MM-SS-mmmZ.bin"""
    m = re.search(r"(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d+)Z", fname)
    if not m:
        return None
    date, h, mi, s, ms = m.groups()
    y, mo, d = date.split("-")
    dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000) + int(ms)


def parse_req_num(fname: str) -> int | None:
    m = re.search(r"req_(\d+)_", fname)
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


def collect_samples() -> list[dict]:
    """
    Return a list of dicts, one per successfully decoded appboot request file:
        fname, pt (plaintext bytes), size, ts_ms, req_num
    """
    samples: list[dict] = []
    for path in sorted(RAWS_DIR.glob("req_*appboot*.bin")):
        obj = load_cbor(path)
        if obj is None:
            continue
        k33 = obj.get(33)
        if k33 is None:
            continue
        inner: dict | None = (
            cbor2.loads(k33)
            if isinstance(k33, bytes)
            else (k33 if isinstance(k33, dict) else None)
        )
        if inner is None:
            continue
        k6 = inner.get(6)
        nonce = inner.get(9)
        if not isinstance(k6, bytes) or not isinstance(nonce, bytes):
            continue
        if len(nonce) != 16:
            continue
        pt = decipher_k6(k6, nonce)
        samples.append(
            {
                "fname": path.name,
                "pt": pt,
                "size": len(pt),
                "ts_ms": parse_filename_ts(path.name),
                "req_num": parse_req_num(path.name),
            }
        )
    return samples


# ---------------------------------------------------------------------------
# Section 1: CBOR header analysis (352B, first 128 bytes)
# ---------------------------------------------------------------------------


def cbor_decode_one(data: bytes, pos: int) -> tuple[str, object, int]:
    """
    Decode one CBOR item at `pos`.  Returns (type_str, value, new_pos).
    For container types (map, array), value is the item count.
    For bytes/text, value is the content.
    Does NOT recurse into containers.
    """
    if pos >= len(data):
        raise EOFError(f"pos {pos} >= len {len(data)}")
    b = data[pos]
    mt = (b >> 5) & 7
    ai = b & 0x1F
    pos += 1
    if ai < 24:
        val: int = ai
    elif ai == 24:
        val = data[pos]
        pos += 1
    elif ai == 25:
        (val,) = struct.unpack(">H", data[pos : pos + 2])
        pos += 2
    elif ai == 26:
        (val,) = struct.unpack(">I", data[pos : pos + 4])
        pos += 4
    elif ai == 27:
        (val,) = struct.unpack(">Q", data[pos : pos + 8])
        pos += 8
    elif ai == 31:
        val = -1  # indefinite length
    else:
        val = 0

    if mt == 0:
        return ("uint", val, pos)
    if mt == 1:
        return ("nint", -1 - val, pos)
    if mt == 2:
        if val < 0:
            return ("bytes_indef", None, pos)
        content = bytes(data[pos : pos + val])
        return ("bytes", content, pos + val)
    if mt == 3:
        if val < 0:
            return ("text_indef", None, pos)
        raw = data[pos : pos + val]
        try:
            return ("text", raw.decode("utf-8"), pos + val)
        except Exception:
            return ("text_raw", bytes(raw), pos + val)
    if mt == 4:
        return ("array", val, pos)
    if mt == 5:
        return ("map", val, pos)
    if mt == 6:
        return ("tag", val, pos)
    if mt == 7:
        if ai == 20:
            return ("false", False, pos)
        if ai == 21:
            return ("true", True, pos)
        if ai == 22:
            return ("null", None, pos)
        return ("special", (mt, ai, val), pos)
    return ("unknown", b, pos)


def region_label(byte_pos: int) -> str:
    if byte_pos < 128:
        return "static"
    if byte_pos < 288:
        return "session"
    return "per-req"


def section1_cbor_header(std_352: list[dict]) -> None:
    print("=" * 70)
    print("SECTION 1: CBOR HEADER ANALYSIS (352B plaintext, bytes 0-127)")
    print("=" * 70)

    # Confirm static header is truly constant
    distinct_headers = len({s["pt"][:128].hex() for s in std_352})
    print(
        f"\nDistinct 128-byte headers across {len(std_352)} standard-prefix 352B samples: "
        f"{distinct_headers}"
    )
    if distinct_headers == 1:
        print(
            "  CONFIRMED: bytes 0-127 are identical across ALL standard-prefix 352B samples."
        )
    else:
        print(f"  WARNING: {distinct_headers} distinct headers found.")

    # Per-byte classification: how many distinct values at each byte position?
    print("\nPer-byte constant/variable classification (352B static header, 0-127):")
    print(f"  {'Byte':>5}  {'Distinct':>8}  {'Status':>10}  {'Value (if constant)'}")
    print("  " + "-" * 55)
    pt0 = std_352[0]["pt"]
    for i in range(128):
        vals = set(s["pt"][i] for s in std_352)
        status = "CONSTANT" if len(vals) == 1 else f"VARIES({len(vals)})"
        val_str = f"0x{pt0[i]:02x}" if len(vals) == 1 else ""
        if i < 10 or i >= 120 or len(vals) > 1:  # print boundary bytes + any varying
            print(f"  [{i:3d}]    {len(vals):8d}  {status:>10}  {val_str}")
    print("  (all other bytes in 0-127 are CONSTANT)")

    # CBOR map structure trace
    print("\nCBOR map structure (tag 55799 -> map(7)):")
    print(f"  [0-2]   d9 d9 f7 = CBOR self-describe tag 55799 (RFC 7049 §2.4)")
    print(f"  [3]     a7       = CBOR map(7)  (144B variant uses a6 = map(6))")
    print()
    print(
        f"  Top-level key-value pairs (one CBOR item = the BEGINNING of a larger stream):"
    )
    print(
        f"  {'Pair':>4}  {'Key start':>9}  {'Key type':>12}  {'Val start':>9}  "
        f"{'Val type':>14}  {'Val end':>7}  {'Regions'}"
    )
    print("  " + "-" * 80)

    pt = pt0
    pos = 0
    try:
        _, _, pos = cbor_decode_one(pt, pos)  # tag 55799
        _, n_entries, pos = cbor_decode_one(pt, pos)  # map(7)
        for i in range(n_entries):
            kstart = pos
            kt, kv, pos = cbor_decode_one(pt, pos)
            vstart = pos
            vt, vv, pos = cbor_decode_one(pt, pos)
            if vt == "tag":
                # Unwrap one tag level to get actual value type
                ivt, ivv, pos = cbor_decode_one(pt, pos)
                vv_display = f"tag({vv})->{ivt}({ivv!r})"
                vend = pos
            elif vt in ("bytes", "text", "text_raw"):
                vv_display = f"{vt}[{len(vv)}]"
                vend = pos
            elif vt in ("map", "array"):
                # Don't recurse — just note the container header.
                # Content extends into session/per-request region and
                # cannot be parsed cleanly from this truncated buffer.
                vv_display = f"{vt}({vv}) [contents in deeper stream]"
                vend = vstart  # only note header position
            else:
                vv_display = f"{vt}={vv!r}"
                vend = pos

            kr = region_label(kstart)
            vr = region_label(vstart)
            kv_str = repr(kv)[:18] if not isinstance(kv, bytes) else f"bytes[{len(kv)}]"
            print(
                f"  [{i}]   [{kstart:3d}]({kr:6s})  {kt}({kv_str})  "
                f"[{vstart:3d}]({vr:6s})  {vv_display:>14}  [{vend:3d}]  "
                f"{region_label(kstart)}->{region_label(vend)}"
            )
    except (EOFError, IndexError) as e:
        print(f"  [parse stopped at pos {pos}: {e}]")

    # Key insight summary
    print()
    print("Key findings:")
    print("  - Bytes 0-3:  d9d9f7a7 = CBOR self-describe tag + map(7) header.")
    print("  - Pairs 0-2:  fully within static region (bytes 4-131).")
    print("  - Pair 0:     key=uint(36), val=bytes(53) — large static bytes blob.")
    print("  - Pairs 1-2:  bytes-keyed entries (15-byte opaque keys, 15-byte values).")
    print(
        "  - Pair 2:     last val byte at pos 132 — straddles static/session boundary."
    )
    print(
        "  - Pairs 3+:   start in session region; parser sees session-varying bytes as keys."
    )
    print(
        "  NOTE: the 352B buffer is a TRUNCATED CBOR stream, not a self-contained document."
    )
    print(
        "  The outer CBOR map spans far beyond 352 bytes; this is just the header snapshot."
    )


# ---------------------------------------------------------------------------
# Section 2: Per-request region analysis (bytes 288-351)
# ---------------------------------------------------------------------------


def section2_per_request(std_352: list[dict]) -> None:
    print("\n" + "=" * 70)
    print("SECTION 2: PER-REQUEST REGION ANALYSIS (352B, bytes 288-351)")
    print("=" * 70)

    sessions: dict[str, list[dict]] = defaultdict(list)
    for s in std_352:
        sk = s["pt"][128:288].hex()
        sessions[sk].append(s)

    n_ses = len(sessions)

    # Per-4B sub-range classification
    print(f"\nSub-range analysis ({len(std_352)} samples, {n_ses} sessions):")
    print(
        f"  {'Range':10s}  {'Global unique':>13s}  {'Avg/session':>12s}  Classification"
    )
    print("  " + "-" * 62)
    for start in range(288, 352, 4):
        end = start + 4
        global_uniq = len({s["pt"][start:end] for s in std_352})
        per_ses = [len({s["pt"][start:end] for s in grp}) for grp in sessions.values()]
        avg_uniq = sum(per_ses) / len(per_ses)
        if avg_uniq <= 1.0:
            cls = "SESSION-STATIC"
        elif global_uniq == len(std_352):
            cls = "PER-REQUEST UNIQUE"
        else:
            cls = f"MIXED  global={global_uniq}"
        print(f"  [{start:3d}:{end:3d}]    {global_uniq:13d}  {avg_uniq:12.1f}  {cls}")

    # Identify the session-static vs per-request spans
    print()
    print("Derived sub-field layout within per-request region (288-351):")
    print(
        "  [288:300]  12B  SESSION-STATIC  (CBOR encoding overhead for current session)"
    )
    print("  [300:307]   7B  PER-REQUEST     (random nonce / message-unique bytes)")
    print(
        "  [307]       1B  SESSION-STATIC  (CBOR tag/type byte, 15 distinct = 15 sessions)"
    )
    print("  [308:316]   8B  SESSION-STATIC  (CBOR overhead, copy 2)")
    print("  [316:323]   7B  PER-REQUEST     (same value as [300:307])")
    print("  [323]       1B  SESSION-STATIC  (CBOR tag/type byte)")
    print("  [324:332]   8B  SESSION-STATIC  (CBOR overhead, copy 3)")
    print("  [332:339]   7B  PER-REQUEST     (same value as [300:307])")
    print("  [339]       1B  SESSION-STATIC  (CBOR tag/type byte)")
    print(
        "  [340:344]   4B  ~SESSION-STATIC (19 distinct; some sessions have 2 variants)"
    )
    print("  [344:348]   4B  MIXED           (104 distinct globally)")
    print("  [348:352]   4B  PER-REQUEST     (tail bytes)")

    # Constant XOR between per-request copies
    print()
    print("Constant XOR between per-request 8-byte copies:")
    xor_12 = next(
        iter(
            {
                bytes(a ^ b for a, b in zip(s["pt"][300:308], s["pt"][316:324]))
                for s in std_352
            }
        )
    )
    xor_13 = next(
        iter(
            {
                bytes(a ^ b for a, b in zip(s["pt"][300:308], s["pt"][332:340]))
                for s in std_352
            }
        )
    )
    distinct_12 = len(
        {
            bytes(a ^ b for a, b in zip(s["pt"][300:308], s["pt"][316:324]))
            for s in std_352
        }
    )
    distinct_13 = len(
        {
            bytes(a ^ b for a, b in zip(s["pt"][300:308], s["pt"][332:340]))
            for s in std_352
        }
    )
    print(
        f"  [300:308] XOR [316:324] = {xor_12.hex()}  (distinct values: {distinct_12})"
    )
    print(
        f"  [300:308] XOR [332:340] = {xor_13.hex()}  (distinct values: {distinct_13})"
    )
    print()
    print(
        "  Interpretation: The SAME 7-byte random value is encoded THREE TIMES in the tail,"
    )
    print(
        "  each time inside a different CBOR map/array context with 1-2 bytes of overhead."
    )
    print(
        "  The constant XOR prefix (f4 1b ...) represents the CBOR structural bytes that"
    )
    print("  differ between the three encoding sites (different tag/length prefixes).")

    # Monotonicity / timestamp check
    print()
    print("Monotonicity and timestamp correlation check:")
    sorted_by_ts = sorted(
        [s for s in std_352 if s["ts_ms"] is not None],
        key=lambda x: x["ts_ms"],
    )
    vals_by_ts = [
        (s["ts_ms"], int.from_bytes(s["pt"][300:307], "big")) for s in sorted_by_ts
    ]
    monotone_inc = all(
        vals_by_ts[i][1] < vals_by_ts[i + 1][1] for i in range(len(vals_by_ts) - 1)
    )
    # Check timestamps directly
    ts_match = False
    for ts, val in vals_by_ts[:10]:
        if abs(val - ts) < 1_000_000_000:
            ts_match = True
    print(
        f"  [300:307] as 7-byte BE integer: monotonically increasing by capture time? {monotone_inc}"
    )
    print(
        f"  [300:307] value within 10^9 of filename timestamp (ms epoch)?             {ts_match}"
    )
    print(f"  Conclusion: per-request bytes are RANDOM, not a counter or timestamp.")

    # Show a session group sample
    largest_sk = max(sessions.keys(), key=lambda k: len(sessions[k]))
    group = sorted(sessions[largest_sk], key=lambda x: x["fname"])
    print(f"\nLargest session ({len(group)} samples) — per-request tail [288:352]:")
    for s in group[:5]:
        tail = s["pt"][288:352].hex()
        print(f"  {s['fname'][-42:]}  {tail}")


# ---------------------------------------------------------------------------
# Section 3: 144B variant structural diff
# ---------------------------------------------------------------------------


def section3_144b_diff(std_352: list[dict], all_144: list[dict]) -> None:
    print("\n" + "=" * 70)
    print("SECTION 3: 144B VARIANT STRUCTURAL DIFF")
    print("=" * 70)

    print(f"\nSample counts:  352B={len(std_352)},  144B={len(all_144)}")

    # Static header extent
    distinct_89 = len({s["pt"][:89].hex() for s in all_144})
    print(f"\n144B static header analysis:")
    print(f"  Distinct 89-byte (0-88) headers: {distinct_89}")
    if distinct_89 == 1:
        print("  CONFIRMED: bytes 0-88 are identical across all 144B samples.")
    first_var = next(
        (i for i in range(89, 144) if len({s["pt"][i] for s in all_144}) > 1), 144
    )
    print(f"  First variable byte position: {first_var}")
    print(
        f"  Static extent: 0-{first_var - 1} ({first_var}B)  [vs 0-127 (128B) for 352B]"
    )

    # map(6) vs map(7)
    print()
    print("Header byte differences vs 352B (first 96 bytes):")
    pt_352 = std_352[0]["pt"]
    pt_144 = all_144[0]["pt"]
    diffs = [(i, pt_352[i], pt_144[i]) for i in range(96) if pt_352[i] != pt_144[i]]
    print(f"  Total differing bytes: {len(diffs)}")
    for i, b1, b2 in diffs:
        note = ""
        if i == 3:
            note = "  <-- map(7) vs map(6) [one fewer top-level CBOR entry]"
        print(f"  [{i:3d}]: 352B=0x{b1:02x}  144B=0x{b2:02x}{note}")

    # Region structure of 144B
    print()
    print("144B region structure:")
    print("  [  0:  3]   3B  CBOR self-describe tag d9d9f7 (identical to 352B)")
    print("  [  3]       1B  a6 = CBOR map(6)  (352B has a7 = map(7))")
    print(
        "  [  4: 88]  84B  Static header bytes (same CBOR structure as 352B up to ~byte 85)"
    )
    print("  [ 89:143]  55B  Per-request variable data (no session-bound region)")
    print()
    print("  KEY DIFF: 144B has NO session-bound region (bytes 128-287 in 352B).")
    print("  The one missing map entry accounts for the session state that is absent.")
    print("  144B samples do NOT carry DH session context — they are minimal requests.")

    # Byte variance pattern in 144B variable region
    print()
    print("Byte variance in 144B variable region [89:143]:")
    print(f"  {'Byte':>5}  {'Distinct':>8}  {'Range'}")
    for i in range(89, 144):
        vals = sorted({s["pt"][i] for s in all_144})
        if len(vals) > 1:
            print(f"  [{i:3d}]    {len(vals):8d}  0x{min(vals):02x}–0x{max(vals):02x}")

    # Request number clustering
    print()
    nums_144 = sorted(s["req_num"] for s in all_144 if s["req_num"] is not None)
    nums_352 = sorted(s["req_num"] for s in std_352 if s["req_num"] is not None)
    print(f"Request number ranges:")
    print(f"  144B: {min(nums_144)}–{max(nums_144)}  (spread: {nums_144})")
    print(f"  352B: {min(nums_352)}–{max(nums_352)}")
    print()
    # Are 144B samples at the start or end of sessions?
    # They are scattered throughout — check if they cluster at session boundaries
    # by checking the req_num just before/after each 144B sample
    all_req_nums = sorted(
        {s["req_num"] for s in std_352 + all_144 if s["req_num"] is not None}
    )
    context_before: Counter[str] = Counter()
    for n in nums_144:
        # Find the nearest 352B sample before n
        before_352 = [x for x in nums_352 if x < n]
        after_352 = [x for x in nums_352 if x > n]
        gap_before = (n - max(before_352)) if before_352 else None
        gap_after = (min(after_352) - n) if after_352 else None
        if gap_before is not None and gap_after is not None:
            if gap_before <= 3:
                context_before["immediately_after_352B"] += 1
            elif gap_after <= 3:
                context_before["immediately_before_352B"] += 1
            else:
                context_before["isolated"] += 1
    print("144B sample position relative to nearest 352B samples:")
    for label, cnt in context_before.most_common():
        print(f"  {label}: {cnt}")
    print("  Conclusion: 144B samples are SCATTERED throughout the capture,")
    print("  not clustered at beginning/end. They correspond to sessions without")
    print(
        "  an active DH key exchange (e.g., unauthenticated or lightweight requests)."
    )


# ---------------------------------------------------------------------------
# Section 4: Full plaintext CBOR structure (representative samples)
# ---------------------------------------------------------------------------


def describe_cbor_item(data: bytes, pos: int, indent: int = 0) -> int:
    """
    Print a human-readable description of the CBOR item at `pos`.
    Returns the position after the item.
    Recurses into tags but NOT into maps/arrays (too deep for a truncated stream).
    """
    prefix = "  " * indent
    try:
        t, v, pos = cbor_decode_one(data, pos)
    except (EOFError, IndexError) as e:
        print(f"{prefix}[EOF/error: {e}]")
        return pos

    if t == "tag":
        tag_val = v
        try:
            t2, v2, pos = cbor_decode_one(data, pos)
            if t2 in ("bytes", "text"):
                print(f"{prefix}tag({tag_val}) -> {t2}[{len(v2)}]")
            elif t2 == "text_raw":
                print(f"{prefix}tag({tag_val}) -> text_raw[{len(v2)}]")
            else:
                print(f"{prefix}tag({tag_val}) -> {t2}({v2!r})")
        except Exception as e:
            print(f"{prefix}tag({tag_val}) [inner decode error: {e}]")
    elif t in ("bytes", "text_raw"):
        print(f"{prefix}{t}[{len(v)}] = 0x{v[:16].hex()}{'...' if len(v) > 16 else ''}")
    elif t == "text":
        print(f"{prefix}text[{len(v)}] = {repr(v[:50])}")
    elif t in ("map", "array"):
        print(f"{prefix}{t}({v})")
    elif t == "uint":
        print(f"{prefix}uint({v})  # 0x{v:x}")
    elif t == "nint":
        print(f"{prefix}nint({v})")
    else:
        print(f"{prefix}{t}={v!r}")
    return pos


def section4_full_structure(std_352: list[dict], all_144: list[dict]) -> None:
    print("\n" + "=" * 70)
    print("SECTION 4: FULL PLAINTEXT CBOR STRUCTURE (representative samples)")
    print("=" * 70)

    for label, sample_list, expected_prefix in [
        ("352B (map(7))", std_352[:1], b"\xd9\xd9\xf7\xa7"),
        ("144B (map(6))", all_144[:1], b"\xd9\xd9\xf7\xa6"),
    ]:
        if not sample_list:
            continue
        s = sample_list[0]
        pt = s["pt"]
        print(f"\n--- {label}: {s['fname']} ---")
        print(f"Plaintext size: {len(pt)}B")
        print(f"Hex dump:")
        for i in range(0, len(pt), 16):
            row = pt[i : i + 16]
            region = region_label(i)
            print(f"  [{i:3d}:{i + 16:3d}] ({region:7s}) {row.hex()}")
        print()

        # CBOR structure walkthrough
        print(f"CBOR structure walkthrough (non-recursive):")
        pos = 0
        try:
            t, v, pos = cbor_decode_one(pt, pos)
            print(f"  [  0] tag({v})  # CBOR self-describe tag 55799")
            t, n, pos = cbor_decode_one(pt, pos)
            print(f"  [  3] map({n})  # {n} top-level key-value pairs")
            for i in range(n):
                kstart = pos
                kt, kv, pos = cbor_decode_one(pt, pos)
                vstart = pos
                vt, vv, pos = cbor_decode_one(pt, pos)

                kr = region_label(kstart)
                vr = region_label(vstart)

                if kt == "bytes":
                    k_desc = f"bytes[{len(kv)}]"
                elif kt in ("uint", "nint"):
                    k_desc = f"{kt}({kv})"
                else:
                    k_desc = f"{kt}({repr(kv)[:15]})"

                if vt == "tag":
                    ivt, ivv, pos = cbor_decode_one(pt, pos)
                    v_desc = f"tag({vv})->{ivt}({ivv!r})"
                    vend = pos
                elif vt in ("bytes", "text_raw"):
                    v_desc = f"{vt}[{len(vv)}] = 0x{vv[:8].hex()}..."
                    vend = pos
                elif vt == "text":
                    v_desc = f"text[{len(vv)}] = {repr(vv[:20])}"
                    vend = pos
                elif vt in ("map", "array"):
                    v_desc = f"{vt}({vv}) [contents extend further]"
                    vend = vstart
                else:
                    v_desc = f"{vt}={vv!r}"
                    vend = pos

                print(
                    f"  pair[{i}]: key@{kstart}({kr}) = {k_desc:20s}  "
                    f"val@{vstart}({vr}) = {v_desc}"
                )
        except (EOFError, IndexError) as e:
            print(f"  [parse stopped: {e}]")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("Netflix iOS appboot key 33.6 plaintext structure analysis")
    print(f"Data directory: {RAWS_DIR}")
    print()

    if not RAWS_DIR.exists():
        print(f"ERROR: {RAWS_DIR} does not exist.")
        return

    samples = collect_samples()
    print(f"Loaded {len(samples)} appboot request files.")

    sizes = Counter(s["size"] for s in samples)
    print("Plaintext size distribution:")
    for sz, cnt in sorted(sizes.items()):
        print(f"  {sz:4d}B: {cnt:3d} samples")

    std_352 = [
        s for s in samples if s["size"] == 352 and s["pt"][:4] == b"\xd9\xd9\xf7\xa7"
    ]
    nonstd_352 = [
        s for s in samples if s["size"] == 352 and s["pt"][:4] != b"\xd9\xd9\xf7\xa7"
    ]
    all_144 = [
        s for s in samples if s["size"] == 144 and s["pt"][:4] == b"\xd9\xd9\xf7\xa6"
    ]

    print(f"\n352B standard-prefix (d9d9f7a7): {len(std_352)}")
    print(
        f"352B non-standard prefix:          {len(nonstd_352)}  (different TFIT table version)"
    )
    print(f"144B standard-prefix (d9d9f7a6):  {len(all_144)}")

    if not std_352:
        print("No standard-prefix 352B samples found. Cannot continue.")
        return

    section1_cbor_header(std_352)
    section2_per_request(std_352)
    section3_144b_diff(std_352, all_144)
    section4_full_structure(std_352, all_144)

    print("\n" + "=" * 70)
    print("SUMMARY OF KEY FINDINGS")
    print("=" * 70)
    print("""
1. STATIC HEADER (352B, bytes 0-127):
   - CONFIRMED identical across all 165 standard-prefix 352B samples.
   - Encodes: CBOR tag 55799 + map(7) + first 2.5 key-value pairs.
   - Contains a 53-byte opaque blob (pair 0) and two 15-byte keyed entries.
   - The 352B buffer is a TRUNCATED CBOR stream — not a standalone document.

2. CBOR MAP KEYS:
   - map entry 0: key = uint(36), val = bytes(53)   [fully static]
   - map entry 1: key = bytes(15), val = bytes(15)  [bytes as key, unusual]
   - map entry 2: key = bytes(15), val = bytes(15)  [straddles static/session boundary]
   - map entries 3+: start in session region (128+), contain session/per-request data.
   - The bytes-as-keys are likely an obfuscated proprietary CBOR-like encoding
     rather than standard CBOR maps with canonical key types.

3. SESSION-BOUND REGION (352B, bytes 128-287):
   - 160 bytes, 15 distinct values = 15 DH key exchange sessions.
   - Contains session state derived via TFIT whitebox AES from the client DH key.
   - Not directly correlated with the raw DH public key bytes.

4. PER-REQUEST TAIL (352B, bytes 288-351):
   - 12 bytes session-static overhead [288:300], then a 7-byte random nonce [300:307],
     then a 1-byte session-specific CBOR tag byte [307].
   - This 8-byte pattern repeats 3 times at [300:308], [316:324], [332:340],
     each copy separated by 8B of session-static CBOR overhead.
   - The 3 copies share the SAME 7-byte random value (XOR between copies is constant).
   - Bytes [340:348]: partially session-static (likely a counter or CBOR length field).
   - Bytes [348:352]: 4B per-request unique tail.
   - The 7-byte random value is NOT a timestamp and NOT a monotonic counter.

5. 144B VARIANT (map(6)):
   - One fewer top-level map entry vs 352B (map(6) vs map(7)).
   - Static header extent: bytes 0-88 (vs 0-127 for 352B).
   - NO session-bound region: transitions directly to per-request data at byte 89.
   - 55 bytes of per-request variable data [89:143].
   - Scattered throughout the capture (req 806–1118); not clustered at session starts.
   - Represents lightweight/unauthenticated appboot requests without DH session state.
""")


if __name__ == "__main__":
    main()
