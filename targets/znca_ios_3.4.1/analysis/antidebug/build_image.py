#!/usr/bin/env python3
"""Build a rebase-resolved flat memory image of Crew for emulation.

Reads raw file bytes, then for every dyld chained-fixup rebase relocation,
overwrites the 8-byte pointer slot with the fully resolved absolute VA
(lief already resolves target to an absolute VA for rebase entries).
"""
import struct
import lief
from pathlib import Path

BIN_PATH = "/home/vscode/app/targets/znca_ios_3.4.1/Crew"

# Import (bind) symbol name (without leading underscore) -> address we want
# GOT/bind slots pointing at that symbol to resolve to. If the symbol matches
# a known __stubs trampoline used elsewhere in emulate.py's STUBS table, point
# directly at that stub VA so indirect calls (blr via a GOT-loaded pointer)
# land on our hook too. Populated lazily by emulate.py via set_stub_table().
_stub_name_to_addr = {}

def set_stub_table(stubs_dict):
    """stubs_dict: {va: name} as used by emulate.py STUBS."""
    global _stub_name_to_addr
    _stub_name_to_addr = {name: va for va, name in stubs_dict.items()}

FAKEBIND_BASE = 0x00007FB000000000
FAKEBIND_SIZE = 0x00200000

_cache = {}

def get_patched_bytes():
    if "buf" in _cache:
        return _cache["buf"], _cache["segments"]
    raw = bytearray(Path(BIN_PATH).read_bytes())
    b = lief.parse(BIN_PATH)
    segments = []
    for seg in b.segments:
        segments.append((seg.virtual_address, seg.virtual_size, seg.file_offset, seg.name))

    def va_to_off(va):
        for vaddr, vsize, foff, name in segments:
            if vaddr <= va < vaddr + vsize:
                return foff + (va - vaddr)
        return None

    n_patched = 0
    n_skipped = 0
    for r in b.relocations:
        t = r.target
        if not isinstance(t, int):
            n_skipped += 1
            continue
        off = va_to_off(r.address)
        if off is None or off + 8 > len(raw):
            n_skipped += 1
            continue
        struct.pack_into("<Q", raw, off, t & 0xFFFFFFFFFFFFFFFF)
        n_patched += 1
    print(f"[build_image] patched {n_patched} rebase slots, skipped {n_skipped}")

    # --- patch BIND (import) slots ---
    dcf = b.dyld_chained_fixups
    fakebind_buf = bytearray(FAKEBIND_SIZE)
    fakebind_ptr = 0x10  # leave a null cell at offset 0
    name_to_cell = {}
    n_bind_stub = 0
    n_bind_data = 0
    n_bind_skip = 0
    bind_map = {}  # address(int) -> resolved value written (for debugging/report)
    for bd in dcf.bindings:
        sym = bd.symbol
        if sym is None:
            n_bind_skip += 1
            continue
        raw_name = sym.name or ""
        short = raw_name[1:] if raw_name.startswith("_") else raw_name
        off = va_to_off(bd.address)
        if off is None or off + 8 > len(raw):
            n_bind_skip += 1
            continue
        if short in _stub_name_to_addr:
            val = _stub_name_to_addr[short]
            n_bind_stub += 1
        else:
            if raw_name not in name_to_cell:
                cell_va = FAKEBIND_BASE + fakebind_ptr
                name_to_cell[raw_name] = cell_va
                fakebind_ptr += 8
                assert fakebind_ptr < FAKEBIND_SIZE
            val = name_to_cell[raw_name]
            n_bind_data += 1
        struct.pack_into("<Q", raw, off, val & 0xFFFFFFFFFFFFFFFF)
        bind_map[bd.address] = (raw_name, val)
    print(f"[build_image] bind slots: stub-redirected={n_bind_stub} data-fake={n_bind_data} skipped={n_bind_skip}")

    _cache["buf"] = bytes(raw)
    _cache["segments"] = segments
    _cache["fakebind_buf"] = bytes(fakebind_buf)
    _cache["fakebind_base"] = FAKEBIND_BASE
    _cache["fakebind_size"] = FAKEBIND_SIZE
    _cache["bind_map"] = bind_map
    _cache["cell_to_name"] = {cell_va: name for name, cell_va in name_to_cell.items()}
    return _cache["buf"], segments

def get_fakebind_region():
    get_patched_bytes()
    return _cache["fakebind_base"], _cache["fakebind_size"], _cache["fakebind_buf"]

def get_bind_map():
    get_patched_bytes()
    return _cache["bind_map"]

def get_cell_map():
    """{fakebind_cell_va: raw_symbol_name} for every *unresolved* bind symbol
    (i.e. not redirected to a known STUBS entry). Used by emulate.py to
    install a generic catch-all hook at every such cell so direct calls
    through unresolved lazy-bind GOT slots (e.g. plain libc functions we
    didn't explicitly model) don't crash into unmapped/zeroed fakebind
    memory."""
    get_patched_bytes()
    return dict(_cache["cell_to_name"])

if __name__ == "__main__":
    buf, segs = get_patched_bytes()
    print(f"total image bytes: {len(buf)}")
    for s in segs:
        print(f"  va=0x{s[0]:x} size=0x{s[1]:x} foff=0x{s[2]:x} name={s[3]}")
