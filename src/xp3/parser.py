"""
XP3 / Hxv4 archive parser.

Per static analysis, the visible (zlib-compressed) index has been augmented
with a 26-byte 'Hxv4' prefix that points to a separately-encrypted index blob:

    [zlib-decoded XP3 index]
    +0x00  4 bytes "Hxv4"
    +0x04  8 bytes (LE u64) extra-header size = 0x0E
    +0x0c  8 bytes (LE u64) encrypted-blob file offset
    +0x14  4 bytes (LE u32) encrypted-blob size
    +0x18  2 bytes (LE u16) flag (0=raw, 1=zlib-compressed?)
    +0x1a  ... standard XP3 chunks (decoy / placeholders)

Visible chunks describe placeholder files named U+5000 (倀), U+5001 (倁), ...
Real filename mapping is held in the encrypted Hxv4 blob.
"""

import io
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path


XP3_MAGIC = b"XP3\r\n \n\x1a\x8b\x67\x01"


@dataclass
class Hxv4Header:
    extra_header_size: int  # always 0x0E
    blob_offset: int
    blob_size: int
    flag: int  # 0 = raw, 1 = zlib-deflated (= the encrypted-then-deflated case)


@dataclass
class XP3SegmEntry:
    bzlib: int  # 0 = raw, 1 = zlib
    offset: int
    orig_size: int
    arch_size: int


@dataclass
class XP3FileEntry:
    name: str = ""
    protected: int = 0
    info_orig_size: int = 0
    info_arch_size: int = 0
    adlr_hash: int = 0
    time: bytes = b""
    segments: list[XP3SegmEntry] = field(default_factory=list)
    yuzu_extra: bytes = b""


@dataclass
class XP3:
    path: Path
    index_offset: int
    raw_index: bytes
    hxv4: Hxv4Header
    decoy_files: list[XP3FileEntry] = field(default_factory=list)
    encrypted_blob: bytes = b""


def _read_index_offset_v2(f):
    """Read XP3 v2 header and locate the index_offset.

    Layout observed in Kanade:
        0x00..0x0a (11 bytes): magic
        0x0b..0x12 (8 bytes):  0x17 = "info chunk follows" marker
        0x13       (1 byte):   minor_version (0)
        0x14..0x17 (4 bytes):  ?
        0x18..0x1f (8 bytes):  ?
        0x20..0x27 (8 bytes):  index_offset (LE u64)  <-- our target
    """
    f.seek(0)
    magic = f.read(11)
    if magic != XP3_MAGIC:
        raise ValueError(f"not an XP3: magic={magic!r}")
    info_off = struct.unpack("<Q", f.read(8))[0]
    if info_off != 0x17:
        # alternate: legacy XP3 v1 with index_offset in the standard slot
        return info_off
    # Skip extension header (21 bytes total from 0x13 to 0x27)
    f.read(0x14)  # advance to 0x27 - 11 - 8 = ... let's just read until 0x20 then read offset
    # We've consumed 11 + 8 = 19 bytes. To reach 0x20 we need to skip 0x20 - 0x13 = 13 bytes.
    f.seek(0x20)
    return struct.unpack("<Q", f.read(8))[0]


def parse_xp3_index(blob: bytes) -> tuple[Hxv4Header, list[XP3FileEntry]]:
    """Parse Hxv4 prefix + XP3 chunks."""
    if blob[:4] != b"Hxv4":
        raise ValueError(f"not Hxv4: head={blob[:4]!r}")
    extra_size = struct.unpack("<Q", blob[4:12])[0]
    blob_off = struct.unpack("<Q", blob[12:20])[0]
    blob_sz = struct.unpack("<I", blob[20:24])[0]
    flag = struct.unpack("<H", blob[24:26])[0]
    hxv4 = Hxv4Header(extra_size, blob_off, blob_sz, flag)

    body = blob[26:]
    s = io.BytesIO(body)
    files: list[XP3FileEntry] = []
    while s.tell() < len(body):
        magic = s.read(4)
        if len(magic) < 4:
            break
        size = struct.unpack("<Q", s.read(8))[0]
        chunk = s.read(size)
        if magic != b"File":
            continue
        f = _parse_file_chunk(chunk)
        files.append(f)
    return hxv4, files


def _parse_file_chunk(chunk: bytes) -> XP3FileEntry:
    s = io.BytesIO(chunk)
    e = XP3FileEntry()
    while s.tell() < len(chunk):
        m = s.read(4)
        if len(m) < 4:
            break
        sz = struct.unpack("<Q", s.read(8))[0]
        d = s.read(sz)
        if m == b"info":
            e.protected = struct.unpack("<I", d[0:4])[0]
            e.info_orig_size = struct.unpack("<Q", d[4:12])[0]
            e.info_arch_size = struct.unpack("<Q", d[12:20])[0]
            nlen = struct.unpack("<H", d[20:22])[0]
            e.name = d[22 : 22 + nlen * 2].decode("utf-16-le", errors="replace")
        elif m == b"adlr":
            e.adlr_hash = struct.unpack("<I", d[0:4])[0]
        elif m == b"time":
            e.time = d
        elif m == b"segm":
            n_segs = sz // 28
            for i in range(n_segs):
                seg_d = d[i * 28 : (i + 1) * 28]
                bzlib = struct.unpack("<I", seg_d[0:4])[0]
                offv = struct.unpack("<Q", seg_d[4:12])[0]
                orig = struct.unpack("<Q", seg_d[12:20])[0]
                arch = struct.unpack("<Q", seg_d[20:28])[0]
                e.segments.append(XP3SegmEntry(bzlib, offv, orig, arch))
        elif m == b"Yuzu":
            e.yuzu_extra = d
    return e


def open_xp3(path: str | Path) -> XP3:
    p = Path(path)
    f = p.open("rb")
    idx_off = _read_index_offset_v2(f)
    f.seek(idx_off)
    flag = f.read(1)[0]
    csz = struct.unpack("<Q", f.read(8))[0]
    if flag == 1:
        osz = struct.unpack("<Q", f.read(8))[0]
        raw = zlib.decompress(f.read(csz))
        if len(raw) != osz:
            raise ValueError(f"index size mismatch: got {len(raw)} expected {osz}")
    else:
        raw = f.read(csz)

    hxv4, files = parse_xp3_index(raw)
    f.seek(hxv4.blob_offset)
    enc = f.read(hxv4.blob_size)
    f.close()
    return XP3(p, idx_off, raw, hxv4, files, enc)


if __name__ == "__main__":
    import sys

    for arg in sys.argv[1:] or [
        "targets/Kanade/data.xp3",
        "targets/Kanade/patch.xp3",
        "targets/Kanade/steam.xp3",
    ]:
        x = open_xp3(arg)
        print(f"=== {arg} ===")
        print(
            f"  index_offset=0x{x.index_offset:08x}  raw_index_size={len(x.raw_index)}"
        )
        print(
            f"  hxv4: blob_off=0x{x.hxv4.blob_offset:08x} blob_sz=0x{x.hxv4.blob_size:x} flag={x.hxv4.flag}"
        )
        print(f"  decoy files: {len(x.decoy_files)} entries")
        for i, e in enumerate(x.decoy_files[:5]):
            seg = e.segments[0] if e.segments else None
            seg_s = (
                f" segm[bz={seg.bzlib} off=0x{seg.offset:x} orig={seg.orig_size} arch={seg.arch_size}]"
                if seg
                else ""
            )
            print(
                f"    [{i}] name={e.name!r} prot=0x{e.protected:08x} adlr=0x{e.adlr_hash:08x}{seg_s}"
            )
