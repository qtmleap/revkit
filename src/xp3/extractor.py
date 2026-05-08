"""
Extract files from a Kanade-style Cxdec-protected XP3 archive using:
  - Visible (zlib) XP3 index (Hxv4-prefixed; placeholder filenames)
  - Per-file XOR-byte protection: bytes 0..15 plaintext, bytes 16+ XOR with
    per-file mask byte. The mask byte is derived from the file's adler32 hash
    by an undocumented (Cxdec-style) formula; we recover it by:
      1. Magic-based reversal — try known plaintext magics at offset 16 and
         derive mask = ciphertext[16] ^ magic[0], verify the rest matches.
      2. Frequency fallback — most-common byte in [16..1024) is the mask
         (works when plaintext has long runs of 0x00).
"""

import argparse
import collections
import zlib
from dataclasses import dataclass
from pathlib import Path

from .parser import XP3FileEntry, open_xp3


@dataclass
class ExtractStats:
    n_files: int = 0
    n_extracted: int = 0
    n_errors: int = 0
    failed: list[tuple[int, str, str]] = None

    def __post_init__(self):
        if self.failed is None:
            self.failed = []


PREAMBLE_BYTES = 16  # bytes 0..15 are NOT XOR-encrypted
PROTECT_FLAG = 0x80000000

# Known plaintext magics that appear at offset 16 (after the 16-byte preamble)
# in Frontwing-wrapped files. Order matters only for tie-breaking; each magic
# is checked independently.
KNOWN_MAGICS_AT_16: tuple[bytes, ...] = (
    b"\xc1\xa2\x06\x00\x00\x00",  # PSB v6 (Frontwing UI scripts)
    b"\xc1\xa2\x07\x00\x00\x00",  # PSB v7
    b"\xc1\xa2\x08\x00\x00\x00",  # PSB v8
    b"\xc1\xa2\x09\x00\x00\x00",  # PSB v9
    b"PSB\x00",                    # PSB v1 (legacy)
    b"\x89PNG\r\n\x1a\n",          # PNG
    b"TLG6.0\x00raw\x1a\x00",      # TLG6
    b"TLG5.0\x00raw\x1a\x00",      # TLG5
    b"TJS2",                       # TJS bytecode
    b"OggS\x00\x02",               # OggS (vorbis bitstream)
    b"\xff\xd8\xff\xe0",           # JPEG/JFIF
    b"\xff\xd8\xff\xe1",           # JPEG/EXIF
    b"OP\x00iNFOR",                # Frontwing OP_iNFOR (unknown format, candidate scenario)
)


def recover_mask_by_magic(raw: bytes) -> int | None:
    """Try known plaintext magics at offset 16; return mask if any matches."""
    if len(raw) < PREAMBLE_BYTES + 4:
        return None
    head = raw[PREAMBLE_BYTES : PREAMBLE_BYTES + 16]
    for magic in KNOWN_MAGICS_AT_16:
        if len(head) < len(magic):
            continue
        candidate = head[0] ^ magic[0]
        if all((head[i] ^ candidate) == magic[i] for i in range(len(magic))):
            return candidate
    return None


def estimate_mask_by_frequency(raw: bytes, sample_window: int = 1024) -> int:
    """Most-frequent byte over [16, 16+window) — mask byte if plaintext has long zero runs."""
    if len(raw) <= PREAMBLE_BYTES:
        return 0
    sample = raw[PREAMBLE_BYTES : PREAMBLE_BYTES + sample_window]
    if not sample:
        return 0
    cnt = collections.Counter(sample)
    return cnt.most_common(1)[0][0]


def estimate_mask_byte(raw: bytes, sample_window: int = 1024) -> int:
    """Magic-based reversal first, fall back to frequency if no magic matches."""
    by_magic = recover_mask_by_magic(raw)
    if by_magic is not None:
        return by_magic
    return estimate_mask_by_frequency(raw, sample_window)


def decrypt_file_bytes(
    raw: bytes,
    bzlib: int,
    protected: int,
    mask_byte: int | None = None,
) -> bytes:
    """Reverse zlib then XOR bytes 16+ with the per-file mask byte.

    Encryption order observed (Cxdec-style):
      plaintext file -> XOR bytes [16, end) with mask -> optionally zlib-compress
    Decryption: optional zlib-decompress -> XOR bytes [16, end) with mask
    """
    if not protected:
        if bzlib == 1:
            return zlib.decompress(raw)
        return raw

    # 1. Inflate if zlib (= reverse the optional outermost compression)
    if bzlib == 1:
        data = zlib.decompress(raw)
    else:
        data = raw

    # 2. Estimate per-file mask if not provided
    if mask_byte is None:
        mask_byte = estimate_mask_byte(data)

    # 3. XOR bytes 16+ with mask
    out = bytearray(data)
    for i in range(PREAMBLE_BYTES, len(out)):
        out[i] ^= mask_byte
    return bytes(out)


def safe_filename(name: str, idx: int) -> str:
    """Convert anonymized U+5000+N or any name to a safe filename."""
    # Anonymized names are single CJK chars from U+5000..U+5FFF
    if len(name) == 1 and 0x5000 <= ord(name) <= 0x5FFF:
        slot = ord(name) - 0x5000
        return f"slot_{slot:05d}"
    # else: sanitize for filesystem; strip any existing extension to avoid double-ext
    base = name.rsplit(".", 1)[0] if "." in name else name
    out = []
    for c in base:
        if c in '/\\:*?"<>|\x00':
            out.append("_")
        else:
            out.append(c)
    return "".join(out) or f"slot_{idx:05d}"


def extract_file(
    f, entry: XP3FileEntry, out_dir: Path, *, idx: int, mask_byte: int | None = None
) -> tuple[bool, str]:
    if not entry.segments:
        return False, "no segments"
    pieces = []
    for seg in entry.segments:
        f.seek(seg.offset)
        raw = f.read(seg.arch_size)
        try:
            piece = decrypt_file_bytes(raw, seg.bzlib, entry.protected, mask_byte)
        except Exception as e:
            return False, f"seg-decrypt fail: {e}"
        pieces.append(piece)
    data = b"".join(pieces)
    name = safe_filename(entry.name, idx)
    # determine output extension based on first bytes (light sniffing)
    ext = sniff_ext(data)
    out_path = out_dir / f"{name}{ext}"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return True, str(out_path)


def sniff_ext(data: bytes) -> str:
    """Identify file type. Checks both offset 0 and offset 16 (= after wuv-style preamble)."""
    if len(data) < 4:
        return ".bin"

    # Check magics at offset 0
    head = data[:16]
    if head[:4] == b"TJS2":
        return ".tjs"
    if head[:4] == b"OggS":
        return ".ogg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if head[:4] == b"PSB\x00":
        return ".psb"
    if head[:4] == b"\xff\xd8\xff\xe0" or head[:4] == b"\xff\xd8\xff\xe1":
        return ".jpg"
    if head[:6] == b"TLG6.0" or head[:6] == b"TLG5.0":
        return ".tlg"
    if head[:2] == b"BM":
        return ".bmp"
    if head[:4] == b"RIFF":
        return ".wav"
    if head.startswith(b"Warning:"):
        return ".txt"

    # Frontwing wuVorbis: 16-byte preamble + vorbis packet at offset 28+
    if len(data) >= 64 and data[26:35] == b"\x01\x1e\x01vorbis":
        return ".wuv"
    if len(data) >= 64 and data[28:35] == b"\x01vorbis":
        return ".wuv"

    # PSB after preamble
    if len(data) >= 20 and data[16:20] == b"PSB\x00":
        return ".psb"

    # TLG after preamble
    if len(data) >= 22 and (data[16:22] == b"TLG6.0" or data[16:22] == b"TLG5.0"):
        return ".tlg"

    # PNG after preamble
    if len(data) >= 24 and data[16:24] == b"\x89PNG\r\n\x1a\n":
        return ".png"

    # OggS scan in first 256 bytes (wuVorbis variant)
    if len(data) >= 64 and b"OggS" in data[:128]:
        return ".ogg"

    return ".bin"


def extract_archive(arc_path: str | Path, out_dir: str | Path, *, limit: int = 0) -> ExtractStats:
    arc_path = Path(arc_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    x = open_xp3(arc_path)
    f = arc_path.open("rb")
    stats = ExtractStats(n_files=len(x.decoy_files))
    files_to_process = x.decoy_files[:limit] if limit > 0 else x.decoy_files
    for idx, e in enumerate(files_to_process):
        ok, info = extract_file(f, e, out_dir, idx=idx)
        if ok:
            stats.n_extracted += 1
        else:
            stats.n_errors += 1
            stats.failed.append((idx, e.name, info))
    f.close()
    return stats


def main():
    p = argparse.ArgumentParser(description="Extract Cxdec-protected XP3 (Kanade)")
    p.add_argument("archive")
    p.add_argument("-o", "--out", default="_unpacked")
    p.add_argument("--limit", type=int, default=0)
    args = p.parse_args()
    s = extract_archive(args.archive, args.out, limit=args.limit)
    print(f"files in archive: {s.n_files}")
    print(f"extracted:        {s.n_extracted}")
    print(f"errors:           {s.n_errors}")
    for idx, name, info in s.failed[:20]:
        print(f"  [{idx}] {name!r}: {info}")


if __name__ == "__main__":
    main()
