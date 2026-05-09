#!/usr/bin/env python3
"""
KANADE PSB format tree parser.
Format: c1 a2 VV 00 00 00 | sequence of (raw_str_key, value_node) pairs
value_node: 2-byte tag + payload
  c1 6e  MAP:   uint32 count x (raw_str_key, value_node)
  81 XX  ARRAY: uint32 count x value_node
  02 XX  STR:   uint32 char_count x UTF-16LE char
  00 XX  NULL:  uint32 value (semantics TBD)
"""

import struct
import sys
import os


def parse(data):
    pos = [6]  # mutable for nested functions
    n = len(data)

    def read_u32():
        if pos[0] + 4 > n:
            raise EOFError(f"read_u32 at {pos[0]}, file size {n}")
        v = struct.unpack_from("<I", data, pos[0])[0]
        pos[0] += 4
        return v

    def read_raw_str():
        count = read_u32()
        if count > 200000:
            raise ValueError(f"str count {count} at {pos[0]-4}")
        end = pos[0] + count * 2
        if end > n:
            raise EOFError(f"str body at {pos[0]}, need {count*2} bytes")
        raw = data[pos[0]:end]
        pos[0] = end
        return count, raw

    def read_value():
        if pos[0] + 2 > n:
            raise EOFError(f"tag at {pos[0]}")
        t1, t2 = data[pos[0]], data[pos[0] + 1]
        pos[0] += 2

        if t1 == 0x02:  # string value
            count = read_u32()
            if count > 200000:
                raise ValueError(f"str val count {count}")
            raw = data[pos[0]:pos[0] + count * 2]
            pos[0] += count * 2
            return {"type": "str", "tag2": t2, "count": count, "raw": raw}

        elif t1 == 0xc1:  # map (string-keyed dict)
            count = read_u32()
            if count > 100000:
                raise ValueError(f"map count {count}")
            entries = {}
            for _ in range(count):
                kcount, kraw = read_raw_str()
                try:
                    key = kraw.decode("utf-16-le")
                except Exception:
                    key = kraw.hex()
                val = read_value()
                entries[key] = val
            return {"type": "map", "tag2": t2, "entries": entries}

        elif t1 == 0x81:  # array
            count = read_u32()
            if count > 100000:
                raise ValueError(f"arr count {count}")
            items = [read_value() for _ in range(count)]
            return {"type": "arr", "tag2": t2, "items": items}

        elif t1 == 0x00:  # null / zero scalar
            val = read_u32()
            return {"type": "null", "tag2": t2, "val": val}

        else:
            raise ValueError(f"unknown tag {t1:02x} {t2:02x} at {pos[0]-2}")

    root = {}
    while pos[0] < n - 6:
        before = pos[0]
        try:
            kcount, kraw = read_raw_str()
            key = kraw.decode("utf-16-le", errors="replace")
            val = read_value()
            root[key] = val
        except Exception:
            pos[0] = before
            break
    return root


def show(node, depth=0, key=""):
    indent = "  " * depth
    prefix = f"{key}: " if key else ""
    t = node.get("type")
    if t == "str":
        raw = node["raw"]
        # Try plain UTF-16LE
        try:
            s = raw.decode("utf-16-le")
            if all(0x20 <= ord(c) < 0x7f or ord(c) in (0x0a, 0x0d) for c in s):
                print(f"{indent}{prefix}STR({node['count']}) [{node['tag2']:02x}] = {repr(s)}")
                return
        except Exception:
            pass
        # Show raw hex words
        words = [struct.unpack_from("<H", raw, i * 2)[0] for i in range(min(node["count"], 8))]
        suffix = "..." if node["count"] > 8 else ""
        print(f"{indent}{prefix}STR({node['count']}) [{node['tag2']:02x}] encoded={[f'{w:04x}' for w in words]}{suffix}")
    elif t == "map":
        print(f"{indent}{prefix}MAP({len(node['entries'])}) [{node['tag2']:02x}]")
        for k, v in node["entries"].items():
            show(v, depth + 1, k)
    elif t == "arr":
        print(f"{indent}{prefix}ARR({len(node['items'])}) [{node['tag2']:02x}]")
        for i, item in enumerate(node["items"]):
            show(item, depth + 1, f"[{i}]")
    elif t == "null":
        print(f"{indent}{prefix}NULL [{node['tag2']:02x}] val={node['val']}")
    else:
        print(f"{indent}{prefix}??? {node}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        # Default: first v8 scenario file
        d = "/home/vscode/app/targets/Kanade/_decrypted/scenario"
        for f in sorted(os.listdir(d)):
            if "v8" in f:
                path = os.path.join(d, f)
                break
    data = open(path, "rb").read()
    version = data[2]
    print(f"File: {path}")
    print(f"Magic: {data[:2].hex()}  Version: {version}  Size: {len(data)}")
    tree = parse(data)
    for k, v in tree.items():
        show(v, 0, k)
