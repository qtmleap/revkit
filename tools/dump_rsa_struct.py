#!/usr/bin/env python3
"""Chrome Widevine CDM RSA Struct Scanner v2

BoringSSL RSA struct (384 bytes) のレイアウトに基づき、
CDM プロセスのメモリからRSA秘密鍵を検出する。

struct rsa_st layout (Chrome ~2025, macOS arm64):
  +0x00: RSA_METHOD *meth
  +0x08: BIGNUM *n
  +0x10: BIGNUM *e
  +0x18: BIGNUM *d
  +0x20: BIGNUM *p
  +0x28: BIGNUM *q
  +0x30: BIGNUM *dmp1
  +0x38: BIGNUM *dmq1
  +0x40: BIGNUM *iqmp
  +0x48: CRYPTO_EX_DATA (8 bytes)
  +0x50: CRYPTO_refcount_t (4) + flags (4)
  +0x58: CRYPTO_MUTEX (200 bytes = pthread_rwlock_t)
  ...

使い方:
  sudo uv run python dump_rsa_struct.py
"""

import ctypes
import ctypes.util
import json
import os
import struct
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ─── Mach VM API ───
libc = ctypes.CDLL(ctypes.util.find_library("c"))
KERN_SUCCESS = 0
VM_PROT_READ = 0x01

libc.task_for_pid.restype = ctypes.c_int32
libc.task_for_pid.argtypes = [
    ctypes.c_uint32,
    ctypes.c_int32,
    ctypes.POINTER(ctypes.c_uint32),
]
libc.mach_task_self.restype = ctypes.c_uint32
libc.mach_task_self.argtypes = []
libc.mach_vm_read_overwrite.restype = ctypes.c_int32
libc.mach_vm_read_overwrite.argtypes = [
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint64),
]
libc.mach_vm_region.restype = ctypes.c_int32
libc.mach_vm_region.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
]
VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = 9


class VMRegionBasicInfo64(ctypes.Structure):
    _fields_ = [
        ("protection", ctypes.c_int32),
        ("max_protection", ctypes.c_int32),
        ("inheritance", ctypes.c_uint32),
        ("shared", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
        ("behavior", ctypes.c_int32),
        ("user_wired_count", ctypes.c_uint16),
    ]


def get_task_port(pid):
    task = ctypes.c_uint32(0)
    kr = libc.task_for_pid(libc.mach_task_self(), pid, ctypes.byref(task))
    if kr != KERN_SUCCESS:
        print("[!] task_for_pid failed. Run with sudo.")
        sys.exit(1)
    return task.value


def read_memory(task, address, size):
    buf = (ctypes.c_char * size)()
    out_size = ctypes.c_uint64(0)
    buf_ptr = ctypes.cast(buf, ctypes.c_void_p).value
    kr = libc.mach_vm_read_overwrite(
        task,
        ctypes.c_uint64(address),
        ctypes.c_uint64(size),
        ctypes.c_uint64(buf_ptr),
        ctypes.byref(out_size),
    )
    if kr != KERN_SUCCESS:
        return None
    return bytes(buf[: out_size.value])


def enumerate_regions(task):
    regions = []
    address = ctypes.c_uint64(0)
    while True:
        size = ctypes.c_uint64(0)
        info = VMRegionBasicInfo64()
        info_count = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
        obj_name = ctypes.c_uint32(0)
        kr = libc.mach_vm_region(
            task,
            ctypes.byref(address),
            ctypes.byref(size),
            VM_REGION_BASIC_INFO_64,
            ctypes.byref(info),
            ctypes.byref(info_count),
            ctypes.byref(obj_name),
        )
        if kr != KERN_SUCCESS:
            break
        if info.protection & VM_PROT_READ:
            regions.append((address.value, size.value))
        address.value += size.value
    return regions


# ─── BIGNUM reader ───


def read_ptr_at(data, offset):
    if offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, offset)[0]


def read_bignum_value(task, bn_ptr):
    bn_data = read_memory(task, bn_ptr, 24)
    if not bn_data or len(bn_data) < 16:
        return None, 0
    d_ptr = struct.unpack_from("<Q", bn_data, 0)[0]
    width = struct.unpack_from("<I", bn_data, 8)[0]
    if not d_ptr or width <= 0 or width > 128:
        return None, 0
    words_data = read_memory(task, d_ptr, width * 8)
    if not words_data or len(words_data) < width * 8:
        return None, 0
    value = 0
    for i in range(width):
        word = struct.unpack_from("<Q", words_data, i * 8)[0]
        value |= word << (i * 64)
    return value, width


def is_plausible_ptr(p):
    """ユーザ空間のヒープポインタとして妥当か"""
    return 0x100000 < p < 0x800000000000


# ─── Brute-force RSA struct scanner ───


def scan_for_rsa(task, regions, output_dir):
    """様々なオフセットパターンで RSA struct を探す。

    e=3 or e=65537 の BIGNUM を起点に、その前後の BIGNUM ポインタ群を
    検証して RSA struct の先頭を推定する。
    """
    print("[*] Phase 1: Scanning for BIGNUM with e=3 or e=65537...")

    e_candidates = []
    chunk_size = 4 * 1024 * 1024

    for region_start, region_size in regions:
        # dyld shared cache をスキップ
        if 0x180000000 <= region_start < 0x280000000:
            continue
        if region_size < 64:
            continue

        addr = region_start
        remaining = region_size
        while remaining > 0:
            read_size = min(remaining, chunk_size)
            data = read_memory(task, addr, read_size)
            if data is None:
                addr += read_size
                remaining -= read_size
                continue

            # BIGNUM を探す: { BN_ULONG *d; int width; int dmax; int neg; int flags }
            # width=1, value=3 or 65537 のパターン
            # d -> [3] or d -> [65537], width=1
            for off in range(0, len(data) - 24, 8):
                d_ptr = read_ptr_at(data, off)
                if not d_ptr or not is_plausible_ptr(d_ptr):
                    continue

                width = (
                    struct.unpack_from("<I", data, off + 8)[0]
                    if off + 12 <= len(data)
                    else 0
                )
                if width != 1:
                    continue

                dmax = (
                    struct.unpack_from("<I", data, off + 12)[0]
                    if off + 16 <= len(data)
                    else 0
                )
                if dmax < 1 or dmax > 64:
                    continue

                # d_ptr が指す値を読む
                val_data = read_memory(task, d_ptr, 8)
                if val_data is None:
                    continue
                val = struct.unpack_from("<Q", val_data, 0)[0]
                if val in (3, 65537):
                    bn_addr = addr + off
                    e_candidates.append((bn_addr, val))

            addr += read_size
            remaining -= read_size

    print("[*] Found %d BIGNUM candidates with e=3 or e=65537" % len(e_candidates))

    if not e_candidates:
        print("[-] No e candidates found")
        return []

    # Phase 2: 各 e candidate の周辺を探索
    # RSA struct では e は n の直後にある
    # 試すオフセットパターン:
    #   pattern A: n at e_addr - 8 (連続 BIGNUM*)
    #   pattern B: n at e_addr - 8, with meth* before that
    #   pattern C: 任意のオフセット (e_addr - X で X を総当たり)

    print("[*] Phase 2: Checking surrounding memory for RSA struct patterns...")

    results = []
    seen_n = set()

    for e_bn_addr, e_val in e_candidates:
        # e BIGNUM のアドレスを知っている
        # RSA struct 内では e は BIGNUM* として格納される
        # つまり struct 内のどこかに e_bn_addr の値がポインタとして入っている
        # それを探す

        # e_bn_addr を含むリージョンの周辺を読む
        search_start = e_bn_addr - 4096
        search_data = read_memory(task, search_start, 8192)
        if search_data is None:
            continue

        # search_data 内で e_bn_addr の値を持つ 8-byte aligned ポインタを探す
        e_bytes = struct.pack("<Q", e_bn_addr)
        pos = 0
        while True:
            idx = search_data.find(e_bytes, pos)
            if idx < 0:
                break
            if idx % 8 != 0:
                pos = idx + 1
                continue

            # e* のアドレス = search_start + idx
            e_ptr_addr = search_start + idx

            # RSA struct pattern A: e* is at struct_base + 0x10
            # → n* at struct_base + 0x08, d* at + 0x18, etc.
            for e_offset in [0x10, 0x08, 0x18, 0x20]:
                struct_base = e_ptr_addr - e_offset

                # struct 全体を読む (0x48 = iqmp まで)
                s_data = read_memory(task, struct_base, 0x48)
                if s_data is None or len(s_data) < 0x48:
                    continue

                # BIGNUM* を読む (offset 仮定に基づく)
                if e_offset == 0x10:
                    # Standard layout: meth, n, e, d, p, q, dmp1, dmq1, iqmp
                    n_ptr = read_ptr_at(s_data, 0x08)
                    e_ptr = read_ptr_at(s_data, 0x10)
                    d_ptr = read_ptr_at(s_data, 0x18)
                    p_ptr = read_ptr_at(s_data, 0x20)
                    q_ptr = read_ptr_at(s_data, 0x28)
                elif e_offset == 0x08:
                    # No meth: n, e, d, p, q
                    n_ptr = read_ptr_at(s_data, 0x00)
                    e_ptr = read_ptr_at(s_data, 0x08)
                    d_ptr = read_ptr_at(s_data, 0x10)
                    p_ptr = read_ptr_at(s_data, 0x18)
                    q_ptr = read_ptr_at(s_data, 0x20)
                else:
                    pos = idx + 8
                    continue

                if e_ptr != e_bn_addr:
                    pos = idx + 8
                    continue

                if not all(p and is_plausible_ptr(p) for p in [n_ptr, d_ptr]):
                    pos = idx + 8
                    continue

                # n を読む
                n_val, n_width = read_bignum_value(task, n_ptr)
                if n_val is None or n_val.bit_length() < 1900:
                    pos = idx + 8
                    continue

                if n_val in seen_n:
                    pos = idx + 8
                    continue

                # e を検証
                e_v, _ = read_bignum_value(task, e_ptr)
                if e_v != e_val:
                    pos = idx + 8
                    continue

                # d を読む
                d_val, _ = read_bignum_value(task, d_ptr)

                # p, q を読む
                p_val, q_val = None, None
                if p_ptr and is_plausible_ptr(p_ptr):
                    p_val, _ = read_bignum_value(task, p_ptr)
                if q_ptr and is_plausible_ptr(q_ptr):
                    q_val, _ = read_bignum_value(task, q_ptr)

                n_bits = n_val.bit_length()
                verified = p_val and q_val and p_val * q_val == n_val

                print()
                print(
                    "  [HIT] RSA struct @ %#x (e_offset=%#x)" % (struct_base, e_offset)
                )
                print("    n: %d bits, e: %d" % (n_bits, e_val))
                if d_val:
                    print("    d: %d bits" % d_val.bit_length())
                if p_val:
                    print("    p: %d bits" % p_val.bit_length())
                if q_val:
                    print("    q: %d bits" % q_val.bit_length())
                if verified:
                    print("    *** n == p*q VERIFIED ***")

                seen_n.add(n_val)
                results.append(
                    {
                        "struct_addr": struct_base,
                        "e_offset": e_offset,
                        "n": n_val,
                        "e": e_val,
                        "d": d_val,
                        "p": p_val,
                        "q": q_val,
                        "n_bits": n_bits,
                        "verified": verified,
                    }
                )

            pos = idx + 8

    return results


def build_der(n, e, d, p, q):
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateNumbers,
        RSAPublicNumbers,
        rsa_crt_dmp1,
        rsa_crt_dmq1,
        rsa_crt_iqmp,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        NoEncryption,
    )

    dmp1 = rsa_crt_dmp1(d, p)
    dmq1 = rsa_crt_dmq1(d, q)
    iqmp = rsa_crt_iqmp(p, q)
    pub = RSAPublicNumbers(e, n)
    priv = RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
    key = priv.private_key()
    return key.private_bytes(
        Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )


def find_cdm_pid():
    result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "CdmServiceBroker" in line or "sandbox-type=cdm" in line:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    continue
    return None


def main():
    print("=" * 60)
    print("[*] Chrome Widevine CDM RSA Struct Scanner v2")
    print("[*] %s" % datetime.now().isoformat())
    print("[*] Strategy: Find BIGNUM(e=3|65537) → trace back to RSA struct")
    print("=" * 60)
    print()

    if os.geteuid() != 0:
        print("[!] Run with: sudo uv run python dump_rsa_struct.py")
        sys.exit(1)

    pid = find_cdm_pid()
    if not pid:
        print("[!] CDM process not found. Play DRM content first.")
        sys.exit(1)

    print("[+] CDM process: PID %d" % pid)
    task = get_task_port(pid)
    print("[+] Task port: %d" % task)

    regions = enumerate_regions(task)
    print("[*] %d readable regions" % len(regions))

    output_dir = Path("logs") / (
        "rsastruct_%s" % datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    results = scan_for_rsa(task, regions, output_dir)

    if not results:
        print()
        print("[-] No RSA structs found in CDM process heap.")
        sys.exit(0)

    saved = 0
    for i, r in enumerate(results):
        if not (r["d"] and r["p"] and r["q"]):
            print("[%d] Incomplete (missing d/p/q)" % i)
            continue
        if not r["verified"]:
            print("[%d] n != p*q — false positive" % i)
            continue
        try:
            der = build_der(r["n"], r["e"], r["d"], r["p"], r["q"])
            path = output_dir / ("private_key_%d.der" % i)
            path.write_bytes(der)
            print(
                "[+] Key #%d: %s (%d bytes, RSA-%d e=%d)"
                % (i, path, len(der), r["n_bits"], r["e"])
            )
            saved += 1
            jpath = output_dir / ("rsa_struct_%d.json" % i)
            jpath.write_text(
                json.dumps(
                    {
                        "struct_addr": hex(r["struct_addr"]),
                        "e_offset": hex(r["e_offset"]),
                        "n_bits": r["n_bits"],
                        "e": r["e"],
                        "n": hex(r["n"]),
                        "d": hex(r["d"]),
                        "p": hex(r["p"]),
                        "q": hex(r["q"]),
                    },
                    indent=2,
                )
            )
        except Exception as ex:
            print("[%d] DER build failed: %s" % (i, ex))

    print()
    if saved:
        print("=" * 60)
        print("[+] %d key(s) extracted to %s" % (saved, output_dir))
        print("=" * 60)
        print(
            "[*] Verify: uv run python verify_key.py %s/private_key_0.der" % output_dir
        )
    else:
        print("[-] No complete verified keys.")


if __name__ == "__main__":
    main()
