#!/usr/bin/env python3
"""Chrome Widevine CDM Private Key Extractor (External Memory Read)

Frida のインジェクションを使わず、macOS の Mach VM API で
CDM プロセスのメモリを外部から読み取り、RSA 秘密鍵を検出する。

CDM の VerifyCdmHost_0 はプロセス内のコード改竄を検出するが、
外部からのメモリ読み取りは検出されない。

使い方:
  1. Chrome で DRM コンテンツを再生開始 (再生が動作していることを確認)
  2. sudo uv run python run_key_extract.py
"""

import ctypes
import ctypes.util
import json
import os
import re
import signal
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ─── Mach VM API ───

libc = ctypes.CDLL(ctypes.util.find_library("c"))

KERN_SUCCESS = 0
VM_REGION_BASIC_INFO_64 = 9
VM_PROT_READ = 0x01

# task_for_pid(mach_port_t target, int pid, mach_port_t *task) -> kern_return_t
libc.task_for_pid.restype = ctypes.c_int32
libc.task_for_pid.argtypes = [
    ctypes.c_uint32,
    ctypes.c_int32,
    ctypes.POINTER(ctypes.c_uint32),
]

# mach_task_self() -> mach_port_t
libc.mach_task_self.restype = ctypes.c_uint32
libc.mach_task_self.argtypes = []

# mach_vm_read_overwrite(task, address, size, data, outsize) -> kern_return_t
libc.mach_vm_read_overwrite.restype = ctypes.c_int32
libc.mach_vm_read_overwrite.argtypes = [
    ctypes.c_uint32,  # task
    ctypes.c_uint64,  # address
    ctypes.c_uint64,  # size
    ctypes.c_uint64,  # data (pointer as uint64)
    ctypes.POINTER(ctypes.c_uint64),  # outsize
]


def get_task_port(pid: int) -> int:
    """Get a Mach task port for the given PID."""
    task = ctypes.c_uint32(0)
    kr = libc.task_for_pid(libc.mach_task_self(), pid, ctypes.byref(task))
    if kr != KERN_SUCCESS:
        if kr == 5:  # KERN_FAILURE - usually permission denied
            print(f"[!] task_for_pid failed (permission denied)")
            print(f"    Run with sudo: sudo uv run python run_key_extract.py")
            sys.exit(1)
        raise OSError(f"task_for_pid failed: kern_return={kr}")
    return task.value


def read_memory(task: int, address: int, size: int) -> bytes | None:
    """Read memory from a remote process. Returns None on failure."""
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


# ─── Memory Region Enumeration ───

# mach_vm_region(task, &addr, &size, flavor, info, &infoCnt, &objName)
libc.mach_vm_region.restype = ctypes.c_int32
libc.mach_vm_region.argtypes = [
    ctypes.c_uint32,  # task
    ctypes.POINTER(ctypes.c_uint64),  # address (in/out)
    ctypes.POINTER(ctypes.c_uint64),  # size (out)
    ctypes.c_int32,  # flavor
    ctypes.c_void_p,  # info (out)
    ctypes.POINTER(ctypes.c_uint32),  # infoCnt (in/out)
    ctypes.POINTER(ctypes.c_uint32),  # object_name (out)
]

VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = 9  # struct has 9 natural_t fields


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


def enumerate_regions_mach(task: int) -> list[dict]:
    """Mach VM API でメモリリージョンを列挙する。"""
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

        readable = bool(info.protection & VM_PROT_READ)
        regions.append(
            {
                "start": address.value,
                "end": address.value + size.value,
                "size": size.value,
                "readable": readable,
                "line": "",
            }
        )
        address.value += size.value

    return regions


def get_memory_regions(pid: int, task: int | None = None) -> list[dict]:
    """プロセスのメモリリージョンを取得する。vmmap を試し、失敗したら Mach API。"""
    # まず vmmap を試す
    try:
        result = subprocess.run(
            ["vmmap", "-w", str(pid)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout
        if output and "REGION" in output:
            regions = []
            pattern = re.compile(
                r"^\s*([0-9a-f]+)-([0-9a-f]+)\s+\[\s*[\d.]+[KMG]?\]\s+"
                r"(r|-)(w|-)(x|-)/(r|-)(w|-)(x|-)",
                re.MULTILINE,
            )
            for m in pattern.finditer(output):
                start = int(m.group(1), 16)
                end = int(m.group(2), 16)
                readable = m.group(3) == "r"
                line_start = output.rfind("\n", 0, m.start()) + 1
                line_end = output.find("\n", m.end())
                line = (
                    output[line_start:line_end] if line_end > 0 else output[line_start:]
                )
                regions.append(
                    {
                        "start": start,
                        "end": end,
                        "size": end - start,
                        "readable": readable,
                        "line": line.strip(),
                    }
                )
            if regions:
                print(f"[*] Got {len(regions)} regions via vmmap")
                return regions
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    # vmmap 失敗 → Mach VM API でフォールバック
    if task is not None:
        print("[*] vmmap failed, using Mach VM API...")
        regions = enumerate_regions_mach(task)
        print(f"[*] Got {len(regions)} regions via mach_vm_region")
        return regions

    return []


def find_cdm_regions(regions: list[dict]) -> list[dict]:
    """libwidevinecdm.dylib に関連するリージョンを見つける。"""
    cdm_regions = []
    for r in regions:
        if "widevinecdm" in r["line"].lower() or "widevine" in r["line"].lower():
            cdm_regions.append(r)
    return cdm_regions


# ─── CDM Process Discovery ───


def find_cdm_pid() -> int | None:
    """CDM をロードしている Chrome Helper プロセスの PID を見つける。

    Chrome の CDM プロセスは以下のコマンドライン引数で識別できる:
      --utility-sub-type=media.mojom.CdmServiceBroker
      --service-sandbox-type=cdm
    """
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None

    for line in result.stdout.splitlines():
        # CDM プロセスはコマンドラインで直接識別
        if "CdmServiceBroker" in line or "sandbox-type=cdm" in line:
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                return int(parts[1])
            except ValueError:
                continue

    return None


# ─── RSA Key Detection ───


def find_rsa_keys(data: bytes, base_address: int) -> list[dict]:
    """バイト列から DER エンコードされた RSA 秘密鍵を検索する。"""
    keys = []

    # PKCS#8 パターン: 30 82 XX XX 02 01 00 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01
    pkcs8_header = bytes(
        [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    )
    # PKCS#1 パターン: 30 82 XX XX 02 01 00 02 82
    pkcs1_marker = bytes([0x02, 0x01, 0x00, 0x02, 0x82])

    for i in range(len(data) - 20):
        if data[i] != 0x30 or data[i + 1] != 0x82:
            continue

        # DER SEQUENCE の長さを取得
        seq_len = (data[i + 2] << 8) | data[i + 3]
        total_len = 4 + seq_len

        if total_len < 600 or total_len > 5000:
            continue
        if i + total_len > len(data):
            continue

        # version = 0 チェック
        if data[i + 4] != 0x02 or data[i + 5] != 0x01 or data[i + 6] != 0x00:
            continue

        fmt = None
        # PKCS#8 チェック
        if (
            i + 7 + len(pkcs8_header) <= len(data)
            and data[i + 7 : i + 7 + len(pkcs8_header)] == pkcs8_header
        ):
            fmt = "pkcs8"
        # PKCS#1 チェック
        elif (
            i + 4 + len(pkcs1_marker) <= len(data)
            and data[i + 4 : i + 4 + len(pkcs1_marker)] == pkcs1_marker
        ):
            fmt = "pkcs1"
        else:
            continue

        key_data = data[i : i + total_len]

        # 有効な RSA 鍵か検証
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_der_private_key,
            )

            key_obj = load_der_private_key(key_data, password=None)
            key_size = key_obj.key_size
            exponent = key_obj.public_key().public_numbers().e
        except Exception:
            continue

        keys.append(
            {
                "format": fmt,
                "address": base_address + i,
                "length": total_len,
                "key_bytes": key_data,
                "key_size": key_size,
                "exponent": exponent,
            }
        )

    return keys


# ─── Main ───


def main():
    print("=" * 60)
    print("[*] Chrome Widevine CDM Private Key Extractor")
    print(f"[*] {datetime.now().isoformat()}")
    print("[*] Method: External memory read (Mach VM API)")
    print("=" * 60)
    print()

    # CDM プロセスを探す
    print("[*] Searching for CDM process...")
    cdm_pid = find_cdm_pid()
    if not cdm_pid:
        print("[!] CDM process not found.")
        print("[*] Make sure Chrome is running and DRM content is playing.")
        sys.exit(1)

    print(f"[+] CDM process found: PID {cdm_pid}")

    # Task port を取得 (vmmap より先に必要)
    print("[*] Getting task port...")
    task = get_task_port(cdm_pid)
    print(f"[+] Task port: {task}")

    # メモリリージョンを取得
    print("[*] Getting memory regions...")
    all_regions = get_memory_regions(cdm_pid, task=task)
    cdm_regions = find_cdm_regions(all_regions)

    if cdm_regions:
        print(f"[+] CDM module regions:")
        for r in cdm_regions:
            print(f"    {r['start']:#x}-{r['end']:#x} ({r['size']:,} bytes)")
    else:
        print("[*] CDM module regions not identified (will scan all readable regions)")

    # セッションディレクトリ
    session_dir = (
        Path("logs") / f"keyextract_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    session_dir.mkdir(parents=True, exist_ok=True)

    # ─── ベースラインスキャン ───
    print()
    print("-" * 60)
    print("[Step 1] Baseline scan (recording existing keys)...")
    print("-" * 60)

    baseline_keys = scan_process(task, all_regions, cdm_regions, label="baseline")
    baseline_fps = {k["key_bytes"] for k in baseline_keys}
    print(f"[*] Baseline: {len(baseline_keys)} RSA key(s)")
    for k in baseline_keys:
        addr_note = ""
        if any(r["start"] <= k["address"] < r["end"] for r in cdm_regions):
            addr_note = " [CDM module]"
        elif k["address"] >= 0x180000000:
            addr_note = " [dyld shared cache]"
        print(
            f"    {k['address']:#x} {k['format']} RSA-{k['key_size']} e={k['exponent']}{addr_note}"
        )

    # ─── 再生待機 & 差分スキャン ───
    print()
    print("-" * 60)
    print("[Step 2] Differential scanning...")
    print("         If DRM is already playing, new keys may appear soon.")
    print("         Press ENTER to scan manually, Ctrl+C to stop.")
    print("-" * 60)

    running = True

    def shutdown(sig, frame):
        nonlocal running
        running = False
        print("\n[*] Stopping...")

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    new_keys_all = []
    scan_count = 0

    import select

    last_scan = time.time()

    while running:
        # stdin check
        try:
            rlist, _, _ = select.select([sys.stdin], [], [], 0.5)
            if rlist:
                sys.stdin.readline()
                if running:
                    scan_count += 1
                    print(f"[Scan #{scan_count}] Manual scan...")
                    keys = scan_process(
                        task, all_regions, cdm_regions, label=f"scan_{scan_count}"
                    )
                    new = [k for k in keys if k["key_bytes"] not in baseline_fps]
                    print(f"  Found {len(keys)} total, {len(new)} new")
                    new_keys_all.extend(new)
                    for k in new:
                        baseline_fps.add(k["key_bytes"])
                    last_scan = time.time()
        except (ValueError, OSError):
            time.sleep(0.5)

        # 自動スキャン (3秒間隔)
        if running and time.time() - last_scan >= 3:
            scan_count += 1
            try:
                keys = scan_process(
                    task, all_regions, cdm_regions, label=f"scan_{scan_count}"
                )
            except OSError:
                print("[!] Process may have exited. Trying to re-discover...")
                cdm_pid_new = find_cdm_pid()
                if cdm_pid_new and cdm_pid_new != cdm_pid:
                    cdm_pid = cdm_pid_new
                    all_regions = get_memory_regions(cdm_pid, task=task)
                    cdm_regions = find_cdm_regions(all_regions)
                    task = get_task_port(cdm_pid)
                    print(f"[+] Re-attached to PID {cdm_pid}")
                    keys = scan_process(
                        task, all_regions, cdm_regions, label=f"scan_{scan_count}"
                    )
                else:
                    last_scan = time.time()
                    continue

            new = [k for k in keys if k["key_bytes"] not in baseline_fps]
            if new:
                print(f"[Scan #{scan_count}] {len(new)} NEW key(s) found!")
                new_keys_all.extend(new)
                for k in new:
                    baseline_fps.add(k["key_bytes"])
            else:
                # 進捗表示 (10回ごと)
                if scan_count % 10 == 0:
                    print(f"[Scan #{scan_count}] No new keys yet...")
            last_scan = time.time()

        if new_keys_all:
            break

    # ─── 結果 ───
    print()
    print("=" * 60)
    if new_keys_all:
        print(f"[+] {len(new_keys_all)} NEW key(s) found after baseline!")
        print("=" * 60)
        for i, k in enumerate(new_keys_all):
            fname = f"private_key_{i}.der"
            fpath = session_dir / fname
            fpath.write_bytes(k["key_bytes"])
            addr_note = ""
            if any(r["start"] <= k["address"] < r["end"] for r in cdm_regions):
                addr_note = " [CDM module]"
            print(
                f"  [{i}] {k['format']} RSA-{k['key_size']} e={k['exponent']}"
                f" @ {k['address']:#x}{addr_note} → {fpath}"
            )

        # capture.jsonl にも保存
        capture = session_dir / "capture.jsonl"
        with open(capture, "w") as f:
            for k in new_keys_all:
                entry = {
                    "event": "cdm.privateKey",
                    "ts": datetime.now().isoformat(),
                    "format": k["format"],
                    "address": hex(k["address"]),
                    "length": k["length"],
                    "key_hex": k["key_bytes"].hex(),
                    "key_size": k["key_size"],
                    "exponent": k["exponent"],
                    "is_new": True,
                }
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        print()
        print(f"[*] Saved to {session_dir}/")
        print("[*] Next: verify with")
        print(f"    uv run python verify_key.py {session_dir}/private_key_0.der")
    else:
        print("[-] No new keys found.")
        print("=" * 60)
        print("[*] The CDM device key may be obfuscated in memory.")
        print("[*] Consider trying: longer playback, different content,")
        print("    or hooking BoringSSL's RSA_sign within the CDM.")

    print(f"\n[*] Done. {scan_count} scans performed.")


def scan_process(
    task: int,
    all_regions: list[dict],
    cdm_regions: list[dict],
    label: str,
) -> list[dict]:
    """プロセスメモリをスキャンして RSA 秘密鍵を検索する。"""
    all_keys = []
    chunk_size = 4 * 1024 * 1024  # 4MB chunks
    scanned_regions = 0
    skipped_regions = 0
    read_errors = 0

    # 読み取り可能なリージョンをスキャン
    for region in all_regions:
        if not region["readable"]:
            continue
        if region["size"] < 1024:
            continue

        scanned_regions += 1
        addr = region["start"]
        remaining = region["size"]

        while remaining > 0:
            read_size = min(remaining, chunk_size)
            data = read_memory(task, addr, read_size)
            if data is None:
                read_errors += 1
                # このチャンクをスキップして次へ
                addr += read_size
                remaining -= read_size
                continue
            keys = find_rsa_keys(data, addr)
            all_keys.extend(keys)
            addr += read_size
            remaining -= read_size

    print(
        f"    [{label}] {scanned_regions} regions scanned, "
        f"{read_errors} read errors, {len(all_keys)} key(s) found"
    )
    return all_keys


if __name__ == "__main__":
    main()
