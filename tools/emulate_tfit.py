#!/usr/bin/env python3
"""
TFIT whitebox AES-128-ECB emulator using Unicorn Engine.

Emulates TFIT_op_iAES11 from NFWebCrypto.framework (arm64 Mach-O) to compute:
    genModelGroupKeys(MGKType, ESN) -> (mgk_key_16B, mgk_vector_32B)

Which is: SHA384(ESN) split into 3x16B blocks, each TFIT-encrypted with the
device-specific whitebox AES key schedule.

Usage:
    uv run tools/emulate_tfit.py <ESN>
    uv run tools/emulate_tfit.py --test

Binary: /tmp/nfwc/Payload/Argo.app/Frameworks/NFWebCrypto.framework/NFWebCrypto
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

import lief
from unicorn import (
    UC_ARCH_ARM64,
    UC_MODE_ARM,
    Uc,
    UcError,
    arm64_const,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W0,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X16,
)
from unicorn import unicorn_const

BINARY_PATH = Path(
    "/tmp/nfwc/Payload/Argo.app/Frameworks/NFWebCrypto.framework/NFWebCrypto"
)

# Function offsets (file offset == virtual address; __TEXT base = 0x0)
TFIT_OP_ADDR = 0x25CB0  # TFIT_op_iAES11(ctx, input, output)
TFIT_R9_ADDR = 0x248DC  # TFIT_r9_op_iAES11(ctx, input_state, output_state)
TFIT_CIPHER_ADDR = 0x26C9C  # TFIT_wbaes_ecb_cipher_iAES11(ctx, in, size, out)

# Key schedule offsets in binary (within __TEXT __const, va == file offset)
KS_IPHONE_OFFSET = 0x1AD0E8  # 224 bytes
KS_IPAD_OFFSET = 0x1AD008  # 224 bytes
KS_ATV_OFFSET = 0x1ACF28  # 224 bytes
KS_SIZE = 224

# GOT base in __DATA_CONST
GOT_BASE = 0x238000

# GOT entry offsets for external functions we must intercept
GOT_MEMSET = 0x440  # _memset
GOT_MEMCPY = 0x430  # _memcpy
GOT_STACK_CHK_GUARD = 0x2A8  # ___stack_chk_guard

# Stubs that call through GOT (these addresses jump to external functions)
STUB_MEMSET = 0x1AB990  # bl -> GOT[0x440]
STUB_MEMCPY = 0x1AB978  # bl -> GOT[0x430]

# Unicorn memory layout
STACK_BASE = 0x7FFF0000
STACK_SIZE = 0x100000  # 1 MB
SCRATCH_BASE = 0x60000000  # scratch memory for ctx/input/output/canary
SCRATCH_SIZE = 0x10000

# Sentinel: return address we push to detect function exit
RETURN_SENTINEL = 0xDEAD0000


class TFITEmulator:
    """ARM64 Unicorn emulator for TFIT_op_iAES11."""

    def __init__(self, binary_data: bytes, binary: lief.MachO.Binary) -> None:
        self._binary_data = binary_data
        self._binary = binary
        self._uc: Uc | None = None
        self._memset_addr = STUB_MEMSET
        self._memcpy_addr = STUB_MEMCPY

        # Set up canary value: just a fixed non-zero value
        self._canary_value = 0x1122334455667788

        self._setup_engine()

    # ------------------------------------------------------------------
    # Memory setup
    # ------------------------------------------------------------------

    def _setup_engine(self) -> None:
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self._uc = uc

        # Map all Mach-O segments
        page = 0x1000
        mapped: list[tuple[int, int]] = []

        for seg in self._binary.segments:
            va = seg.virtual_address
            vsz = seg.virtual_size
            if vsz == 0:
                continue

            # Align to page
            va_aligned = (va // page) * page
            end_aligned = ((va + vsz + page - 1) // page) * page
            map_size = end_aligned - va_aligned

            # Avoid overlap
            skip = False
            for prev_va, prev_size in mapped:
                if va_aligned < prev_va + prev_size and va_aligned + map_size > prev_va:
                    skip = True
                    break
            if skip:
                continue

            uc.mem_map(va_aligned, map_size)

            # Write file content
            fsz = seg.file_size
            if fsz > 0:
                foff = seg.file_offset
                data = self._binary_data[foff : foff + fsz]
                uc.mem_write(va, data)

            mapped.append((va_aligned, map_size))

        # Map stack
        uc.mem_map(STACK_BASE, STACK_SIZE)
        # Map scratch area
        uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE)

        # Provide fake __stack_chk_guard:
        # The code does: adrp x9, #0x238000; ldr x9, [x9, #0x2a8]; ldr x9, [x9]
        # GOT[0x2a8] must contain a pointer to the actual canary value.
        canary_val_addr = SCRATCH_BASE + 0x500
        uc.mem_write(canary_val_addr, struct.pack("<Q", self._canary_value))
        uc.mem_write(GOT_BASE + GOT_STACK_CHK_GUARD, struct.pack("<Q", canary_val_addr))

        # Point GOT stubs to our magic return addresses so we can intercept
        # We write a known address into the GOT entries that our hook will detect.
        # Hook strategy: hook on the BR X16 in each stub.
        # Alternative: write NOPs or trampoline to return sentinel.
        # Simplest: write our own "function" at SCRATCH_BASE that does RET immediately,
        # then point GOT entries to it.

        nop_ret_addr = SCRATCH_BASE + 0x200  # tiny function: just "ret"
        ret_insn = struct.pack("<I", 0xD65F03C0)  # ret
        uc.mem_write(nop_ret_addr, ret_insn)

        # Provide fake memset and memcpy in GOT so stubs work
        # For memset(ptr, 0, n): we implement it in the hook
        # For memcpy(dst, src, n): we implement it in the hook
        # Point GOT entries to unique sentinel addresses we hook on
        self._fake_memset_impl = SCRATCH_BASE + 0x210
        self._fake_memcpy_impl = SCRATCH_BASE + 0x220

        # Each fake impl = "ret" for now; we'll do the work in _hook_code
        uc.mem_write(self._fake_memset_impl, ret_insn)
        uc.mem_write(self._fake_memcpy_impl, ret_insn)

        uc.mem_write(GOT_BASE + GOT_MEMSET, struct.pack("<Q", self._fake_memset_impl))
        uc.mem_write(GOT_BASE + GOT_MEMCPY, struct.pack("<Q", self._fake_memcpy_impl))

        # Install code hook for intercepting calls to fake impls
        uc.hook_add(unicorn_const.UC_HOOK_CODE, self._hook_code)

    def _hook_code(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """Intercept calls at sentinel addresses and implement memset/memcpy."""
        if address == self._fake_memset_impl:
            # memset(ptr, value, n)
            ptr = uc.reg_read(UC_ARM64_REG_X0)
            value = uc.reg_read(arm64_const.UC_ARM64_REG_X1) & 0xFF
            n = uc.reg_read(UC_ARM64_REG_X2)
            if n > 0 and n <= 0x10000:
                uc.mem_write(ptr, bytes([value]) * n)
            # RET: jump to LR
            lr = uc.reg_read(UC_ARM64_REG_LR)
            uc.reg_write(UC_ARM64_REG_PC, lr)

        elif address == self._fake_memcpy_impl:
            # memcpy(dst, src, n)
            dst = uc.reg_read(UC_ARM64_REG_X0)
            src = uc.reg_read(UC_ARM64_REG_X1)
            n = uc.reg_read(UC_ARM64_REG_X2)
            if n > 0 and n <= 0x10000:
                data = uc.mem_read(src, n)
                uc.mem_write(dst, bytes(data))
            lr = uc.reg_read(UC_ARM64_REG_LR)
            uc.reg_write(UC_ARM64_REG_PC, lr)

    # ------------------------------------------------------------------
    # Emulate one block
    # ------------------------------------------------------------------

    def encrypt_block(self, key_schedule: bytes, plaintext: bytes) -> bytes:
        """Encrypt a single 16-byte block with TFIT_op_iAES11.

        key_schedule: 224 bytes (device-specific whitebox key schedule)
        plaintext: 16 bytes
        returns: 16 bytes ciphertext
        """
        assert len(key_schedule) == KS_SIZE, f"key_schedule must be {KS_SIZE} bytes"
        assert len(plaintext) == 16, "plaintext must be 16 bytes"

        uc = self._uc

        # Layout scratch memory:
        #   SCRATCH_BASE + 0x000 : ctx = key_schedule (224 bytes = 0xE0)
        #     The real code allocates 0xE4 bytes, aligns ptr, and copies
        #     key_schedule[0..224] directly to aligned_ptr[0].
        #     So ctx[0x10] = round-0 key word 0 (u32 at ks[0x10]).
        #   SCRATCH_BASE + 0x300 : input (16 bytes)
        #   SCRATCH_BASE + 0x400 : output (16 bytes)
        ctx_addr = SCRATCH_BASE + 0x000
        input_addr = SCRATCH_BASE + 0x300
        output_addr = SCRATCH_BASE + 0x400

        # Build ctx: write key_schedule directly at offset 0 (zero-pad to 0xE4)
        ctx_data = bytearray(0xE4)
        ctx_data[0:KS_SIZE] = key_schedule
        uc.mem_write(ctx_addr, bytes(ctx_data))

        # Write input
        uc.mem_write(input_addr, plaintext)

        # Clear output
        uc.mem_write(output_addr, bytes(16))

        # Restore the canary value (it may have been clobbered by previous run)
        canary_val_addr = SCRATCH_BASE + 0x500
        uc.mem_write(canary_val_addr, struct.pack("<Q", self._canary_value))

        # Set up stack pointer (grows down, leave room for frame)
        sp = STACK_BASE + STACK_SIZE - 0x1000
        uc.reg_write(UC_ARM64_REG_SP, sp)

        # Set function arguments: x0=ctx, x1=input, x2=output
        uc.reg_write(UC_ARM64_REG_X0, ctx_addr)
        uc.reg_write(UC_ARM64_REG_X1, input_addr)
        uc.reg_write(UC_ARM64_REG_X2, output_addr)

        # Set LR to sentinel so we detect function return
        uc.reg_write(UC_ARM64_REG_LR, RETURN_SENTINEL)

        # Map sentinel page if not already mapped
        try:
            uc.mem_map((RETURN_SENTINEL // 0x1000) * 0x1000, 0x1000)
            uc.mem_write(RETURN_SENTINEL, struct.pack("<I", 0xD65F03C0))  # ret
        except UcError:
            pass  # already mapped

        # Run emulation
        try:
            uc.emu_start(TFIT_OP_ADDR, RETURN_SENTINEL, timeout=5_000_000, count=0)
        except UcError as e:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            raise RuntimeError(f"Unicorn error at PC=0x{pc:x}: {e}") from e

        # Read output
        result = bytes(uc.mem_read(output_addr, 16))
        return result

    def encrypt_ecb(
        self,
        key_schedule: bytes,
        data: bytes,
    ) -> bytes:
        """Encrypt multiple 16-byte blocks in ECB mode."""
        assert len(data) % 16 == 0, "data must be a multiple of 16 bytes"
        out = bytearray()
        for i in range(0, len(data), 16):
            block = data[i : i + 16]
            out.extend(self.encrypt_block(key_schedule, block))
        return bytes(out)


# ------------------------------------------------------------------
# Key schedule selection
# ------------------------------------------------------------------

MGK_TYPE_IPHONE = 0
MGK_TYPE_IPAD = 1
MGK_TYPE_ATV = 2


def load_key_schedule(mgk_type: int, binary_data: bytes) -> bytes:
    """Extract the TFIT key schedule for the given device type."""
    offsets = {
        MGK_TYPE_IPHONE: KS_IPHONE_OFFSET,
        MGK_TYPE_IPAD: KS_IPAD_OFFSET,
        MGK_TYPE_ATV: KS_ATV_OFFSET,
    }
    off = offsets[mgk_type]
    return binary_data[off : off + KS_SIZE]


# ------------------------------------------------------------------
# High-level: genModelGroupKeys
# ------------------------------------------------------------------


def gen_model_group_keys(
    esn: str,
    mgk_type: int = MGK_TYPE_IPHONE,
) -> tuple[bytes, bytes]:
    """Compute MGK pair from ESN string.

    Implements:
        SHA384(ESN) -> 48 bytes
        mgk_key   = TFIT_ECB(hash[0:16])     -> 16B
        mgk_vec_a = TFIT_ECB(hash[16:32])    -> 16B
        mgk_vec_b = TFIT_ECB(hash[32:48])    -> 16B
        return (mgk_key, mgk_vec_a + mgk_vec_b)

    Returns:
        (mgk_key: 16B, mgk_vector: 32B)
    """
    binary_path = BINARY_PATH
    binary_data = binary_path.read_bytes()
    binary = lief.MachO.parse(str(binary_path)).at(0)

    emu = TFITEmulator(binary_data, binary)
    ks = load_key_schedule(mgk_type, binary_data)

    esn_bytes = esn.encode("ascii")
    sha384 = hashlib.sha384(esn_bytes).digest()  # 48 bytes
    assert len(sha384) == 48

    mgk_key = emu.encrypt_block(ks, sha384[0:16])
    mgk_vec_a = emu.encrypt_block(ks, sha384[16:32])
    mgk_vec_b = emu.encrypt_block(ks, sha384[32:48])

    return mgk_key, mgk_vec_a + mgk_vec_b


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

# Self-consistent test vectors generated by running the emulator itself.
#
# Note on the appboot_tfit_capture.log: that log captures AES_encrypt (OpenSSL)
# calls, NOT TFIT whitebox calls. The TFIT_wbaes_ecb_encrypt_iAES11 symbol was
# not exported and the hook for it was skipped ("not found"). Therefore the log
# pairs like "in=00..01 out=530f..." are standard AES-256 zero-key encryptions
# (matches OpenSSL AES-256 ECB), NOT TFIT whitebox outputs.
#
# These test vectors are derived from a clean Unicorn emulation of TFIT_op_iAES11
# and are self-consistent (running the emulator twice gives the same result).
# External verification against live device output is still pending (requires
# a Frida hook that captures TFIT_wbaes_ecb_encrypt_iAES11 by offset rather
# than symbol name).
KNOWN_ANSWER_TESTS = [
    # (plaintext_hex, ciphertext_hex) — zero key schedule (all 224 bytes = 0)
    ("00000000000000000000000000000001", "f469188c949ce132d5265939cc67e908"),
    ("00000000000000000000000000000002", "5c90c3336189b725cac1073129aefbe1"),
    ("00000000000000000000000000000003", "ddeb1836524af20722d9651c9434037f"),
    ("00000000000000000000000000000000", "7195623eff1992bde8a632719b556918"),
    ("00000001000000000000000000000000", "b3c44c826aa149e043325c2dba404a13"),
    ("00000002000000000000000000000000", "4e20076397bc7e3b914ebd43aadcd85a"),
]

# iPhone key schedule test vectors (self-consistent)
IPHONE_KS_TESTS = [
    ("0f034310a5dcb20a61dbdc60760ac3a9", "68f4884a03e1fd671da06a8808997740"),
    ("0f034310a5dcb20a61dbdc60760ac3aa", "35ed42eab6141a01bf0797bde5b4351e"),
]


def run_tests() -> None:
    """Run known-answer tests with the zero key schedule."""
    binary_path = BINARY_PATH
    binary_data = binary_path.read_bytes()
    binary = lief.MachO.parse(str(binary_path)).at(0)

    emu = TFITEmulator(binary_data, binary)
    zero_ks = bytes(KS_SIZE)  # all-zeros key schedule

    print("Running TFIT KAT (zero key schedule)...")
    passed = 0
    failed = 0
    for i, (pt_hex, ct_hex) in enumerate(KNOWN_ANSWER_TESTS):
        plaintext = bytes.fromhex(pt_hex)
        expected = bytes.fromhex(ct_hex)

        result = emu.encrypt_block(zero_ks, plaintext)

        status = "PASS" if result == expected else "FAIL"
        if result == expected:
            passed += 1
        else:
            failed += 1

        print(
            f"  [{i + 1}] {status}  in={pt_hex}  expected={ct_hex}  got={result.hex()}"
        )

    print(f"\nResults: {passed}/{len(KNOWN_ANSWER_TESTS)} passed, {failed} failed")

    if failed == 0:
        print("\nAll zero-KS KATs passed. Testing iPhone key schedule...")
        ks_iphone = load_key_schedule(MGK_TYPE_IPHONE, binary_data)
        iphone_passed = 0
        iphone_failed = 0
        for pt_hex, ct_hex in IPHONE_KS_TESTS:
            result = emu.encrypt_block(ks_iphone, bytes.fromhex(pt_hex))
            expected = bytes.fromhex(ct_hex)
            status = "PASS" if result == expected else "FAIL"
            if result == expected:
                iphone_passed += 1
            else:
                iphone_failed += 1
            print(
                f"  iPhone KS [{status}]  in={pt_hex}  "
                f"expected={ct_hex}  got={result.hex()}"
            )
        print(f"\nPhone KS: {iphone_passed}/{len(IPHONE_KS_TESTS)} passed")


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="TFIT whitebox AES-128-ECB emulator")
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run known-answer tests to verify emulation",
    )
    parser.add_argument(
        "esn",
        nargs="?",
        help="ESN string to compute MGK for",
    )
    parser.add_argument(
        "--type",
        choices=["iphone", "ipad", "atv"],
        default="iphone",
        help="Device type for key schedule (default: iphone)",
    )

    args = parser.parse_args()

    if not BINARY_PATH.exists():
        print(f"Binary not found: {BINARY_PATH}", file=sys.stderr)
        print("Extract with:", file=sys.stderr)
        print(
            "  mkdir -p /tmp/nfwc && "
            "unzip -o /home/vscode/app/assets/Netflix-15.48.1.ipa "
            '"Payload/Argo.app/Frameworks/NFWebCrypto.framework/*" -d /tmp/nfwc',
            file=sys.stderr,
        )
        sys.exit(1)

    if args.test:
        run_tests()
        return

    if not args.esn:
        parser.print_help()
        sys.exit(1)

    mgk_type_map = {
        "iphone": MGK_TYPE_IPHONE,
        "ipad": MGK_TYPE_IPAD,
        "atv": MGK_TYPE_ATV,
    }
    mgk_type = mgk_type_map[args.type]

    esn = args.esn
    print(f"ESN:      {esn}")
    print(f"Type:     {args.type}")

    sha384 = hashlib.sha384(esn.encode("ascii")).digest()
    print(f"SHA384:   {sha384.hex()}")

    mgk_key, mgk_vec = gen_model_group_keys(esn, mgk_type)
    print(f"MGK key (16B):    {mgk_key.hex()}")
    print(f"MGK vector (32B): {mgk_vec.hex()}")


if __name__ == "__main__":
    main()
