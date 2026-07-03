#!/usr/bin/env python3
"""Unicorn-based emulation of +[VoIPClient initGenAudioH] body (0x100783fc8..0x1007d594c)
to dynamically resolve CFF-obfuscated anti-debug strings and syscall arguments.

Strategy: map a rebase-resolved flat image of Crew, hook every imported stub
call site (bl targets in __TEXT.__stubs) with a Python handler that logs args
and fakes a "clean device" return, and hook raw SVC (syscall) instructions to
fake syscall results consistent with a non-jailbroken / non-debugged host so
that execution proceeds through as much of the anti-debug gauntlet as possible.
"""
import struct
import sys
from unicorn import *
from unicorn.arm64_const import *

from build_image import get_patched_bytes, set_stub_table, get_fakebind_region, get_cell_map

BASE = 0x100000000
FUNC_START = 0x100783fc8
FUNC_END = 0x1007d594c

STACK_BASE = 0x00007FF000000000
STACK_SIZE = 0x800000  # 8 MiB
HEAP_BASE = 0x00007FE000000000
HEAP_SIZE = 0x02000000  # 32 MiB
FAKE_BASE = 0x00007FD000000000  # misc fake string / struct pool
FAKE_SIZE = 0x00100000

SENTINEL_PAGE = 0x00007FC0DEAD0000 & ~0xFFF
SENTINEL_RET = 0x00007FC0DEAD0000

STUBS = {
    0x100c32fe8: "CFCopyHomeDirectoryURL",
    0x100c33084: "CFRelease",
    0x100c330a8: "CFStringGetCString",
    0x100c330b4: "CFURLCopyFileSystemPath",
    0x100c33648: "_Unwind_Resume",
    0x100c3390c: "recursive_mutex_lock",
    0x100c33918: "recursive_mutex_unlock",
    0x100c3396c: "mutex_lock",
    0x100c33978: "mutex_unlock",
    0x100c33ad4: "operator_delete",
    0x100c33af8: "operator_new_array",
    0x100c33b04: "operator_new",
    0x100c33bc4: "__error",
    0x100c33c24: "__snprintf_chk",
    0x100c33c30: "__stack_chk_fail",
    0x100c33c60: "_dyld_get_image_header",
    0x100c33c6c: "_dyld_get_image_name",
    0x100c33c78: "_dyld_get_image_vmaddr_slide",
    0x100c33c84: "_dyld_image_count",
    0x100c33e04: "clock_gettime",
    0x100c33e1c: "closedir",
    0x100c33ff0: "dladdr",
    0x100c33ffc: "dlclose",
    0x100c34008: "dlopen",
    0x100c34014: "dlsym",
    0x100c34110: "getenv",
    0x100c3426c: "malloc",
    0x100c342b4: "memset",
    0x100c343f8: "objc_getClass",
    0x100c34434: "objc_msgSend",
    0x100c346d4: "opendir",
    0x100c347d0: "pthread_create",
    0x100c3480c: "pthread_join",
    0x100c34920: "rand",
    0x100c34944: "readdir",
    0x100c34980: "sel_registerName",
    0x100c34b84: "sranddev",
    0x100c353dc: "uuid_generate",
}

# Internal (non-imported) helper functions that construct C++ objects with
# externally-bound (libc++) vtables. We don't have real libc++ loaded, so
# virtual dispatch through their vtables lands in fake/zeroed memory and
# crashes emulation. These are unrelated to the anti-debug string logic we
# care about, so short-circuit them like stubs (fake "constructed object"
# pointer return).
INTERNAL_SKIP = {
    0x1007d594c: "compound_init_ctor",
}

SYSCALLS = {
    4: "write", 5: "open", 6: "close", 10: "unlink", 20: "getpid", 26: "ptrace",
    33: "access", 37: "kill", 57: "symlink", 202: "__sysctl",
}
FAKE_PID = 1337

class Emu:
    def __init__(self, log_path="/tmp/emu_log.txt"):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.heap_ptr = HEAP_BASE
        self.fake_ptr = FAKE_BASE
        self.log_f = open(log_path, "w")
        self.call_log = []
        self.stop_reason = None
        self.rand_counter = 0x1234

    def log(self, msg):
        print(msg)
        self.log_f.write(msg + "\n")
        self.log_f.flush()

    def read_cstr(self, addr, maxlen=512):
        if addr == 0:
            return None
        try:
            data = self.uc.mem_read(addr, maxlen)
        except UcError:
            return None
        end = bytes(data).find(b"\x00")
        if end == -1:
            end = maxlen
        raw = bytes(data[:end])
        return raw

    def bump_heap(self, size):
        size = (size + 0xF) & ~0xF
        p = self.heap_ptr
        self.heap_ptr += size
        assert self.heap_ptr < HEAP_BASE + HEAP_SIZE, "heap exhausted"
        return p

    def bump_fake(self, data):
        p = self.fake_ptr
        self.uc.mem_write(p, data)
        self.fake_ptr += (len(data) + 0xF) & ~0xF
        assert self.fake_ptr < FAKE_BASE + FAKE_SIZE, "fake pool exhausted"
        return p

    def setup_memory(self):
        set_stub_table(STUBS)
        buf, segs = get_patched_bytes()
        fb_base, fb_size, fb_buf = get_fakebind_region()
        seg_map = {name: (va, sz, off) for (va, sz, off, name) in segs}
        for name in ("__TEXT", "__DATA_CONST", "__DATA", "__ETC"):
            va, sz, off = seg_map[name]
            va_aligned = va & ~0xFFF
            end_aligned = (va + sz + 0xFFF) & ~0xFFF
            map_size = end_aligned - va_aligned
            self.uc.mem_map(va_aligned, map_size, UC_PROT_ALL)
            self.uc.mem_write(va, buf[off:off+sz])
            self.log(f"[map] {name} va=0x{va:x} size=0x{sz:x}")

        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
        self.uc.mem_map(FAKE_BASE, FAKE_SIZE, UC_PROT_ALL)
        self.uc.mem_map(fb_base, fb_size, UC_PROT_ALL)
        self.uc.mem_write(fb_base, fb_buf)
        self.log(f"[map] __FAKEBIND va=0x{fb_base:x} size=0x{fb_size:x}")

        self.uc.mem_map(SENTINEL_PAGE, 0x1000, UC_PROT_ALL)
        self.uc.mem_write(SENTINEL_RET, bytes.fromhex("000020d4"))  # brk #0
        self.log(f"[map] SENTINEL va=0x{SENTINEL_RET:x}")

        # pre-seed some fake strings we may need pointers to
        self.fake_image_path = self.bump_fake(
            b"/private/var/containers/Bundle/Application/AAAA/Crew.app/Crew\x00")
        self.fake_home_path = self.bump_fake(b"/var/mobile\x00")
        self.errno_slot = self.bump_fake(struct.pack("<i", 0))

    def set_ret(self, val):
        self.uc.reg_write(UC_ARM64_REG_X0, val & 0xFFFFFFFFFFFFFFFF)

    def do_ret(self):
        lr = self.uc.reg_read(UC_ARM64_REG_LR)
        self.uc.reg_write(UC_ARM64_REG_PC, lr)

    def get_x(self, n):
        return self.uc.reg_read(getattr(unicorn.arm64_const, f"UC_ARM64_REG_X{n}"))

    def hook_generic_fakebind(self, uc, address, size, user_data):
        """Catch-all for direct calls through *unresolved* lazy-bind GOT
        slots (plain libc/C++ symbols we didn't explicitly model in STUBS).
        Logs the real symbol name (from build_image's bind table) and
        returns a safe default (0) so execution can keep going instead of
        crashing into zeroed fakebind memory."""
        name = self._cell_map.get(address, f"?cell@0x{address:x}")
        x = [uc.reg_read(getattr(sys.modules['unicorn.arm64_const'], f"UC_ARM64_REG_X{i}")) for i in range(4)]
        lr = uc.reg_read(UC_ARM64_REG_LR)
        self.log(f"CALL <unmodeled-external> {name} @0x{address:x} lr=0x{lr:x} x0=0x{x[0]:x} x1=0x{x[1]:x} x2=0x{x[2]:x} x3=0x{x[3]:x} -> ret=0x0 (generic fallback)")
        self.call_log.append((f"unmodeled:{name}", address, x, 0))
        self.set_ret(0)
        self.do_ret()

    def hook_stub(self, uc, address, size, user_data):
        name = STUBS.get(address) or INTERNAL_SKIP.get(address)
        if name is None:
            return
        x = [uc.reg_read(getattr(sys.modules['unicorn.arm64_const'], f"UC_ARM64_REG_X{i}")) for i in range(8)]
        handler = getattr(self, f"stub_{name}", None)
        entry = f"CALL {name} @0x{address:x} lr=0x{uc.reg_read(UC_ARM64_REG_LR):x} x0=0x{x[0]:x} x1=0x{x[1]:x} x2=0x{x[2]:x} x3=0x{x[3]:x}"
        try:
            if handler:
                ret = handler(uc, x)
            else:
                ret = 0
        except Exception as e:
            self.log(f"[stub-error] {name}: {e}")
            ret = 0
        self.call_log.append((name, address, x, ret))
        self.log(entry + f" -> ret=0x{ret if ret is not None else 0:x}")
        if ret is not None:
            self.set_ret(ret)
        self.do_ret()

    # --- stub implementations ---
    def stub_getenv(self, uc, x):
        s = self.read_cstr(x[0])
        self.log(f"    getenv(\"{s}\")")
        return 0  # not set -> NULL

    def stub_dlopen(self, uc, x):
        s = self.read_cstr(x[0])
        self.log(f"    dlopen(\"{s}\", mode=0x{x[1]:x})")
        return 0  # NULL handle

    def stub_dlsym(self, uc, x):
        s = self.read_cstr(x[1])
        self.log(f"    dlsym(handle=0x{x[0]:x}, \"{s}\")")
        return 0

    def stub_dlclose(self, uc, x):
        return 0

    def stub_dladdr(self, uc, x):
        # Dl_info { const char*dli_fname; void*dli_fbase; const char*dli_sname; void*dli_saddr; }
        info_ptr = x[1]
        try:
            uc.mem_write(info_ptr, struct.pack("<QQQQ", self.fake_image_path, BASE, 0, 0))
        except UcError:
            pass
        return 1

    def stub_opendir(self, uc, x):
        s = self.read_cstr(x[0])
        self.log(f"    opendir(\"{s}\")")
        return 0xDEAD0001  # non-null sentinel DIR*

    def stub_readdir(self, uc, x):
        return 0  # NULL -> end of directory immediately

    def stub_closedir(self, uc, x):
        return 0

    def stub__dyld_image_count(self, uc, x):
        return 1

    def stub__dyld_get_image_name(self, uc, x):
        return self.fake_image_path

    def stub__dyld_get_image_header(self, uc, x):
        return BASE

    def stub__dyld_get_image_vmaddr_slide(self, uc, x):
        return 0

    def stub_malloc(self, uc, x):
        size = x[0]
        p = self.bump_heap(max(size, 8))
        return p

    def stub_memset(self, uc, x):
        ptr, val, size = x[0], x[1] & 0xFF, x[2]
        if size and ptr:
            try:
                uc.mem_write(ptr, bytes([val]) * size)
            except UcError:
                pass
        return ptr

    def stub_objc_getClass(self, uc, x):
        s = self.read_cstr(x[0])
        self.log(f"    objc_getClass(\"{s}\")")
        return 0

    def stub_objc_msgSend(self, uc, x):
        return 0

    def stub_sel_registerName(self, uc, x):
        s = self.read_cstr(x[0])
        self.log(f"    sel_registerName(\"{s}\")")
        return x[0]

    def stub_pthread_create(self, uc, x):
        self.log(f"    pthread_create(thread=0x{x[0]:x}, attr=0x{x[1]:x}, start_routine=0x{x[2]:x}, arg=0x{x[3]:x})")
        return 0

    def stub_pthread_join(self, uc, x):
        return 0

    def stub_clock_gettime(self, uc, x):
        ts_ptr = x[1]
        try:
            uc.mem_write(ts_ptr, struct.pack("<qq", 1000, 0))
        except UcError:
            pass
        return 0

    def stub_rand(self, uc, x):
        self.rand_counter = (self.rand_counter * 1103515245 + 12345) & 0x7FFFFFFF
        return self.rand_counter

    def stub_sranddev(self, uc, x):
        return None

    def stub_uuid_generate(self, uc, x):
        ptr = x[0]
        try:
            uc.mem_write(ptr, bytes(range(16)))
        except UcError:
            pass
        return None

    def stub___error(self, uc, x):
        return self.errno_slot

    def stub___snprintf_chk(self, uc, x):
        return 0

    def stub___stack_chk_fail(self, uc, x):
        self.log("    !!! __stack_chk_fail triggered !!!")
        self.stop_reason = "stack_chk_fail"
        uc.emu_stop()
        return None

    def stub_mutex_lock(self, uc, x):
        return 0

    def stub_mutex_unlock(self, uc, x):
        return 0

    def stub_recursive_mutex_lock(self, uc, x):
        return 0

    def stub_recursive_mutex_unlock(self, uc, x):
        return 0

    def stub_operator_new(self, uc, x):
        return self.bump_heap(max(x[0], 8))

    def stub_operator_new_array(self, uc, x):
        return self.bump_heap(max(x[0], 8))

    def stub_operator_delete(self, uc, x):
        return None

    def stub_CFCopyHomeDirectoryURL(self, uc, x):
        return 0xCFCF0001

    def stub_CFRelease(self, uc, x):
        return None

    def stub_CFStringGetCString(self, uc, x):
        buf, bufsize = x[1], x[2]
        s = self.fake_home_path_str = b"/var/mobile\x00"
        try:
            uc.mem_write(buf, s[:bufsize])
        except UcError:
            pass
        return 1

    def stub_CFURLCopyFileSystemPath(self, uc, x):
        return 0xCFCF0002

    def stub_compound_init_ctor(self, uc, x):
        self.log(f"    [skipped internal C++ ctor 0x1007d594c to avoid external-vtable dispatch crash]")
        return self.bump_heap(0x40)

    def stub__Unwind_Resume(self, uc, x):
        self.log("    !!! _Unwind_Resume hit (unexpected exception path) !!!")
        self.stop_reason = "unwind_resume"
        uc.emu_stop()
        return None

    # --- SVC / raw syscall handling ---
    def hook_intr(self, uc, intno, user_data):
        try:
            self._hook_intr_impl(uc, intno, user_data)
        except Exception as e:
            import traceback
            self.log(f"[hook_intr EXCEPTION] intno={intno} pc=0x{uc.reg_read(UC_ARM64_REG_PC):x} {e}")
            traceback.print_exc(file=self.log_f)
            self.log_f.flush()
            self.stop_reason = f"hook_intr_exception: {e}"
            uc.emu_stop()

    def _hook_intr_impl(self, uc, intno, user_data):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if pc == SENTINEL_RET:
            self.log("[stop] reached SENTINEL return address -> normal function return")
            self.stop_reason = "normal_return"
            uc.emu_stop()
            return
        fb_base, fb_size, _ = get_fakebind_region()
        if fb_base <= pc < fb_base + fb_size:
            self.log(f"[stop] PC landed in __FAKEBIND (external vtable dispatch through unresolved bind) pc=0x{pc:x}")
            self.stop_reason = f"landed_in_fakebind pc=0x{pc:x}"
            uc.emu_stop()
            return
        # PC at time of SVC intr callback in unicorn2 == address of the svc insn itself
        x16 = uc.reg_read(UC_ARM64_REG_X16)
        name = SYSCALLS.get(x16, f"syscall_{x16}")
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        x4 = uc.reg_read(UC_ARM64_REG_X4)
        x5 = uc.reg_read(UC_ARM64_REG_X5)
        ret = 0
        carry = 0  # success by default
        if name == "getpid":
            ret = FAKE_PID
        elif name == "ptrace":
            self.log(f"[SVC@0x{pc:x}] ptrace(request={x0}, pid=0x{x1:x}, addr=0x{x2:x}, data=0x{x3:x})")
            ret = 0
        elif name == "kill":
            self.log(f"[SVC@0x{pc:x}] kill(pid=0x{x0:x}, sig={x1})")
            if x1 == 0:
                # sig==0 is a liveness probe (no signal sent); treat as success, keep going
                ret = 0
            else:
                self.stop_reason = f"kill(pid=0x{x0:x}, sig={x1})"
                self.log(f"    !!! self-kill triggered: pid=0x{x0:x} sig={x1} !!!")
                uc.emu_stop()
                return
        elif name == "open":
            s = self.read_cstr(x0)
            self.log(f"[SVC@0x{pc:x}] open(\"{s}\", flags=0x{x1:x}, mode=0x{x2:x})")
            ret = 2  # ENOENT
            carry = 1
        elif name == "access":
            s = self.read_cstr(x0)
            self.log(f"[SVC@0x{pc:x}] access(\"{s}\", mode=0x{x1:x})")
            ret = 2  # ENOENT
            carry = 1
        elif name == "unlink":
            s = self.read_cstr(x0)
            self.log(f"[SVC@0x{pc:x}] unlink(\"{s}\")")
            ret = 2
            carry = 1
        elif name == "symlink":
            s0 = self.read_cstr(x0)
            s1 = self.read_cstr(x1)
            self.log(f"[SVC@0x{pc:x}] symlink(\"{s0}\", \"{s1}\")")
            ret = 1  # EPERM
            carry = 1
        elif name == "close":
            ret = 0
        elif name == "write":
            s = None
            try:
                s = bytes(uc.mem_read(x1, min(x2, 256)))
            except UcError:
                pass
            self.log(f"[SVC@0x{pc:x}] write(fd={x0}, buf={s!r}, len={x2})")
            ret = x2
        elif name == "__sysctl":
            mib_words = []
            try:
                miblen = x1
                raw = uc.mem_read(x0, miblen * 4)
                mib_words = list(struct.unpack(f"<{miblen}i", raw))
            except UcError:
                pass
            self.log(f"[SVC@0x{pc:x}] __sysctl(mib={mib_words}, miblen={x1}, oldp=0x{x2:x}, oldlenp=0x{x3:x}, newp=0x{x4:x}, newlen={x5})")
            if x3 != 0:
                try:
                    if x2 == 0:
                        # size query: pretend the structure is 0x288 bytes (kinfo_proc-ish)
                        uc.mem_write(x3, struct.pack("<Q", 0x288))
                    else:
                        oldlen = struct.unpack("<Q", uc.mem_read(x3, 8))[0]
                        if oldlen and oldlen < 0x10000:
                            uc.mem_write(x2, b"\x00" * oldlen)
                except UcError:
                    pass
            ret = 0
        else:
            self.log(f"[SVC@0x{pc:x}] unhandled syscall {name} ({x16}) x0=0x{x0:x} x1=0x{x1:x} x2=0x{x2:x}")
            ret = 0

        uc.reg_write(UC_ARM64_REG_X0, ret & 0xFFFFFFFFFFFFFFFF)
        nzcv = uc.reg_read(UC_ARM64_REG_NZCV)
        if carry:
            nzcv |= (1 << 29)
        else:
            nzcv &= ~(1 << 29)
        uc.reg_write(UC_ARM64_REG_NZCV, nzcv)
        # advance past the svc instruction (4 bytes)
        uc.reg_write(UC_ARM64_REG_PC, pc + 4)

    def hook_progress(self, uc, address, size, user_data):
        self.instr_count += 1
        if self.instr_count % 5_000_000 == 0:
            self.log(f"[progress] {self.instr_count} instructions executed, pc=0x{address:x}")

    def run(self, max_instructions=0, timeout_us=600_000_000):
        self.setup_memory()
        self.instr_count = 0

        for addr in list(STUBS) + list(INTERNAL_SKIP):
            self.uc.hook_add(UC_HOOK_CODE, self.hook_stub, begin=addr, end=addr)

        self._cell_map = get_cell_map()
        fb_base, fb_size, _ = get_fakebind_region()
        self.log(f"[setup] {len(self._cell_map)} unmodeled external bind symbols; installing ONE ranged fallback hook over __FAKEBIND [0x{fb_base:x}, 0x{fb_base+fb_size:x})")
        self.uc.hook_add(UC_HOOK_CODE, self.hook_generic_fakebind, begin=fb_base, end=fb_base + fb_size - 1)

        self.uc.hook_add(UC_HOOK_CODE, self.hook_progress, begin=FUNC_START, end=FUNC_END)
        self.uc.hook_add(UC_HOOK_INTR, self.hook_intr)

        sp0 = STACK_BASE + STACK_SIZE - 0x1000
        self.uc.reg_write(UC_ARM64_REG_SP, sp0)
        self.uc.reg_write(UC_ARM64_REG_X0, 0x00007FC000000001)  # fake self
        self.uc.reg_write(UC_ARM64_REG_X1, 0x00007FC000000002)  # fake _cmd
        self.uc.reg_write(UC_ARM64_REG_LR, SENTINEL_RET)  # sentinel return addr

        try:
            # until = unreachable address; real stop comes from SENTINEL_RET / kill / stack_chk_fail / timeout
            self.uc.emu_start(FUNC_START, 0xFFFFFFFFFFFFFFFF, timeout=timeout_us, count=max_instructions)
        except UcError as e:
            self.stop_reason = f"UcError: {e}"
            self.log(f"[stop] {self.stop_reason} pc=0x{self.uc.reg_read(UC_ARM64_REG_PC):x}")
        else:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            if pc == SENTINEL_RET and self.stop_reason is None:
                self.stop_reason = "normal_return"
            self.log(f"[stop] pc=0x{pc:x} reason={self.stop_reason} instr_count={self.instr_count}")


if __name__ == "__main__":
    e = Emu()
    e.run()
    print("=== call summary ===")
    for name, addr, x, ret in e.call_log:
        print(f"{name}@0x{addr:x} x0=0x{x[0]:x} ret=0x{ret if ret else 0:x}")
