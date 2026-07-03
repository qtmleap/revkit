#!/usr/bin/env python3
"""Scan _gen_audio_h (Crew VA 0x10090f20c .. 0x100a208fc) for data references.

Follows the same ADRP+ADD/LDR tracking method used for initGenAudioH in
docs/spec/znca_ios_init_gen_audio_h_static.md ("categorize_refs.py"), plus
an explicit pass for LDRB (register)-indexed table-lookup instructions
(the classic whitebox S-box access pattern: `ldrb wD, [Xbase, Windex, uxtw]`).

Buckets every resolved data target address by which whitebox-layout section
it falls into (per docs/spec/znca_ios_whitebox_layout.md), to cross-check
that _gen_audio_h really dereferences the "pure" (no-chained-fixup) high
entropy region and not the CFF-plumbing / pointer-fixup pages.

Usage:
    python3 scan_gen_audio_h_refs.py
"""

import struct
from collections import Counter, defaultdict

import capstone

from common import ANALYSIS_DIR, CREW_PATH, VA_HI, VA_LO

FUNC_LO = 0x10090F20C
FUNC_HI = 0x100A208FC  # end of _gen_audio_h .. _gen_audio_h2 tail-merged region
TEXT_VA_BASE = 0x100000000


def read_func_bytes() -> bytes:
    data = CREW_PATH.read_bytes()
    file_off = FUNC_LO - TEXT_VA_BASE
    size = FUNC_HI - FUNC_LO
    return data[file_off : file_off + size]


def classify(addr: int) -> str:
    if VA_LO <= addr < VA_HI:
        return "whitebox_blob"
    if 0x100E54000 <= addr < 0x100EDC000:
        return "__DATA_CONST"
    if 0x100EDC000 <= addr < 0x1013E8000:
        return "__DATA (outside whitebox blob)"
    if 0x100000000 <= addr < 0x100E54000:
        return "__TEXT"
    if 0x1013E8000 <= addr < 0x101458000:
        return "__ETC"
    return "other/unknown"


def main() -> None:
    code = read_func_bytes()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    adrp_targets: dict[int, int] = {}  # reg -> page target (accumulated per adrp then add)
    data_refs: Counter[int] = Counter()
    ldrb_reg_insns: list[tuple[int, str]] = []
    ldr_indexed_insns: list[tuple[int, str]] = []

    pending_adrp: dict[int, int] = {}  # reg number -> page base

    insn_count = 0
    for insn in md.disasm(code, FUNC_LO):
        insn_count += 1
        mnem = insn.mnemonic
        ops = insn.op_str

        if mnem == "adrp":
            # adrp xN, #imm  -> operands: reg, imm(page-aligned target)
            try:
                reg = insn.reg_name(insn.operands[0].reg)
                imm = insn.operands[1].imm
                pending_adrp[reg] = imm
            except Exception:
                pass
            continue

        if mnem == "add" and len(insn.operands) == 3:
            try:
                dst = insn.reg_name(insn.operands[0].reg)
                src = insn.reg_name(insn.operands[1].reg)
                if src in pending_adrp and insn.operands[2].type == capstone.arm64.ARM64_OP_IMM:
                    target = pending_adrp[src] + insn.operands[2].imm
                    data_refs[target] += 1
                    pending_adrp[dst] = target  # propagate in case chained
            except Exception:
                pass
            continue

        if mnem.startswith("ldrb") and "[" in ops:
            # true register-indexed byte load: ldrb wD, [Xn, Wm, uxtw] or [Xn, Xm]
            # (as opposed to immediate-offset struct field access [Xn, #imm])
            inner = ops.split("[", 1)[1]
            if "," in inner and "#" not in inner:
                ldrb_reg_insns.append((insn.address, f"{mnem} {ops}"))
            continue

        if mnem in ("ldr", "ldrh", "ldrsb", "ldrsh") and "[" in ops:
            inner = ops.split("[", 1)[1]
            if "," in inner and "#" not in inner:
                ldr_indexed_insns.append((insn.address, f"{mnem} {ops}"))

    print(f"disassembled {insn_count} instructions over {len(code)} bytes")
    print(f"distinct ADRP+ADD data targets: {len(data_refs)}, total refs: {sum(data_refs.values())}")

    by_section: Counter[str] = Counter()
    for addr, cnt in data_refs.items():
        by_section[classify(addr)] += cnt

    print("\nADRP+ADD targets by section:")
    for sec, cnt in by_section.most_common():
        print(f"  {sec:35s} {cnt:6d}")

    print(f"\nregister-indexed LDRB instructions (S-box-style byte table lookup): {len(ldrb_reg_insns)}")
    for addr, txt in ldrb_reg_insns[:30]:
        print(f"  0x{addr:x}  {txt}")

    print(f"\nother register-indexed load instructions: {len(ldr_indexed_insns)}")
    for addr, txt in ldr_indexed_insns[:30]:
        print(f"  0x{addr:x}  {txt}")

    # top data targets within whitebox blob specifically
    wb_targets = {a: c for a, c in data_refs.items() if VA_LO <= a < VA_HI}
    print(f"\ndistinct whitebox-blob targets referenced: {len(wb_targets)}")
    top = sorted(wb_targets.items(), key=lambda kv: -kv[1])[:30]
    for addr, cnt in top:
        off = addr - VA_LO
        print(f"  0x{addr:x}  (blob+0x{off:06x})  refs={cnt}")

    import pickle

    with (ANALYSIS_DIR / "gen_audio_h_data_refs.pkl").open("wb") as f:
        pickle.dump(
            {
                "data_refs": dict(data_refs),
                "ldrb_reg_insns": ldrb_reg_insns,
                "ldr_indexed_insns": ldr_indexed_insns,
            },
            f,
        )
    print(f"\nsaved raw results to {ANALYSIS_DIR / 'gen_audio_h_data_refs.pkl'}")


if __name__ == "__main__":
    main()
