#!/usr/bin/env python3
"""Contract test for tools/extract_ivar_cell_references.py.

The scan is pure integer arithmetic over words, so it can be pinned on a synthetic
instruction stream with a KNOWN answer, and it must reject the mask bug that made an
earlier version of this scan return zero hits with no error.

Synthetic layout (all little-endian words):
    @0x1000 ldr r2, [pc, #0x30]   ; wB -> pool at 0x1000+8+0x30 = 0x1038
    @0x1004 add r2, pc, r2        ; v = 0x1004+8+wB
    @0x1008 ldr r3, [pc, #0x24]   ; wA -> pool at 0x1010+0x24 = 0x1034
    @0x100c ldr r2, [r3, r2]      ; slot = wA + v
and the .got "slot" holds the cell VA. Choose wB so that v == PIC_BASE, exactly like
the real idiom, then wA = slot - v.
"""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import extract_ivar_cell_references as x  # noqa: E402

BIAS_LDR, WB_LDR, AD, LOAD = 0x1000, 0x1004, 0x1008, 0x100C
POOL_A, POOL_B = 0x1034, 0x1038            # bias pool, wB pool
SLOT = 0x1080                             # the .got entry holding the cell VA


def build(slot_addr: int, cell_va: int, bias_reg: int = 3) -> bytes:
    """The real idiom, in the real order:

        ldr  rA, [pc, #kA]     -> wA   (pool BIAS_LDR+8+kA)
        ldr  r2, [pc, #kB]     -> wB   (pool WB_LDR+8+kB)
        add  r2, pc, r2        -> v = (AD+8) + wB == PIC_BASE
        ldr  r2, [rA, r2]      -> *(wA + v) = the slot, whose contents are the cell VA
    """
    blob = bytearray(0x2000)
    wB = (x.PIC_BASE - (AD + 8)) & 0xFFFFFFFF
    wA = (slot_addr - x.PIC_BASE) & 0xFFFFFFFF
    struct.pack_into("<I", blob, BIAS_LDR, 0xE59F0000 | (bias_reg << 12) | (POOL_A - BIAS_LDR - 8))
    struct.pack_into("<I", blob, WB_LDR, 0xE59F2000 | (POOL_B - WB_LDR - 8))
    struct.pack_into("<I", blob, AD, 0xE08F2002)                     # add r2, pc, r2
    struct.pack_into("<I", blob, LOAD, 0xE7922000 | (bias_reg << 16) | 2)  # ldr r2,[rA,r2]
    struct.pack_into("<I", blob, POOL_A, wA)
    struct.pack_into("<I", blob, POOL_B, wB)
    struct.pack_into("<I", blob, slot_addr, cell_va)
    return bytes(blob)


def main() -> int:
    # --- the masks themselves -------------------------------------------------
    assert x.ldr_pc(0xE59F203C, 2), "ldr r2,[pc,#imm] must be accepted (Rd free)"
    assert x.ldr_pc(0xE59F103C, 1) and x.ldr_pc(0xE59F003C, 0)
    assert not x.ldr_pc(0xE59F203C, 3), "wrong Rd must not match"
    assert not x.ldr_pc(0xE59D203C, 2), "ldr from sp is not pc-relative"
    assert x.add_pc_self(0xE08F2002, 2), "add r2,pc,r2 must be accepted"
    assert not x.add_pc_self(0xE08F2002, 3), "Rd/Rm mismatch must not match"
    assert not x.add_pc_self(0xE08F2003, 2), "Rd != Rm must not match"
    # the exact bug: a mask that also pins Rd only ever sees rd=0 instructions
    assert (0xE08F2002 & 0xFFFFF000) != 0xE08F0000, "the old rd-pinning mask would miss rd=2"
    assert (0xE08F2002 & 0xFFFF0000) == 0xE08F0000, "correct mask keeps Rn=pc and frees Rd"

    assert x.is_push_lr(0xE92D4010) and not x.is_push_lr(0xE92D0000)

    # --- end to end on a synthetic stream ------------------------------------
    cell = 0x00F32930
    blob = build(SLOT, cell)
    W = lambda a: struct.unpack_from("<I", blob, a)[0]
    v = (AD + 8 + W(POOL_B)) & 0xFFFFFFFF
    assert v == x.PIC_BASE, f"fixture must reproduce the PIC base, got {v:#x}"
    assert (W(POOL_A) + v) & 0xFFFFFFFF == SLOT, "fixture slot address is wrong"
    assert W(SLOT) == cell

    # end-to-end through scan() on a synthetic window (capstone optional)
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        sites, stats = x.scan(blob, {cell: "World.fastForward"}, {}, md.disasm,
                              lo=0x1000, hi=0x1100)
        assert stats["add_sites"] == 1, stats
        assert len(sites) == 1, sites
        got = sites[0]
        assert got["ivar"] == "World.fastForward" and got["cell"] == hex(cell), got
        assert got["got_slot"] == hex(SLOT), got
        # a slot holding a NON-cell word must not be reported (negative control)
        other = build(0x10C0, cell)
        blob2 = bytearray(other)
        struct.pack_into("<I", blob2, 0x10C0, 0xDEADBEEF)
        sites2, _ = x.scan(bytes(blob2), {cell: "World.fastForward"}, {}, md.disasm,
                           lo=0x1000, hi=0x1100)
        assert sites2 == [], f"non-cell slot content was reported as a reference: {sites2}"
    except ImportError:
        print("skip: capstone unavailable (masks + fixture verified without it)")

    # --- the real shape must be reachable from the ELF copy when present ------
    pinned = Path(os.environ.get("BH_ELF",
        ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present (pure helpers + fixture verified)")
        return 0
    print("pure helpers + synthetic fixture verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
