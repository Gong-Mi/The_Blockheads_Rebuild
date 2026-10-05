#!/usr/bin/env python3
"""Execute the ORIGINAL's -[World worldTime] under Unicorn and compare with the value we planted.

This turns a live-memory conclusion into an execution result. The getter (IMP 0x5d99a4) is pure
PIC + cell arithmetic:

    ldr r1, [pc, #k]        ; a pool word
    ldr r2, [pc, #k2]       ; companion word
    add r2, pc, r2          ; PIC base
    ldr r1, [r1, r2]        ; *.got slot - its CONTENTS are the cell VA
    ldr r1, [r1]            ; the runtime ivar offset (648 for World.worldTime)
    add r1, r0, r1          ; self + offset
    ... copy 8 bytes out ...
    vldr d0, [fp, #-8]      ; return the double (soft-float ABI: low word in r0, high in r1)

Harness decisions, both stated because they are abstractions rather than fidelity:
  * the image is mapped at vaddr + BIAS, and the two absolute words the chain depends on (the .got
    slot and the cell) are relocated by BIAS, because the file stores absolute VAs;
  * `bl 0x1c2888` is intercepted and served by a host memcpy: that address is a LAZY trampoline chain
    (0x1c2888 -> slot -> 0x1c27c0 -> a further lazy pointer), and the real loader fills it at run
    time. Intercepting it is the same abstraction the repo's own ARM bridges use.

Controls:
  * positive: two different doubles must come back bit-exact;
  * negative (the important one): rewriting the CELL to a different offset must change the returned
    value to whatever sits at self + that offset - which is what proves the emulation really follows
    the cell instead of a hard-coded 648.

Usage:
  python3 tools/emulate_worldtime_getter.py <libApplication.so> --methods <t.tsv> [--json OUT]
Exit 0 only if the positive and negative controls both hold.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM,
                     UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_SP)

BIAS = 0x10000000
OBJ = BIAS + 0x20000000
STACK_TOP = BIAS + 0x21000000
SENTINEL = BIAS + 0x22000000
COPY_STUB = 0x001C2888
GETTER = 0x005D99A4
GOT_SLOT = 0x105C754          # .got entry for World.worldTime (contents = the cell VA)
CELL = 0xF328F4               # __objc_ivar cell for World.worldTime (contents = 648)


def load_image(mu: Uc, elf_path: Path) -> dict:
    with elf_path.open("rb") as fh:
        e = ELFFile(fh)
        loaded = {}
        for seg in e.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            va, sz, off = seg["p_vaddr"], seg["p_memsz"], seg["p_offset"]
            page = va & ~0xFFF
            end = (va + sz + 0xFFF) & ~0xFFF
            try:
                mu.mem_map(BIAS + page, end - page, UC_PROT_ALL)
            except UcError:
                pass
            data = bytearray(seg.data())
            if sz > len(data):
                data.extend(b"\0" * (sz - len(data)))
            mu.mem_write(BIAS + va, bytes(data))
            loaded[va] = sz
    return loaded


def run_getter(mu: Uc, planted: float, cell_value: int, planted_at: int = 648,
               decoy: float | None = None) -> float:
    # relocate the two absolute words the chain walks through
    mu.mem_write(BIAS + GOT_SLOT, struct.pack("<I", BIAS + CELL))
    mu.mem_write(BIAS + CELL, struct.pack("<i", cell_value))
    mu.mem_write(OBJ, b"\0" * 0x1000)
    mu.mem_write(OBJ + planted_at, struct.pack("<d", planted))
    if decoy is not None:
        # a different value at the OTHER candidate offset: whichever comes back names the offset
        mu.mem_write(OBJ + (648 if planted_at != 648 else 640), struct.pack("<d", decoy))
    mu.mem_write(BIAS + STACK_TOP - 0x4000, b"\0" * 0x4000)
    state = {"stub": 0}

    def hook(mu_, addr, size, _):
        if addr == BIAS + COPY_STUB:
            dst = mu_.reg_read(UC_ARM_REG_R0)
            src = mu_.reg_read(UC_ARM_REG_R1)
            n = mu_.reg_read(UC_ARM_REG_R2)
            mu_.mem_write(dst, bytes(mu_.mem_read(src, n)))
            state["stub"] += 1
            state["dst"] = dst
            # The original's epilogue is `vldr d0,[fp,#-8]` - a VFP instruction Unicorn's default
            # ARM model rejects (UC_ERR_INSN_INVALID). So the harness reads the eight bytes the
            # original's own code copied out, and states that as an abstraction instead of
            # pretending it emulated the VFP return path.
            if n == 8:
                state["ret"] = struct.unpack("<d", bytes(mu_.mem_read(dst, 8)))[0]
                mu_.emu_stop()
            else:
                mu_.reg_write(UC_ARM_REG_PC, mu_.reg_read(UC_ARM_REG_LR))
            return
        if addr == SENTINEL:
            mu_.emu_stop()

    h = mu.hook_add(UC_HOOK_CODE, hook)
    mu.reg_write(UC_ARM_REG_R0, OBJ)                 # self
    mu.reg_write(UC_ARM_REG_SP, BIAS + STACK_TOP)
    mu.reg_write(UC_ARM_REG_LR, SENTINEL)
    mu.emu_start(BIAS + GETTER, BIAS + SENTINEL, timeout=5_000_000)
    mu.hook_del(h)
    if "ret" in state:
        return state["ret"], state["stub"]
    lo = mu.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
    hi = mu.reg_read(UC_ARM_REG_R1) & 0xFFFFFFFF
    return struct.unpack("<d", struct.pack("<II", lo, hi))[0], state["stub"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--methods", type=Path, default=None)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()
    elf = Path(args.libapplication)

    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    load_image(mu, elf)
    # the fabricated regions: the World object, a stack, and a page for the return sentinel
    mu.mem_map(OBJ & ~0xFFF, 0x4000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(BIAS + STACK_TOP - 0x8000, 0x8000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(SENTINEL & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    mu.mem_write(SENTINEL, struct.pack("<I", 0xE1A0F00E))     # bx lr, if the hook ever misses

    cases = [900.0, 123.5]
    results = []
    ok = True
    for v in cases:
        got, stubs = run_getter(mu, v, 648, planted_at=648)
        good = struct.pack("<d", got) == struct.pack("<d", v)
        ok &= good
        results.append({"planted": v, "returned": got, "bit_exact": good, "copy_stub_calls": stubs})

    # Negative control, done so that it can actually fail: rewrite the CELL to 640, plan 42.25 at
    # self+640 and a decoy 999.0 at self+648. If the emulation is really walking the cell it returns
    # 42.25; a hard-coded 648 would return the decoy. (The first version of this control wiped its
    # own marker - run_getter clears the object - and could not have distinguished anything.)
    alt, planted_alt, decoy = 640, 42.25, 999.0
    got_alt, _ = run_getter(mu, planted_alt, alt, planted_at=alt, decoy=decoy)
    neg_ok = struct.pack("<d", got_alt) == struct.pack("<d", planted_alt)
    ok &= neg_ok

    # and back to 648: the value at 640 must NOT come back
    got_sane, _ = run_getter(mu, 7.5, 648, planted_at=648, decoy=1234.0)
    neg2_ok = struct.pack("<d", got_sane) == struct.pack("<d", 7.5)
    ok &= neg2_ok

    rep = {"schema": 1, "what": "execute the original's -[World worldTime] under Unicorn",
           "getter_imp": hex(GETTER), "cell": hex(CELL), "got_slot": hex(GOT_SLOT),
           "abstraction": "bl 0x1c2888 intercepted and served by a host memcpy (a lazy trampoline "
                          "chain the real loader fills at run time); the value is read from the buffer "
                          "the original s own code copied into, because its VFP epilogue "
                          "(vldr d0,[fp,#-8]) is not emulable in Unicorn s default ARM model",
           "positive": results,
           "negative_control": {"cell_rewritten_to": alt, "returned": got_alt,
                                "equals_value_at_self_plus_cell": neg_ok},
           "second_negative": {"cell_back_to": 648, "returned": got_sane, "bit_exact": neg2_ok},
           "passed": bool(ok)}
    if args.json:
        args.json.write_text(json.dumps(rep, indent=1) + "\n")
    print(json.dumps(rep, indent=1))
    print(f"\nworldTime getter emulation: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
