#!/usr/bin/env python3
"""The THIRD abstraction: the float (and word-sized) getters.

The classifier grouped the clock/weather getters as "one abstraction covers eight". Running them
showed that was a cost estimate, not a fact: this family has three abstraction classes, and they are
not the same abstraction.

  * `char`   (fastForward, doubleTimeUnlocked): `ldrsb r0,[r0,r1]` - value returns in r0.
    **No abstraction at all.**                              -> emulate_worldtime_getter.py
  * `double` (worldTime): the field is read through the 8-byte copy helper, then moved by VFP.
    Abstraction: serve the copy, read the buffer.            -> emulate_worldtime_getter.py
  * float/word (this tool): NO copy and NO direct vldr. The original does
        ldr r0, [r0, r1]     <- reads the 32-bit word at self+offset
        dmb ish
        str r0, [sp, #8]
        vldr s0, [sp, #8]    <- reinterpret the STACK word as float (this line is why the first
        vmov r0, s0             attempt died: hooking the vldr reads the stack, not the field)
    Abstraction: intercept the word load that addresses the field.

The interception is self-validating. Pass 1 hooks every load in the getter and requires the FIRST
one whose effective address equals `self + offset`, where the offset was derived from the getter's
literal pool and cross-checked against `OBJC_IVAR_$_World.<name>`. If the derivation were wrong, no
load would hit that address and the field fails rather than returning a plausible number from
somewhere else. Pass 2 then reads the value at whatever address that instruction computes, so it
follows the cell wherever the test points it.

Controls per field: two planted values bit-exact; plus a cross-control that rewrites the cell to
ANOTHER float field's offset and requires that field's planted value back (with a decoy planted at
the original offset) - which proves the value tracks the cell rather than a cached offset.

Usage:
  python3 tools/emulate_float_getters.py <libApplication.so> --methods <t.tsv> [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN      # noqa: E402
from elftools.elf.elffile import ELFFile                                       # noqa: E402

from emulate_worldtime_getter import BIAS, OBJ, STACK_TOP, SENTINEL, load_image  # noqa: E402

FLOAT_FIELDS = ("timeOfDayFraction", "weatherFraction", "rainFraction",
                "rainFractionNotIncludingSnow", "simulationProgress")
# The Unicorn register ids are NOT the ARM register numbers (UC_ARM_REG_R0 == 66, while id 0 is a
# deprecated no-op that reads back garbage) - using range(13) here silently computed every effective
# address from a wrong register value. Build the table from the real constants.
from unicorn import arm_const as _ac                                              # noqa: E402

REGS = {n: getattr(_ac, f"UC_ARM_REG_{n.upper()}")
        for n in ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
                  "sp", "lr", "pc")}


def derive(blob: bytes, imp: int) -> dict:
    """slot = wA + PIC base (from the getter's own pool); cell = *(slot); offset = *(cell)."""
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    insns = list(md.disasm(blob[imp:imp + 0x60], imp))
    for i, ins in enumerate(insns):
        if ins.mnemonic != "add" or ", pc, " not in ins.op_str or i == 0:
            continue
        rd = ins.op_str.split(",")[0].strip()
        prev = insns[i - 1]
        if prev.mnemonic != "ldr" or "pc" not in prev.op_str or rd not in prev.op_str:
            continue
        k = int(prev.op_str.split("#")[1].rstrip("]"), 16)
        pic = (ins.address + 8 + struct.unpack_from("<I", blob, prev.address + 8 + k)[0]) & 0xFFFFFFFF
        order = list(range(i - 2, max(0, i - 5), -1)) + list(range(i + 1, min(len(insns), i + 4)))
        for j in order:
            q = insns[j]
            if q.mnemonic != "ldr" or "pc" not in q.op_str or q.op_str.split(",")[0].strip() == rd:
                continue
            kq = int(q.op_str.split("#")[1].rstrip("]"), 16)
            slot = (struct.unpack_from("<I", blob, q.address + 8 + kq)[0] + pic) & 0xFFFFFFFF
            if not (0 < slot < len(blob)):
                continue
            cell = struct.unpack_from("<I", blob, slot)[0]
            return {"slot": slot, "cell": cell, "offset": struct.unpack_from("<i", blob, cell)[0],
                    "pic": pic, "trace": [f"slot {slot:#x} from wA+PIC {pic:#x}", f"cell {cell:#x}",
                                          f"offset {struct.unpack_from('<i', blob, cell)[0]}"]}
    return {"slot": None}


def loads_in(blob: bytes, imp: int) -> dict[int, tuple[str, str | None, int]]:
    """address -> (base, index, immediate) for every memory load in the getter, VFP included.

    The rule this feeds is "the access whose effective address equals self+offset", and the family uses
    two different instructions for that read: a plain `ldr` into a stack copy (the weather getters), and
    a direct `vldr s0,[r0]` (simulationProgress). Collecting only integer loads is why the latter came
    back unexplained.
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    out = {}
    for ins in list(md.disasm(blob[imp:imp + 0x60], imp))[:24]:
        if not (ins.mnemonic in ("ldr", "ldrb", "ldrsb", "ldrh") or ins.mnemonic.startswith("vldr")):
            continue
        if "[" not in ins.op_str:
            continue
        inner = ins.op_str.split("[", 1)[1].split("]")[0]
        parts = [p.strip() for p in inner.split(",")]
        if not parts or parts[0] not in REGS:
            continue
        imm, idx = 0, None
        for extra in parts[1:]:
            if extra.startswith("#"):
                imm = int(extra[1:], 0)
            elif extra in REGS:
                idx = extra
        out[ins.address] = (parts[0], idx, imm)
    return out


def run(mu, imp: int, slot: int, cell: int, offset: int, planted: float, planted_at: int,
        loads: dict, want_ea: int | None, planted2: float | None = None, planted2_at: int | None = None,
        cell_override: int | None = None, want_at: int | None = None):
    """Returns (value, ea, hit_address). If want_ea is set, only that address counts as the field."""
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_SP

    mu.mem_write(BIAS + slot, struct.pack("<I", BIAS + cell))
    mu.mem_write(BIAS + cell, struct.pack("<i", cell_override if cell_override is not None else offset))
    mu.mem_write(OBJ, b"\0" * 0x2000)
    mu.mem_write(OBJ + planted_at, struct.pack("<f", planted))
    if planted2 is not None and planted2_at is not None:
        mu.mem_write(OBJ + planted2_at, struct.pack("<f", planted2))
    mu.mem_write(BIAS + STACK_TOP - 0x4000, b"\0" * 0x4000)
    st = {"value": None, "ea": None, "at": None}

    def hook(mu_, addr, size, _):
        if addr not in loads:
            return
        base, idx, imm = loads[addr]
        if base == "pc":                    # pc reads as the current instruction here; ARM adds 8
            ea = addr + 8 + imm
        else:
            ea = mu_.reg_read(REGS[base]) + imm
            if idx is not None:
                ea += mu_.reg_read(REGS[idx])
        ea &= 0xFFFFFFFF
        if want_at is not None and addr != want_at:
            return
        if want_ea is not None and ea != want_ea:
            return
        st["ea"], st["at"] = ea, addr
        st["value"] = struct.unpack("<f", bytes(mu_.mem_read(ea, 4)))[0]
        mu_.emu_stop()

    h = mu.hook_add(UC_HOOK_CODE, hook)
    mu.reg_write(UC_ARM_REG_R0, OBJ)
    mu.reg_write(UC_ARM_REG_SP, BIAS + STACK_TOP)
    mu.reg_write(UC_ARM_REG_LR, SENTINEL)
    try:
        mu.emu_start(BIAS + imp, BIAS + SENTINEL, timeout=5_000_000)
    except Exception as exc:                      # VFP/dmb after the field read must not mask a hit
        if st["value"] is None and st["at"] is None:
            raise
        st["stopped_by"] = f"{type(exc).__name__}: {exc}"
    mu.hook_del(h)
    return st["value"], st["ea"], st["at"], st.get("stopped_by")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--methods", type=Path, required=True)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()
    elf = Path(args.libapplication)
    blob = elf.read_bytes()

    enc, cell_of = {}, {}
    with elf.open("rb") as fh:
        e = ELFFile(fh)
        for s in e.get_section_by_name(".dynsym").iter_symbols():
            if s.name.startswith("OBJC_IVAR_$_World.") and s["st_value"]:
                cell_of[s.name[len("OBJC_IVAR_$_World."):]] = s["st_value"]
    for line in args.methods.read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 5 and p[1] == "World" and p[2] == "instance":
            try:
                enc[p[3]] = (int(p[0], 16), p[4])
            except ValueError:
                continue

    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    load_image(mu, elf)
    mu.mem_map(OBJ & ~0xFFF, 0x4000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(BIAS + STACK_TOP - 0x8000, 0x8000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(SENTINEL & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    mu.mem_write(SENTINEL, struct.pack("<I", 0xE1A0F00E))

    derived = {n: derive(blob, enc[n][0]) for n in FLOAT_FIELDS if n in enc}
    offsets = {n: d["offset"] for n, d in derived.items() if d.get("slot")}
    results, ok = [], True
    for name in FLOAT_FIELDS:
        if name not in enc:
            continue
        imp, types = enc[name]
        der = derive(blob, imp)
        row = {"field": name, "imp": hex(imp), "types": types, "slot": hex(der["slot"]),
               "cell": hex(der["cell"]), "offset": der["offset"],
               "symbol_cell_agrees": cell_of.get(name) == der["cell"]}
        if types[0] != "f" or not row["symbol_cell_agrees"]:
            row["status"] = "not a scalar float getter on this shape"
            results.append(row)
            ok = False
            continue
# the code hook reports BIAS+vaddr, so key the table the same way
        loads = {BIAS + a: v for a, v in loads_in(blob, imp).items()}
        v1, v2 = 0.375, -12.5
        try:
            val, ea, at, stopped = run(mu, imp, der["slot"], der["cell"], der["offset"], v1,
                                       der["offset"], loads, OBJ + der["offset"])
        except Exception as exc:      # one field must not take the batch down (learned the hard way)
            row["status"] = f"error in pass 1: {type(exc).__name__}: {exc}"
            results.append(row)
            ok = False
            continue
        row["provenance"] = {"first_load_ea": hex(ea) if ea else None,
                            "expected_ea": hex(OBJ + der["offset"]),
                            "matches_derived_offset": ea == OBJ + der["offset"],
                            "load_instruction": hex(at - BIAS) if at else None,
                            "stopped_by": stopped}
        if at is None:
            row["status"] = "no load in the getter addresses the derived offset"
            results.append(row)
            ok = False
            continue
        v2v, _, _, _ = run(mu, imp, der["slot"], der["cell"], der["offset"], v2, der["offset"],
                           loads, None, want_at=at)
        p1 = struct.pack("<f", val) == struct.pack("<f", v1)
        p2 = struct.pack("<f", v2v) == struct.pack("<f", v2)
        row["positive"] = [{"planted": v1, "returned": val, "ok": p1},
                           {"planted": v2, "returned": v2v, "ok": p2}]
        other = next(((n, o) for n, o in offsets.items() if n != name), None)
        cross_ok = None
        if other:
            oname, ooff = other
            cv, _, _, _ = run(mu, imp, der["slot"], der["cell"], der["offset"], 7.25, ooff, loads, None,
                              planted2=99.0, planted2_at=der["offset"], cell_override=ooff,
                              want_at=at)
            cross_ok = struct.pack("<f", cv or 0.0) == struct.pack("<f", 7.25)
            row["cross_control"] = {"cell_rewritten_to": oname, "offset": ooff,
                                    "expected_ea": hex(OBJ + ooff), "returned": cv,
                                    "decoy_at_original_offset": 99.0, "follows_cell": cross_ok}
        good = p1 and p2 and row["provenance"]["matches_derived_offset"] and bool(cross_ok)
        row["status"] = "executed" if good else "MISMATCH"
        ok &= good
        results.append(row)

    rep = {"schema": 1, "scope": "the float/word clock+weather getters (the third abstraction)",
           "method": "intercept the word load whose effective address equals self+offset, where the "
                     "offset comes from the getter's literal pool cross-checked against the symbol "
                     "table; the value is read at whatever address the original's own instruction "
                     "computes, so a rewritten cell is followed rather than overridden",
           "counts": {"attempted": len(results),
                      "executed": sum(1 for r in results if r.get("status") == "executed")},
           "results": results, "passed": bool(ok and results)}
    if args.json:
        args.json.write_text(json.dumps(rep, indent=1) + "\n")
    print(json.dumps(rep["counts"], indent=1))
    for r in results:
        print(f"  {'OK ' if r.get('status') == 'executed' else '!! '}{r['field']:30s} "
              f"offset={r.get('offset')} "
              f"ea_ok={r.get('provenance', {}).get('matches_derived_offset')} "
              f"cross={r.get('cross_control', {}).get('follows_cell')} {r.get('status')}")
    print("passed:", rep["passed"])
    return 0 if rep["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
