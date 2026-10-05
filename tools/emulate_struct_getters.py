#!/usr/bin/env python3
"""The struct-returning getters: two shapes, one provenance rule.

The scalar work left two shapes unread, and they need different mechanics:

  inline  (translation @624, highestPoint @3164 - 8 bytes)
      ldr r2,[r1] ; str r2,[r0] ; ldr r1,[r1,#4] ; str r1,[r0,#4]
      the field is read by plain integer loads at self+offset, copied into the hidden return buffer in
      r0. Abstraction: none - read `width` bytes at the access that addresses the field.

  copy    (sunDirection @660 - 16 bytes)
      add r1,r1,r2 ; mov r2,ip(=0x10) ; movw lr,#1 ; ... ; bl 0x1c2888
      the field is copied out through the SAME copy helper the worldTime double uses, so the
      provenance anchor is the call itself: source == self+offset and length == width. (That the
      helper is called with 0x10 independently confirms the 16-byte size the type string claims.)

Widths come from each method's own type encoding (`{Vector=[4f]}`, `{Vector2=[2f]}`, `{?=ii}`), parsed
rather than tabulated, and the observed copy length is checked against the parsed width - so the two
independent sources have to agree before a value is reported.

Honest boundary: the hidden return buffer is the caller's memory in an ABI that is only meaningful
together with the caller, so what this reports is the STRUCT CONTENT read at the field, which is what
the reconstruction needs; it does not claim to have run a caller.

Usage:
  python3 tools/emulate_struct_getters.py <libApplication.so> --methods <t.tsv> [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN      # noqa: E402
from elftools.elf.elffile import ELFFile                                       # noqa: E402

from emulate_worldtime_getter import (BIAS, OBJ, STACK_TOP, SENTINEL, COPY_STUB,  # noqa: E402
                                      load_image)
from emulate_float_getters import REGS, derive, loads_in                        # noqa: E402

FIELDS = ("translation", "highestPoint", "sunDirection")


def struct_width(enc: str) -> int | None:
    """Size of a struct return type from its own encoding: `{Vector=[4f]}8@0:4` -> 16."""
    m = re.match(r"\{([^}]*)\}", enc)
    if not m:
        return None
    body = m.group(1).split("=", 1)[-1]
    total = 0
    for tok in re.findall(r"\[(\d+)([a-zA-Z])\]|([a-zA-Z])", body):
        n, kind, single = tok
        if n:
            total += int(n) * 4
        elif single:
            total += 4
    return total or None


def run_field(mu, imp: int, slot: int, cell: int, offset: int, width: int, planted: bytes,
              planted_at: int, decoy: bytes | None = None, decoy_at: int | None = None,
              cell_override: int | None = None, copy_shape: bool = False):
    """Returns (payload, source_address, how). Provenance: source must be self+offset (or self+other)."""
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP

    mu.mem_write(BIAS + slot, struct.pack("<I", BIAS + cell))
    mu.mem_write(BIAS + cell, struct.pack("<i", cell_override if cell_override is not None else offset))
    mu.mem_write(OBJ, b"\0" * 0x2000)
    mu.mem_write(OBJ + planted_at, planted)
    if decoy is not None and decoy_at is not None:
        mu.mem_write(OBJ + decoy_at, decoy)
    mu.mem_write(BIAS + STACK_TOP - 0x4000, b"\0" * 0x4000)
    OUT = OBJ + 0x1000                      # where the hidden return buffer lives in this run
    st = {"payload": None, "src": None, "how": None}
    loads = {BIAS + a: v for a, v in loads_in(blob_ref[0], imp).items()}

    def hook(mu_, addr, size, _):
        from unicorn.arm_const import UC_ARM_REG_R1, UC_ARM_REG_R2
        if addr == BIAS + COPY_STUB and copy_shape:
            src, n = mu_.reg_read(UC_ARM_REG_R1), mu_.reg_read(UC_ARM_REG_R2)
            if n != width:
                return
            st["payload"], st["src"], st["how"] = bytes(mu_.mem_read(src, n)), src, "copy-stub"
            mu_.emu_stop()
            return
        if copy_shape or addr not in loads:
            return
        base, idx, imm = loads[addr]
        if base == "pc":
            ea = addr + 8 + imm
        else:
            ea = mu_.reg_read(REGS[base]) + imm
            if idx is not None:
                ea += mu_.reg_read(REGS[idx])
        ea &= 0xFFFFFFFF
        if ea != OBJ + (cell_override if cell_override is not None else offset):
            return
        # the struct is contiguous at the field address, so take the whole width in one read
        st["payload"], st["src"], st["how"] = bytes(mu_.mem_read(ea, width)), ea, "inline-load"
        mu_.emu_stop()

    h = mu.hook_add(UC_HOOK_CODE, hook)
    # struct-returning ABI (stret):
    #   r0 = hidden return buffer   r1 = self   r2 = _cmd
    # (writing self into r0 here is what made every effective address land at a small
    # unmapped address and fault)
    mu.reg_write(UC_ARM_REG_R0, OUT)
    mu.reg_write(UC_ARM_REG_R1, OBJ)
    mu.reg_write(UC_ARM_REG_SP, BIAS + STACK_TOP)
    mu.reg_write(UC_ARM_REG_LR, SENTINEL)
    try:
        mu.emu_start(BIAS + imp, BIAS + SENTINEL, timeout=5_000_000)
    except Exception:
        if st["payload"] is None:
            raise
    mu.hook_del(h)
    return st["payload"], st["src"], st["how"]


blob_ref = [b""]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("libapplication")
    ap.add_argument("--methods", type=Path, required=True)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()
    elf = Path(args.libapplication)
    blob = elf.read_bytes()
    blob_ref[0] = blob

    enc, cell_of = {}, {}
    with elf.open("rb") as fh:
        e = ELFFile(fh)
        for s in e.get_section_by_name(".dynsym").iter_symbols():
            if s.name.startswith("OBJC_IVAR_$_World.") and s["st_value"]:
                cell_of[s.name[len("OBJC_IVAR_$_World."):]] = s["st_value"]
    for line in args.methods.read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 5 and p[1] == "World" and p[2] == "instance" and p[3] in FIELDS:
            enc[p[3]] = (int(p[0], 16), p[4])

    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    load_image(mu, elf)
    mu.mem_map(OBJ & ~0xFFF, 0x4000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(BIAS + STACK_TOP - 0x8000, 0x8000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(SENTINEL & ~0xFFF, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    mu.mem_write(SENTINEL, struct.pack("<I", 0xE1A0F00E))

    from emulate_float_getters import loads_in as _li
    derived = {}
    for name in FIELDS:
        if name in enc:
            imp, te = enc[name]
            derived[name] = derive(blob, imp) | {"width": struct_width(te), "types": te}

    results, ok = [], True
    for name in FIELDS:
        if name not in enc:
            continue
        imp, te = enc[name]
        der = derived[name]
        body = blob[imp:imp + 0x70]
        copy_shape = any(i.mnemonic == "bl" and i.op_str.lstrip("#") == hex(COPY_STUB) for i in
                         Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN).disasm(body, imp))
        width = der["width"]
        row = {"field": name, "imp": hex(imp), "types": te, "width_from_type": width,
               "slot": hex(der["slot"]), "cell": hex(der["cell"]), "offset": der["offset"],
               "shape": "copy-stub" if copy_shape else "inline-load",
               "symbol_cell_agrees": (None if name not in cell_of else cell_of[name] == der["cell"]),
               "symbol_note": ("no OBJC_IVAR_$_World." + name + " in .dynsym, so the symbol cross-check is unavailable for this field"
                               if name not in cell_of else "cell == symbol value")}
        if not width or row["symbol_cell_agrees"] is False:
            row["status"] = "no parsable width, or the derived cell disagrees with the symbol"
            results.append(row)
            ok = False
            continue
        payload = bytes((i * 7 + 3) & 0xFF for i in range(width))
        try:
            got, src, how = run_field(mu, imp, der["slot"], der["cell"], der["offset"], width,
                                      payload, der["offset"], copy_shape=copy_shape)
            # Prefer a same-width partner, but if the family has only ONE field of this width there is
            # no such partner - and demanding one silently turned a working read into a MISMATCH. Fall
            # back to a control that does not depend on width: rewrite the cell to any other field and
            # require the SOURCE ADDRESS to follow it.
            other = next((n for n, d in derived.items()
                          if n != name and d.get("width") == width and d["offset"] != der["offset"]), None)
            fallback = other is None
            if fallback:
                other = next((n for n, d in derived.items() if n != name), None)
            cross_ok = None
            if other:
                opay = bytes((i * 5 + 11) & 0xFF for i in range(width))
                cv, csrc, _ = run_field(mu, imp, der["slot"], der["cell"], der["offset"], width,
                                        opay, derived[other]["offset"], decoy=payload,
                                        decoy_at=der["offset"], cell_override=derived[other]["offset"],
                                        copy_shape=copy_shape)
                if fallback:
                    cross_ok = csrc == OBJ + derived[other]["offset"]
                    row["cross_control"] = {"control_kind": "source-address-follows-cell",
                                            "cell_rewritten_to": other,
                                            "offset": derived[other]["offset"],
                                            "source_seen": hex(csrc) if csrc else None,
                                            "source_followed": cross_ok,
                                            "why": "only one field of this width exists, so there is no "
                                                   "same-width partner to compare values against"}
                else:
                    cross_ok = cv == opay
                    row["cross_control"] = {"control_kind": "same-width-value",
                                            "cell_rewritten_to": other,
                                            "offset": derived[other]["offset"],
                                            "returned_matches": cross_ok,
                                            "decoy_at_original": payload.hex()}
            row["positive"] = {"planted": payload.hex(), "returned": got.hex() if got else None,
                               "bit_exact": got == payload, "source": hex(src) if src else None,
                               "expected_source": hex(OBJ + der["offset"]), "how": how}
            good = (got == payload) and src == OBJ + der["offset"] and bool(cross_ok)
            row["status"] = "executed" if good else "MISMATCH"
            ok &= good
        except Exception as exc:
            row["status"] = f"error: {type(exc).__name__}: {exc}"
            ok = False
        results.append(row)

    rep = {"schema": 1, "scope": "the struct-returning World getters",
           "method": "provenance is the source address of the field read: the access that lands on "
                     "self+offset (inline shape) or the copy helper called with src == self+offset and "
                     "length == width (copy shape). Widths are parsed from the type encoding and "
                     "checked against the observed copy length.",
           "counts": {"attempted": len(results),
                      "executed": sum(1 for r in results if r.get("status") == "executed")},
           "results": results, "passed": bool(ok and results)}
    if args.json:
        args.json.write_text(json.dumps(rep, indent=1) + "\n")
    print(json.dumps(rep["counts"], indent=1))
    for r in results:
        cc = r.get("cross_control", {})
        ctl = cc.get("returned_matches", cc.get("source_followed"))
        print(f"  {'OK ' if r.get('status') == 'executed' else '!! '}{r['field']:14s} "
              f"offset={r.get('offset')} width={r.get('width_from_type')} shape={r.get('shape')} "
              f"control[{cc.get('control_kind', '-')}]={ctl} {r.get('status')}")
    print("passed:", rep["passed"])
    return 0 if rep["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
