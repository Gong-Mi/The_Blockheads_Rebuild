#!/usr/bin/env python3
"""Byte-gated map for ClientTileLoader -[faultOffsetForX:y:]."""
import argparse
import hashlib
import io
import json
import re
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
START, END = 0x00948470, 0x009488E0
BASE = 0x0105FAF4
BASE_ADD, BASE_LITERAL = 0x00948484, 0x009488DC
MSGSEND_GOT = 0x0105B7A0

CELLS = {
    0x009488B0: (0x0105B7A0, "objc_msgSend GOT"),
    0x009488B4: (0x00E83904, "selector worldWidthMacro"),
    0x009488B8: (0x0105E2A8, "OBJC_IVAR_$_ClientTileLoader.world"),
    0x009488C4: (0x00E83958, "selector getX:Y:octaves:"),
    0x009488C8: (0x0105E2C0, "OBJC_IVAR_$_ClientTileLoader.faultNoiseFunction"),
    0x009488D4: (0x0105E2C8, "OBJC_IVAR_$_ClientTileLoader.heightNoiseFunctionB"),
}
FLOAT_CELLS = {
    0x0094889C: ("float", 32.0),
    0x009488A0: ("double", 0.20000000298023224),
    0x009488A8: ("double", 0.800000011920929),
    0x009488BC: ("float", 32.0),
    0x009488C0: ("float", 512.0),
    0x009488CC: ("float", 0.0),
    0x009488D0: ("float", 0.05000000074505806),
    0x009488D8: ("float", 0.20000000298023224),
}
BLX_CALLS = (
    (0x00948508, "blx lr", "worldWidthMacro", "world = self + world ivar"),
    (0x00948560, "blx r3", "worldWidthMacro", "second width query"),
    (0x00948688, "blx r4", "getX:Y:octaves:", "heightNoiseFunctionB(qx+0.05, 7, 1)"),
    (0x00948734, "blx lr", "getX:Y:octaves:", "faultNoiseFunction(qx, qy, 1)"),
)
DIRECT_CALLS = (
    (0x009486C0, 0x004BE068, "clamp", "band clamp [0,1]"),
    (0x0094879C, 0x001C3F98, "__wrap_powf", "powf(2*a,2) for 0<a<0.2"),
    (0x00948838, 0x001C3F98, "__wrap_powf", "powf(2*(a-0.2),2) for a>=0.2"),
)
BRANCHES = (
    (0x009485A0, 0x009485E4, "bge: width >= 512 -> retain qy=(y/64)/width"),
    (0x0094875C, 0x00948860, "ble: abs(fault) <= 0 -> shaped=0"),
    (0x00948770, 0x009487AC, "bpl: abs(fault) >= 0.2 -> ridge branch"),
    (0x009487A8, 0x0094885C, "b: join small-fault branch into final shape"),
    (0x009487F4, 0x00948804, "bpl: max(2*(a-0.2),0) selection"),
    (0x00948800, 0x0094880C, "b: join max selection"),
)


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site, word):
    if word >> 24 != 0xEB:
        raise ValueError(f"{site:#x} is not ARM bl: {word:#x}")
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xFFFFFFFF


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / "disasm_clienttileloader_faultoffset.txt").read_text()
    words = verify_disassembly(memory, text, START, END)
    base = (BASE_ADD + 8 + signed(memory.word(BASE_LITERAL))) & 0xFFFFFFFF
    if base != BASE:
        raise ValueError(f"PIC base drift: {base:#x}")
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbols = {s["st_value"]: s.name for s in elf.get_section_by_name(".dynsym").iter_symbols()}
    if memory.imports.get(MSGSEND_GOT) != "objc_msgSend":
        raise ValueError("objc_msgSend GOT drift")

    cells = {}
    for cell, (slot, meaning) in CELLS.items():
        got = (base + signed(memory.word(cell))) & 0xFFFFFFFF
        if got != slot:
            raise ValueError(f"cell {cell:#x} -> {got:#x}, expected {slot:#x}")
        entry = memory.word(slot)
        cells[f"0x{cell:08x}"] = {
            "slot": f"0x{slot:08x}", "meaning": meaning,
            "symbol": symbols.get(entry), "slot_word": f"0x{entry:08x}",
        }
    constants = {}
    for cell, (kind, expected) in FLOAT_CELLS.items():
        off = memory.offset(cell, 8 if kind == "double" else 4)
        got = (struct.unpack("<d", memory.data[off:off + 8])[0]
               if kind == "double" else struct.unpack("<f", memory.data[off:off + 4])[0])
        if got != expected:
            raise ValueError(f"constant {cell:#x}: {got!r} != {expected!r}")
        constants[f"0x{cell:08x}"] = {"kind": kind, "value": got}

    rows = {}
    for line in text.splitlines():
        m = re.search(r"\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)", line)
        if m:
            rows[int(m[1], 16)] = m[2].strip().replace("#", "")
    for site, route, _sel, _note in BLX_CALLS:
        if rows.get(site) != route:
            raise ValueError(f"blx drift at {site:#x}: {rows.get(site)!r}")
    for site, target, _name, _note in DIRECT_CALLS:
        if bl_target(site, memory.word(site)) != target:
            raise ValueError(f"direct call drift at {site:#x}")
    for site, dest, _note in BRANCHES:
        m = re.match(r"^b\w*\s+(0x[0-9a-f]+)", rows.get(site, ""))
        if not m or int(m[1], 16) != dest:
            raise ValueError(f"branch drift at {site:#x}: {rows.get(site)!r}")

    return {
        "method": "ClientTileLoader -[faultOffsetForX:y:]",
        "types": "i16@0:4i8i12",
        "elf_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "imp": f"0x{START:08x}", "boundary_end": f"0x{END:08x}",
        "boundary_note": "no own ARM.exidx row; closed by next IMP -[isCaveForX:y:faultOffset:]",
        "verified_words": words, "pic_base": f"0x{base:08x}",
        "cells": cells, "constants": constants,
        "blx_calls": [{"site": f"0x{s:08x}", "route": r, "selector": sel, "note": n}
                      for s, r, sel, n in BLX_CALLS],
        "direct_calls": [{"site": f"0x{s:08x}", "target": f"0x{t:08x}", "name": n, "note": x}
                         for s, t, n, x in DIRECT_CALLS],
        "branches": [{"site": f"0x{s:08x}", "destination": f"0x{d:08x}", "note": n}
                     for s, d, n in BRANCHES],
        "formula": {
            "qx": "(float)x / 32.0f / (float)worldWidthMacro",
            "qy": "(float)y / 2.0f / 32.0f / (float)worldWidthMacro",
            "qy_small_world": "if width < 512: (float)y / 2.0f / 32.0f / 512.0f",
            "band": "band=clamp((float)B.getX(qx+0.05,7.0,1),0,1)",
            "fault": "a=abs((float)faultNoiseFunction.getX(qx,qy,1))",
            "shape": "0 if a<=0; powf(2*a,2) if 0<a<0.2; powf(max(2*(a-0.2),0),2)+5*band otherwise",
            "return": "(int)(512.0f * shape * band), vcvt.s32.f32 truncation",
        },
        "claim": "static bounded-body map; runtime noise values and client integration remain unverified",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("elf", type=Path)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--output", type=Path, default=NATIVE / "clienttileloader_faultoffset.json")
    args = ap.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit("stale clienttileloader_faultoffset.json")
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} blx=4 direct=3 branches=6 constants={len(report['constants'])} cells={len(report['cells'])}")


if __name__ == "__main__":
    main()
