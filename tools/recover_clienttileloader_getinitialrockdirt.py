#!/usr/bin/env python3
"""Byte-gated static map for ClientTileLoader's initial terrain heights.

This is the client/network counterpart of WorldTileLoader's much larger
single-player generator.  It has no customRules objc_msgSend_stret path:
the fixed formula uses two ClientTileLoader height-noise objects.
"""
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
START, END = 0x00947AF8, 0x009482A0
BASE = 0x0105FAF4
BASE_ADD, BASE_LITERAL = 0x00947B0C, 0x0094829C
MSGSEND_GOT = 0x0105B7A0
MSGSEND_PLT = 0x001C281C
CLAMP = 0x004BE068
LERP = 0x00582A14
POWF_PLT = 0x001C3F98
POWF_GOT = 0x010602EC

# PIC cells used for the actual object/selector dispatch paths.
CELLS = {
    0x00948278: (0x0105B7A0, "objc_msgSend GOT"),
    0x0094827C: (0x00E83958, "selector getX:Y:octaves:"),
    0x00948284: (0x0105E2C8, "OBJC_IVAR_$_ClientTileLoader.heightNoiseFunctionB"),
    0x0094828C: (0x0105E2CC, "OBJC_IVAR_$_ClientTileLoader.heightNoiseFunctionA"),
    0x00948290: (0x00E83904, "selector worldWidthMacro"),
    0x00948294: (0x0105E2A8, "OBJC_IVAR_$_ClientTileLoader.world"),
}

# Float/double pools.  The second group repeats the first formula's constants
# in a different literal island.
FLOAT_CELLS = {
    0x00947E3C: ("float", 0.0),
    0x00947E40: ("double", 0.20000000298023224),
    0x00947E48: ("double", 0.800000011920929),
    0x00947E50: ("float", 0.05000000074505806),
    0x00947E54: ("float", 0.07000000029802322),
    0x00947E58: ("double", 0.30000001192092896),
    0x00947E60: ("float", 0.10000000149011612),
    0x00947E64: ("float", 32.0),
    0x00948258: ("double", 0.20000000298023224),
    0x00948260: ("double", 0.800000011920929),
    0x00948268: ("double", 0.30000001192092896),
    0x00948270: ("float", 0.10000000149011612),
    0x00948280: ("float", 0.05000000074505806),
    0x00948288: ("float", 0.07000000029802322),
    0x00948298: ("float", 32.0),
}

BLX_CALLS = (
    (0x00947C44, "blx r7", "worldWidthMacro", "world = [self + ClientTileLoader.world@4]"),
    (0x00947CAC, "blx lr", "getX:Y:octaves:", "heightNoiseFunctionA; X=q+0.05, Y=5, octaves=3"),
    (0x00947D14, "blx lr", "getX:Y:octaves:", "heightNoiseFunctionB; X=q+0.07, Y=5, octaves=5"),
    (0x00947D74, "blx lr", "getX:Y:octaves:", "heightNoiseFunctionB; X=q+0.05, Y=7, octaves=9"),
    (0x00948000, "blx r6", "getX:Y:octaves:", "heightNoiseFunctionA; X=q+0.07, Y=5, octaves=3"),
    (0x00948068, "blx lr", "getX:Y:octaves:", "heightNoiseFunctionB; X=q+0.07, Y=5, octaves=3"),
    (0x009480C8, "blx lr", "getX:Y:octaves:", "heightNoiseFunctionB; X=q+0.05, Y=7, octaves=9"),
)
DIRECT_CALLS = (
    (0x00947DAC, CLAMP, "clamp", "first interpolation factor, [0,1]"),
    (0x00947DD0, LERP, "linearInterpolate", "first height blend"),
    (0x00947E98, POWF_PLT, "__wrap_powf", "square when abs(firstShape)<0.1"),
    (0x00948100, CLAMP, "clamp", "second interpolation factor, [0,1]"),
    (0x00948124, LERP, "linearInterpolate", "second height blend"),
    (0x009481BC, POWF_PLT, "__wrap_powf", "square when abs(secondShape)<0.1"),
)
BRANCHES = (
    (0x00947E34, 0x00947EB4, "bpl: abs(shape) >= 0.1 -> leave shape linear"),
    (0x00947E38, 0x00947E68, "b: abs(shape) < 0.1 -> square branch"),
    (0x00947EBC, 0x00947ECC, "beq: original shape non-negative -> no sign restore"),
    (0x00948188, 0x009481D8, "bpl: abs(shape) >= 0.1 -> leave shape linear"),
    (0x009481E0, 0x009481F0, "beq: original shape non-negative -> no sign restore"),
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


def imm12(word):
    n = 2 * ((word >> 8) & 0xF)
    v = word & 0xFF
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF if n else v


def plt_slot(memory, plt):
    w0, w1, w2 = memory.word(plt), memory.word(plt + 4), memory.word(plt + 8)
    # add ip, pc, #imm; add ip, ip, #imm; ldr pc, [ip,#off]!
    if not ((w0 & 0x0FF00FFF) == 0x0280C000 and
            (w1 & 0x0FF00FFF) == 0x028CC000 and
            (w2 & 0x0FFF0000) == 0x051CF000 and (w2 & 0xFFF) == 0x5B):
        # Keep this helper conservative; site-specific GOT checks below still
        # verify the imported symbols.
        pass
    ip = (plt + 8 + imm12(w0) + imm12(w1)) & 0xFFFFFFFF
    return (ip + (w2 & 0xFFF)) & 0xFFFFFFFF


def recover(path: Path) -> dict:
    memory = ELFMemory(path)
    text = (NATIVE / "disasm_clienttileloader_getinitialrockdirt.txt").read_text()
    words = verify_disassembly(memory, text, START, END)
    base = (BASE_ADD + 8 + signed(memory.word(BASE_LITERAL))) & 0xFFFFFFFF
    if base != BASE:
        raise ValueError(f"PIC base drift: {base:#x}")

    elf = ELFFile(io.BytesIO(path.read_bytes()))
    symbols = {s["st_value"]: s.name for s in elf.get_section_by_name(".dynsym").iter_symbols()}

    if memory.imports.get(MSGSEND_GOT) != "objc_msgSend":
        raise ValueError("objc_msgSend GOT drift")
    if memory.imports.get(POWF_GOT) != "__wrap_powf":
        raise ValueError("powf GOT drift")

    cells = {}
    for cell, (slot, meaning) in CELLS.items():
        got = (base + signed(memory.word(cell))) & 0xFFFFFFFF
        if got != slot:
            raise ValueError(f"cell {cell:#x} -> {got:#x}, expected {slot:#x}")
        entry = memory.word(slot)
        cells[f"0x{cell:08x}"] = {
            "slot": f"0x{slot:08x}",
            "meaning": meaning,
            "symbol": symbols.get(entry),
            "slot_word": f"0x{entry:08x}",
        }

    constants = {}
    for cell, (kind, expected) in FLOAT_CELLS.items():
        off = memory.offset(cell, 8 if kind == "double" else 4)
        if kind == "double":
            got = struct.unpack("<d", memory.data[off:off + 8])[0]
        else:
            got = struct.unpack("<f", memory.data[off:off + 4])[0]
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
            raise ValueError(f"call site {site:#x}: {rows.get(site)!r}")
    for site, target, _name, _note in DIRECT_CALLS:
        if bl_target(site, memory.word(site)) != target:
            raise ValueError(f"direct call target drift at {site:#x}")
    for site, dest, _note in BRANCHES:
        m = re.match(r"^b\w*\s+(0x[0-9a-f]+)", rows.get(site, ""))
        if not m or int(m[1], 16) != dest:
            raise ValueError(f"branch drift at {site:#x}: {rows.get(site)!r}")

    return {
        "method": "ClientTileLoader -[getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:]",
        "types": "v20@0:4i8^f12^f16",
        "elf_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "imp": f"0x{START:08x}",
        "boundary_end": f"0x{END:08x}",
        "boundary_note": "no own ARM.exidx row; closed by next IMP -[maxOfRockAndDirtHeightForX:]",
        "verified_words": words,
        "pic_base": f"0x{base:08x}",
        "cells": cells,
        "constants": constants,
        "blx_calls": [{"site": f"0x{s:08x}", "route": r, "selector": sel, "note": n}
                      for s, r, sel, n in BLX_CALLS],
        "direct_calls": [{"site": f"0x{s:08x}", "target": f"0x{t:08x}", "name": n, "note": x}
                         for s, t, n, x in DIRECT_CALLS],
        "branches": [{"site": f"0x{s:08x}", "destination": f"0x{d:08x}", "note": n}
                     for s, d, n in BRANCHES],
        "formula": {
            "q": "(float)x / 32.0f / (float)[world worldWidthMacro]",
            "sample_triplet": [
                "A(q+0.05, 5.0, 3)",
                "B(q+0.07, 5.0, 5)",
                "B(q+0.05, 7.0, 9)",
            ],
            "sample_shape": "u=clamp(0.8*B(q+0.05,7,9)+0.2,0,1); v=lerp(0.3*A(q+0.05,5,3)+5, 5*B(q+0.07,5,5)+5, u); r=(v-5)*2",
            "small_shape": "if abs(r)<0.1: r=powf(r,2); restore sign from original r",
            "rock": "1.0 + 32.0 * 3.0 * (5.0 + r/2.0)",
            "dirt": "2.0 + 32.0 * 3.0 * (5.0 + r2/2.0)",
        },
        "claim": "static bounded-body map; noise internals are mapped separately in NOISEFUNCTION_GETXY.md; runtime values and ClientTileLoader integration remain unverified",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("elf", type=Path)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--output", type=Path, default=NATIVE / "clienttileloader_getinitialrockdirt.json")
    args = ap.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit("stale clienttileloader_getinitialrockdirt.json")
    else:
        args.output.write_text(payload)
    print(f"words={report['verified_words']} blx=7 direct=6 branches=5 constants={len(report['constants'])} cells={len(report['cells'])}")


if __name__ == "__main__":
    main()
