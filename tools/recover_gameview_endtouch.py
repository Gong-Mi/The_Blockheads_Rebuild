#!/usr/bin/env python3
"""Byte-gate the bounded GameView/World primary end-touch source batch.

This verifies the checked-in instruction listings against one SHA-pinned ELF,
then checks the complete call/branch-site sets, resolves every selector/ivar
literal cell through the pinned PIC/GOT walk, and records the hand-reviewed
receiver/selector map. It does not resolve new Objective-C symbols, emulate
the runtime, or claim APK integration.
"""
import argparse
import hashlib
import io
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
SHA256 = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
MSGSEND_STUB = 0x001C281C
MSGSEND_GOT_SLOT = 0x0105B7A0  # import slot reloaded for both blx r2 gate sites
PIC_BASE = 0x0105FAF4

METHODS = (
    {
        "class": "GameView",
        "selector": "endTouch:",
        "types": "v16@0:4{CGPoint=ff}8",
        "disasm": "disasm_gameview_endtouch.txt",
        "start": 0x0092C3F4,
        "code_end": 0x0092C608,
        "end": 0x0092C638,
        "pic_add": 0x0092C404,
        "pic_literal": 0x0092C634,
        "direct_calls": {
            0x0092C4A4: "mainMenuUI -[endTouch:]",
            0x0092C5D4: "World -[endTouch:index:] (index literal 0)",
        },
        "indirect_calls": {
            0x0092C4E8: "World -[loadComplete] via GOT objc_msgSend reload",
            0x0092C534: "World -[isSimulating] via GOT objc_msgSend reload",
        },
        "branches": (
            (0x0092C43C, 0x0092C4AC, "beq: mainMenuUI == nil -> World path"),
            (0x0092C464, 0x0092C4AC, "bne: world != nil -> World path"),
            (0x0092C4A8, 0x0092C5E0, "b: menu callback done -> shared tail clear"),
            (0x0092C4F4, 0x0092C5DC, "beq: loadComplete byte == 0 -> tail clear, no send"),
            (0x0092C540, 0x0092C5DC, "bne: isSimulating byte != 0 -> tail clear, no send"),
            (0x0092C564, 0x0092C58C, "bne: primaryTouchIsActiveInUI != 0 -> indexed send"),
            (0x0092C588, 0x0092C5D8, "bne: secondaryTouchIsActiveInUI != 0 -> skip send"),
            (0x0092C5D8, 0x0092C5DC, "b: join"),
            (0x0092C5DC, 0x0092C5E0, "b: join -> shared tail clear"),
        ),
        "anchors": {
            0x0092C408: "movw lr, 0",
            0x0092C4E8: "blx r2",
            0x0092C534: "blx r2",
            0x0092C55C: "ldrsb",
            0x0092C580: "ldrsb",
            0x0092C5CC: "mov lr, 0",
            0x0092C5D0: "str lr, [ip]",
            0x0092C5E0: "movw r0, 0",
            0x0092C5FC: "strb",
        },
        "selector_cells": {
            "endTouch:": (0x0092C614, 0x00E836B8),
            "loadComplete": (0x0092C61C, 0x00E835D0),
            "isSimulating": (0x0092C620, 0x00E835C8),
            "endTouch:index:": (0x0092C630, 0x00E836BC),
        },
        "ivar_cells": {
            "mainMenuUI": (0x0092C608, 0x0105E168),
            "world": (0x0092C60C, 0x0105E110),
            "primaryTouchIsActiveInUI": (0x0092C624, 0x0105E208),
            "secondaryTouchIsActiveInUI": (0x0092C628, 0x0105E214),
        },
        "ivars": [
            {"name": "mainMenuUI", "offset": 20, "evidence": "OBJC_IVAR_$_GameView.mainMenuUI via GOT slot 0x0105e168"},
            {"name": "world", "offset": 24, "evidence": "OBJC_IVAR_$_GameView.world via GOT slot 0x0105e110"},
            {"name": "primaryTouchIsActiveInUI", "offset": 496, "evidence": "OBJC_IVAR_$_GameView.primaryTouchIsActiveInUI via GOT slot 0x0105e208"},
            {"name": "secondaryTouchIsActiveInUI", "offset": 508, "evidence": "OBJC_IVAR_$_GameView.secondaryTouchIsActiveInUI via GOT slot 0x0105e214"},
        ],
    },
    {
        "class": "World",
        "selector": "endTouch:index:",
        "types": "v20@0:4{CGPoint=ff}8i16",
        "disasm": "disasm_world_endtouch_index.txt",
        "start": 0x005B3430,
        "code_end": 0x005B34AC,
        "end": 0x005B34B4,
        "pic_add": 0x005B3474,
        "pic_literal": 0x005B34B0,
        "direct_calls": {
            0x005B34A0: "self -[doEndTouch:wasCancelled:index:] (wasCancelled literal 0, index preserved from stack)",
        },
        "indirect_calls": {},
        "branches": (),
        "anchors": {
            0x005B343C: "ldr ip, [fp, 8]",
            0x005B3488: "str r1, [lr, 4]",
            0x005B348C: "mov r1, 0",
            0x005B3490: "str r1, [lr]",
        },
        "selector_cells": {
            "doEndTouch:wasCancelled:index:": (0x005B34AC, 0x00E7E528),
        },
        "ivar_cells": {},
        "ivars": [],
    },
)


def signed32(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


def parse_rows(text: str) -> dict[int, tuple[int, str]]:
    rows = {}
    for line in text.splitlines():
        match = re.search(r"\b(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s+(.*)", line)
        if match:
            rows[int(match.group(1), 16)] = (int(match.group(2), 16), match.group(3).strip())
    return rows


def branch_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f"{site:#x} is not an ARM BL immediate: {word:#010x}")
    imm = word & 0x00FFFFFF
    if imm & 0x00800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xFFFFFFFF


def resolve_method(memory: ELFMemory, elf_symbols: dict[int, str], spec: dict) -> dict:
    """Resolve each literal cell through the pinned GOT base; fail on drift."""
    resolved = {"selectors": {}, "ivars": {}}
    for name, (cell, expected_slot) in spec["selector_cells"].items():
        slot = (PIC_BASE + signed32(memory.word(cell))) & 0xFFFFFFFF
        if slot != expected_slot:
            raise ValueError(f"{spec['selector']}: selector {name} cell {cell:#x} -> slot {slot:#x}, expected {expected_slot:#x}")
        pointer = memory.word(slot)
        offset = memory.offset(pointer, 1)
        if offset is None:
            raise ValueError(f"{spec['selector']}: selector {name} pointer {pointer:#x} not file-backed")
        end = memory.data.find(b"\0", offset, offset + 256)
        got = memory.data[offset:end].decode("utf-8", "strict")
        if got != name:
            raise ValueError(f"{spec['selector']}: selector cell drifted at {cell:#x}: got {got!r}")
        resolved["selectors"][name] = {"cell": f"0x{cell:08x}", "slot": f"0x{slot:08x}"}
    for name, (cell, expected_slot) in spec["ivar_cells"].items():
        slot = (PIC_BASE + signed32(memory.word(cell))) & 0xFFFFFFFF
        if slot != expected_slot:
            raise ValueError(f"{spec['selector']}: ivar {name} cell {cell:#x} -> slot {slot:#x}, expected {expected_slot:#x}")
        entry = memory.word(slot)
        symbol = elf_symbols.get(entry, "")
        if symbol != f"OBJC_IVAR_$_{spec['class']}.{name}":
            raise ValueError(f"{spec['selector']}: ivar cell drifted at {cell:#x}: {symbol}")
        resolved["ivars"][name] = {"cell": f"0x{cell:08x}", "slot": f"0x{slot:08x}",
                                   "symbol": symbol, "offset": memory.word(entry)}
    # Cross-check the reviewed ivar offsets against the resolved symbols.
    for ivar in spec["ivars"]:
        entry = resolved["ivars"].get(ivar["name"])
        if entry and entry["offset"] != ivar["offset"]:
            raise ValueError(f"{spec['selector']}: ivar {ivar['name']} offset drift {entry['offset']}")
    return resolved


def verify_method(memory: ELFMemory, elf_symbols: dict[int, str], spec: dict) -> dict:
    disasm_path = NATIVE / spec["disasm"]
    text = disasm_path.read_text(encoding="utf-8")
    words = verify_disassembly(memory, text, spec["start"], spec["end"])
    rows = parse_rows(text)
    code_addresses = set(range(spec["start"], spec["code_end"], 4))
    if {address for address in rows if spec["start"] <= address < spec["code_end"]} != code_addresses:
        raise ValueError(f"{spec['class']} {spec['selector']}: instruction-address coverage changed")

    base = (spec["pic_add"] + 8 + signed32(memory.word(spec["pic_literal"]))) & 0xFFFFFFFF
    if base != PIC_BASE:
        raise ValueError(f"{spec['class']} {spec['selector']}: PIC base drift {base:#x}")

    direct = {a for a, (_word, asm) in rows.items()
              if spec["start"] <= a < spec["code_end"] and asm.startswith("bl ")}
    indirect = {a for a, (_word, asm) in rows.items()
                 if spec["start"] <= a < spec["code_end"] and asm.startswith("blx ")}
    if direct != set(spec["direct_calls"]):
        raise ValueError(f"{spec['class']} {spec['selector']}: direct call set drift {direct ^ set(spec['direct_calls'])}")
    if indirect != set(spec["indirect_calls"]):
        raise ValueError(f"{spec['class']} {spec['selector']}: indirect call set drift {indirect ^ set(spec['indirect_calls'])}")
    for site in direct:
        target = branch_target(site, memory.word(site))
        if target != MSGSEND_STUB:
            raise ValueError(f"{site:#x}: expected objc_msgSend stub, got {target:#x}")
    for site in indirect:
        if rows[site][1] != "blx r2":
            raise ValueError(f"{site:#x}: indirect dispatch changed: {rows[site][1]}")

    observed_branches = {}
    for address, (_word, asm) in rows.items():
        if not spec["start"] <= address < spec["code_end"]:
            continue
        match = re.match(r"^(b(?:eq|ne|gt|le)?)\s+0x([0-9a-f]+)\b", asm)
        if match:
            observed_branches[address] = (int(match.group(2), 16), match.group(1))
    expected_branches = {address: (target, condition.split(":", 1)[0])
                         for address, target, condition in spec["branches"]}
    if observed_branches != expected_branches:
        raise ValueError(f"{spec['class']} {spec['selector']}: branch map drift")

    for address, mnemonic in spec["anchors"].items():
        actual = rows.get(address, (0, ""))[1]
        if not actual.startswith(mnemonic):
            raise ValueError(f"{address:#x}: expected {mnemonic!r}, got {actual!r}")

    resolved = resolve_method(memory, elf_symbols, spec)

    calls = []
    for address, description in spec["direct_calls"].items():
        calls.append({"site": f"0x{address:08x}", "route": "bl objc_msgSend@plt",
                      "target": f"0x{MSGSEND_STUB:08x}", "selector_route": description})
    for address, description in spec["indirect_calls"].items():
        calls.append({"site": f"0x{address:08x}", "route": f"blx r2 via GOT reload 0x{MSGSEND_GOT_SLOT:08x}",
                      "selector_route": description})
    calls.sort(key=lambda call: int(call["site"], 16))
    return {
        "class": spec["class"],
        "selector": spec["selector"],
        "types": spec["types"],
        "implementation": f"0x{spec['start']:08x}",
        "arm_exidx_end": f"0x{spec['end']:08x}",
        "code_end_exclusive": f"0x{spec['code_end']:08x}",
        "verified_interval_words": words,
        "code_words": len(code_addresses),
        "literal_pool_words": (spec["end"] - spec["code_end"]) // 4,
        "pic_base": f"0x{PIC_BASE:08x}",
        "calls": calls,
        "branches": [
            {"site": f"0x{site:08x}", "target": f"0x{target:08x}", "condition": condition}
            for site, target, condition in spec["branches"]
        ],
        "selector_cells": resolved["selectors"],
        "ivar_cells": resolved["ivars"],
        "ivars": spec["ivars"],
        "claim": "bounded static method map + pinned GOT/selref/ivar-cell resolution + typed host snapshot; dynamic ObjC callees and original runtime are not verified",
    }


def recover(elf_path: Path) -> dict:
    blob = elf_path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != SHA256:
        raise ValueError(f"ELF SHA-256 mismatch: {digest}")
    memory = ELFMemory(elf_path)
    if memory.imports.get(MSGSEND_GOT_SLOT) != "objc_msgSend":
        raise ValueError("msgSend GOT reload slot evidence changed")
    elf = ELFFile(io.BytesIO(blob))
    elf_symbols = {s["st_value"]: s.name
                   for s in elf.get_section_by_name(".dynsym").iter_symbols()}
    methods = [verify_method(memory, elf_symbols, spec) for spec in METHODS]
    return {
        "schema": 1,
        "elf_sha256": digest,
        "batch": "GameView endTouch: -> World endTouch:index: -> doEndTouch:wasCancelled:index: forwarding",
        "methods": methods,
        "replacement_boundary": {
            "host_module": "blockheads_recovered_view",
            "host_test": "tools/test_gameview_endtouch.cpp",
            "android_apk_input_path": "GameActivity.onScroll -> handlePanNative remains separate and does not invoke these recovered methods",
            "apk_integration": False,
            "original_runtime_differential": False,
        },
        "symbol_mapping_basis": "manual cross-reference to the existing pinned startTouch/moveTouch/cancelTouch ivar maps, the checked-in ObjC method table, and a per-cell GOT/selref/ivar-symbol resolution re-verified against this ELF by recover(); the resolution walk proves cell-to-name binding, not dynamic receiver identity",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=NATIVE / "gameview_endtouch.json")
    args = parser.parse_args()
    result = recover(args.elf)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.output.read_text(encoding="utf-8") != payload:
            raise SystemExit("stale gameview_endtouch.json")
    else:
        args.output.write_text(payload, encoding="utf-8")
    print(json.dumps({
        "methods": len(result["methods"]),
        "words": sum(method["verified_interval_words"] for method in result["methods"]),
        "calls": sum(len(method["calls"]) for method in result["methods"]),
        "branches": sum(len(method["branches"]) for method in result["methods"]),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
