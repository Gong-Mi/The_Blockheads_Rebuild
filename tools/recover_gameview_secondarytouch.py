#!/usr/bin/env python3
"""Byte-gate the bounded GameView secondary end/cancel touch batch.

Verifies the checked-in -[endSecondaryTouch:] and -[cancelSecondaryTouch:]
listings against the SHA-pinned ELF with the same gate set as the end/cancel
primary batches (word interval, PIC base, call/branch sets, anchors, per-cell
GOT/selref/ivar-symbol resolution), plus a structural mirror check against the
primary pair: identical selector routes with the (primary, secondary) ivar
roles swapped and index literal 1 instead of 0. r2's ARM.exidx merge makes the
raw endSecondaryTouch listing overlap cancelSecondaryTouch; this tool pins
each body to its own pool end (0x0092cfa0 / 0x0092d188).

It does not resolve new Objective-C symbols, emulate the runtime, or claim
APK integration.
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
MSGSEND_GOT_SLOT = 0x0105B7A0
PIC_BASE = 0x0105FAF4

METHODS = (
    {
        "class": "GameView",
        "selector": "endSecondaryTouch:",
        "types": "v16@0:4{CGPoint=ff}8",
        "disasm": "disasm_gameview_endsecondarytouch.txt",
        "start": 0x0092CDD8,
        "code_end": 0x0092CF78,
        "end": 0x0092CFA0,
        "pic_add": 0x0092CDE8,
        "pic_literal": 0x0092CF9C,
        "direct_calls": {
            0x0092CF48: "World -[endTouch:index:] (index literal 1)",
        },
        "indirect_calls": {
            0x0092CE5C: "World -[loadComplete] via GOT objc_msgSend reload",
            0x0092CEA8: "World -[isSimulating] via GOT objc_msgSend reload",
        },
        "branches": (
            (0x0092CE1C, 0x0092CF50, "beq: secondaryTouchStarted == 0 -> tail clear, no send"),
            (0x0092CE68, 0x0092CF50, "beq: loadComplete byte == 0 -> tail clear, no send"),
            (0x0092CEB4, 0x0092CF50, "bne: isSimulating byte != 0 -> tail clear, no send"),
            (0x0092CED8, 0x0092CF00, "bne: secondaryTouchIsActiveInUI != 0 -> indexed send"),
            (0x0092CEFC, 0x0092CF4C, "bne: primaryTouchIsActiveInUI != 0 -> skip send"),
            (0x0092CF4C, 0x0092CF50, "b: join -> shared tail clear"),
        ),
        "anchors": {
            0x0092CE10: "ldrsb",
            0x0092CED0: "ldrsb",
            0x0092CEF4: "ldrsb",
            0x0092CF40: "mov lr, 1",
            0x0092CF44: "str lr, [ip]",
            0x0092CF50: "movw r0, 0",
            0x0092CF6C: "strb",
        },
        "selector_cells": {
            "loadComplete": (0x0092CF80, 0x00E835D0),
            "isSimulating": (0x0092CF88, 0x00E835C8),
            "endTouch:index:": (0x0092CF98, 0x00E836BC),
        },
        "ivar_cells": {
            "secondaryTouchStarted": (0x0092CF78, 0x0105E218),
            "world": (0x0092CF84, 0x0105E110),
            "secondaryTouchIsActiveInUI": (0x0092CF8C, 0x0105E214),
            "primaryTouchIsActiveInUI": (0x0092CF90, 0x0105E208),
        },
        "ivars": [
            {"name": "secondaryTouchStarted", "offset": 498, "evidence": "OBJC_IVAR_$_GameView.secondaryTouchStarted via GOT slot 0x0105e218"},
            {"name": "world", "offset": 24, "evidence": "OBJC_IVAR_$_GameView.world via GOT slot 0x0105e110"},
            {"name": "secondaryTouchIsActiveInUI", "offset": 508, "evidence": "OBJC_IVAR_$_GameView.secondaryTouchIsActiveInUI via GOT slot 0x0105e214"},
            {"name": "primaryTouchIsActiveInUI", "offset": 496, "evidence": "OBJC_IVAR_$_GameView.primaryTouchIsActiveInUI via GOT slot 0x0105e208"},
        ],
    },
    {
        "class": "GameView",
        "selector": "cancelSecondaryTouch:",
        "types": "v16@0:4{CGPoint=ff}8",
        "disasm": "disasm_gameview_cancelsecondarytouch.txt",
        "start": 0x0092CFA0,
        "code_end": 0x0092D15C,
        "end": 0x0092D188,
        "pic_add": 0x0092CFB0,
        "pic_literal": 0x0092D184,
        "direct_calls": {
            0x0092D110: "World -[cancelTouch:index:] (index literal 1)",
        },
        "indirect_calls": {
            0x0092D024: "World -[loadComplete] via GOT objc_msgSend reload",
            0x0092D070: "World -[isSimulating] via GOT objc_msgSend reload",
        },
        "branches": (
            (0x0092CFE4, 0x0092D134, "beq: secondaryTouchStarted == 0 -> tail clear, no send/latch"),
            (0x0092D030, 0x0092D134, "beq: loadComplete byte == 0 -> tail clear"),
            (0x0092D07C, 0x0092D134, "bne: isSimulating byte != 0 -> tail clear"),
            (0x0092D0A0, 0x0092D0C8, "bne: secondaryTouchIsActiveInUI != 0 -> indexed send"),
            (0x0092D0C4, 0x0092D114, "bne: primaryTouchIsActiveInUI != 0 -> skip send, still clear latch"),
        ),
        "anchors": {
            0x0092CFD8: "ldrsb",
            0x0092D098: "ldrsb",
            0x0092D0BC: "ldrsb",
            0x0092D108: "mov lr, 1",
            0x0092D10C: "str lr, [ip]",
            0x0092D114: "movw r0, 0",
            0x0092D130: "strb",
            0x0092D134: "movw r0, 0",
            0x0092D150: "strb",
        },
        "selector_cells": {
            "loadComplete": (0x0092D164, 0x00E835D0),
            "isSimulating": (0x0092D16C, 0x00E835C8),
            "cancelTouch:index:": (0x0092D17C, 0x00E836C0),
        },
        "ivar_cells": {
            "secondaryTouchStarted": (0x0092D15C, 0x0105E218),
            "world": (0x0092D168, 0x0105E110),
            "secondaryTouchIsActiveInUI": (0x0092D170, 0x0105E214),
            "primaryTouchIsActiveInUI": (0x0092D174, 0x0105E208),
            "secondaryStartTouchHasntMoved": (0x0092D180, 0x0105E21C),
        },
        "ivars": [
            {"name": "secondaryTouchStarted", "offset": 498, "evidence": "OBJC_IVAR_$_GameView.secondaryTouchStarted via GOT slot 0x0105e218"},
            {"name": "world", "offset": 24, "evidence": "OBJC_IVAR_$_GameView.world via GOT slot 0x0105e110"},
            {"name": "secondaryTouchIsActiveInUI", "offset": 508, "evidence": "OBJC_IVAR_$_GameView.secondaryTouchIsActiveInUI via GOT slot 0x0105e214"},
            {"name": "primaryTouchIsActiveInUI", "offset": 496, "evidence": "OBJC_IVAR_$_GameView.primaryTouchIsActiveInUI via GOT slot 0x0105e208"},
            {"name": "secondaryStartTouchHasntMoved", "offset": 497, "evidence": "OBJC_IVAR_$_GameView.secondaryStartTouchHasntMoved via GOT slot 0x0105e21c"},
        ],
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
    for ivar in spec["ivars"]:
        entry = resolved["ivars"].get(ivar["name"])
        if entry and entry["offset"] != ivar["offset"]:
            raise ValueError(f"{spec['selector']}: ivar {ivar['name']} offset drift {entry['offset']}")
    return resolved


def verify_method(memory: ELFMemory, elf_symbols: dict[int, str], spec: dict) -> dict:
    text = (NATIVE / spec["disasm"]).read_text(encoding="utf-8")
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
        "bounded_end": f"0x{spec['end']:08x}",
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

    # Structural mirror vs the pinned primary pair: each secondary method's
    # gate byte is secondaryTouchStarted, its send is the primary pair's
    # selector route with index literal 1, and its tail clear targets the
    # SECONDARY active byte (opposite roles from the primary bodies).
    for spec in METHODS:
        if not any(c["selector_route"].startswith("World -[") for c in
                   [call for call in methods if call["selector"] == spec["selector"]][0]["calls"]):
            raise ValueError(f"{spec['selector']}: missing World forwarding call")
    index_one = all("index literal 1" in call["selector_route"]
                    for m in methods for call in m["calls"]
                    if call["route"] == "bl objc_msgSend@plt")
    if not index_one:
        raise ValueError("secondary indexed forwards must pin literal index 1")
    return {
        "schema": 1,
        "elf_sha256": digest,
        "batch": "GameView secondary end/cancel pair (mirror of the primary pair: secondaryTouchStarted gate, index literal 1, secondary tail clear)",
        "methods": methods,
        "primary_pair_ivar_role_swap": [
            "primary bodies: gate = mainMenuUI/world nil fork, latch = startTouchHasntMoved(486), tail clear = primaryTouchIsActiveInUI(496)",
            "secondary bodies: gate = secondaryTouchStarted(498), latch = secondaryStartTouchHasntMoved(497, cancel only), tail clear = secondaryTouchIsActiveInUI(508)",
            "shared: World loadComplete/isSimulating gates, send iff own-active != 0 OR other-active == 0",
            "index: primary forwards literal 0, secondary forwards literal 1",
        ],
        "replacement_boundary": {
            "host_module": "blockheads_recovered_view",
            "host_test": "tools/test_gameview_secondarytouch.cpp",
            "android_apk_input_path": "GameActivity raw touch handling remains separate and does not invoke these recovered methods",
            "apk_integration": False,
            "original_runtime_differential": False,
        },
        "symbol_mapping_basis": "manual cross-reference to the pinned primary touch ivar/selector cell maps plus the newly resolved OBJC_IVAR_$_GameView.secondaryTouchStarted (offset 498) and secondaryStartTouchHasntMoved (offset 497), each re-verified by this tool's GOT/selref/ivar-symbol walk",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=NATIVE / "gameview_secondarytouch.json")
    args = parser.parse_args()
    result = recover(args.elf)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.output.read_text(encoding="utf-8") != payload:
            raise SystemExit("stale gameview_secondarytouch.json")
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
