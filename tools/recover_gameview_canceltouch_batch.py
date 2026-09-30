#!/usr/bin/env python3
"""Byte-gate the bounded GameView/World cancel-touch source batch.

Verifies the checked-in GameView -[cancelTouch:] listing against the SHA-pinned
ELF (extending the existing hand-reviewed static map with the same full
word/branch/call gates as the move/endTouch batches), and the World
-[cancelTouch:index:] forwarding listing including the tail-merge evidence
that its body is byte-identical to -[endTouch:index:] apart from the
wasCancelled literal. The two World listings carry literal pools that r2's
ARM.exidx unwind merge into one span; this tool pins each function to its own
pool end (cancelTouch:index: ends at 0x005b3430, endTouch:index: at
0x005b34b4) and re-resolves every selector/ivar cell through the GOT.

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
        "selector": "cancelTouch:",
        "types": "v16@0:4{CGPoint=ff}8",
        "disasm": "disasm_gameview_canceltouch.txt",
        "start": 0x0092C638,
        "code_end": 0x0092C868,
        "end": 0x0092C89C,
        "pic_add": 0x0092C648,
        "pic_literal": 0x0092C898,
        "direct_calls": {
            0x0092C6E8: "mainMenuUI -[endTouch:] (menu path sends end, not cancel)",
            0x0092C818: "World -[cancelTouch:index:] (index literal 0)",
        },
        "indirect_calls": {
            0x0092C72C: "World -[loadComplete] via GOT objc_msgSend reload",
            0x0092C778: "World -[isSimulating] via GOT objc_msgSend reload",
        },
        "branches": (
            (0x0092C680, 0x0092C6F0, "beq: mainMenuUI == nil -> World path"),
            (0x0092C6A8, 0x0092C6F0, "bne: world != nil -> World path"),
            (0x0092C6EC, 0x0092C840, "b: menu endTouch: send done -> shared tail"),
            (0x0092C738, 0x0092C83C, "beq: loadComplete byte == 0 -> tail, no send"),
            (0x0092C784, 0x0092C83C, "bne: isSimulating byte != 0 -> tail, no send"),
            (0x0092C7A8, 0x0092C7D0, "bne: primaryTouchIsActiveInUI != 0 -> indexed send"),
            (0x0092C7CC, 0x0092C81C, "bne: secondaryTouchIsActiveInUI != 0 -> skip send, "
                                     "still clear startTouchHasntMoved"),
            (0x0092C83C, 0x0092C840, "b: join -> shared tail"),
        ),
        "anchors": {
            0x0092C64C: "movw lr, 0",
            0x0092C72C: "blx r2",
            0x0092C778: "blx r2",
            0x0092C7A0: "ldrsb",
            0x0092C7C4: "ldrsb",
            0x0092C810: "mov lr, 0",
            0x0092C814: "str lr, [ip]",
            0x0092C838: "strb",
            0x0092C840: "movw r0, 0",
            0x0092C85C: "strb",
        },
        "selector_cells": {
            "endTouch:": (0x0092C874, 0x00E836B8),
            "loadComplete": (0x0092C87C, 0x00E835D0),
            "isSimulating": (0x0092C880, 0x00E835C8),
            "cancelTouch:index:": (0x0092C890, 0x00E836C0),
        },
        "ivar_cells": {
            "mainMenuUI": (0x0092C868, 0x0105E168),
            "world": (0x0092C86C, 0x0105E110),
            "primaryTouchIsActiveInUI": (0x0092C884, 0x0105E208),
            "secondaryTouchIsActiveInUI": (0x0092C888, 0x0105E214),
            "startTouchHasntMoved": (0x0092C894, 0x0105E20C),
        },
        "ivars": [
            {"name": "mainMenuUI", "offset": 20, "evidence": "OBJC_IVAR_$_GameView.mainMenuUI via GOT slot 0x0105e168"},
            {"name": "world", "offset": 24, "evidence": "OBJC_IVAR_$_GameView.world via GOT slot 0x0105e110"},
            {"name": "primaryTouchIsActiveInUI", "offset": 496, "evidence": "OBJC_IVAR_$_GameView.primaryTouchIsActiveInUI via GOT slot 0x0105e208"},
            {"name": "secondaryTouchIsActiveInUI", "offset": 508, "evidence": "OBJC_IVAR_$_GameView.secondaryTouchIsActiveInUI via GOT slot 0x0105e214"},
            {"name": "startTouchHasntMoved", "offset": 486, "evidence": "OBJC_IVAR_$_GameView.startTouchHasntMoved via GOT slot 0x0105e20c"},
        ],
    },
    {
        "class": "World",
        "selector": "cancelTouch:index:",
        "types": "v20@0:4{CGPoint=ff}8i16",
        "disasm": "disasm_world_canceltouch_index.txt",
        "start": 0x005B33AC,
        "code_end": 0x005B3428,
        "end": 0x005B3430,
        "pic_add": 0x005B33F0,
        "pic_literal": 0x005B342C,
        "direct_calls": {
            0x005B341C: "self -[doEndTouch:wasCancelled:index:] (wasCancelled literal 1, index preserved from stack)",
        },
        "indirect_calls": {},
        "branches": (),
        "anchors": {
            0x005B33B8: "ldr ip, [fp, 8]",
            0x005B3404: "str r1, [lr, 4]",
            0x005B3408: "mov r1, 1",
            0x005B340C: "str r1, [lr]",
        },
        "selector_cells": {
            "doEndTouch:wasCancelled:index:": (0x005B3428, 0x00E7E528),
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


def tail_merge_check(memory: ELFMemory) -> bool:
    """World -[cancelTouch:index:] (0x005b33ac) and -[endTouch:index:]
    (0x005b3430) bodies are byte-identical over their 30-word code intervals
    except: offset +0x5c (wasCancelled `mov r1, 1` vs `mov r1, 0`) and offset
    +0x70 (the bl whose displacement encodes the SAME objc_msgSend stub from a
    different site). The pool cells are word-identical pc-relative encodings.
    Any other drift means the tail-merge reading of the forwarding pair is
    wrong and this batch must stop."""
    cancel = [memory.word(0x005B33AC + i) for i in range(0, 30 * 4, 4)]
    end = [memory.word(0x005B3430 + i) for i in range(0, 30 * 4, 4)]
    diffs = {i for i in range(30) if cancel[i] != end[i]}
    if diffs != {23, 28}:
        raise ValueError(f"tail-merge assumption broken at offsets {sorted(diffs)}")
    if cancel[23] != 0xE3A01001 or end[23] != 0xE3A01000:
        raise ValueError("wasCancelled mov pair is not pinned `mov r1, 1` / `mov r1, 0`")
    for site, word in ((0x005B341C, cancel[28]), (0x005B34A0, end[28])):
        if branch_target(site, word) != MSGSEND_STUB:
            raise ValueError("forwarding-pair bl sites no longer share the msgSend stub")
    return True


def recover(elf_path: Path) -> dict:
    blob = elf_path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != SHA256:
        raise ValueError(f"ELF SHA-256 mismatch: {digest}")
    memory = ELFMemory(elf_path)
    if memory.imports.get(MSGSEND_GOT_SLOT) != "objc_msgSend":
        raise ValueError("msgSend GOT reload slot evidence changed")
    tail_merge = tail_merge_check(memory)
    elf = ELFFile(io.BytesIO(blob))
    elf_symbols = {s["st_value"]: s.name
                   for s in elf.get_section_by_name(".dynsym").iter_symbols()}
    methods = [verify_method(memory, elf_symbols, spec) for spec in METHODS]
    return {
        "schema": 1,
        "elf_sha256": digest,
        "batch": "GameView cancelTouch: -> World cancelTouch:index: -> doEndTouch:wasCancelled:1 (tail-merge of the World forwarding pair)",
        "methods": methods,
        "world_forwarding_pair_tail_merge": tail_merge,
        "replacement_boundary": {
            "host_module": "blockheads_recovered_view",
            "host_test": "tools/test_gameview_canceltouch.cpp",
            "android_apk_input_path": "GameActivity.onScroll -> handlePanNative remains separate and does not invoke these recovered methods",
            "apk_integration": False,
            "original_runtime_differential": False,
        },
        "symbol_mapping_basis": "manual cross-reference to the existing pinned startTouch/moveTouch/endTouch/cancelTouch ivar maps, the checked-in ObjC method table, and a per-cell GOT/selref/ivar-symbol resolution re-verified against this ELF by recover()",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=NATIVE / "gameview_canceltouch_batch.json")
    args = parser.parse_args()
    result = recover(args.elf)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.output.read_text(encoding="utf-8") != payload:
            raise SystemExit("stale gameview_canceltouch_batch.json")
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
