#!/usr/bin/env python3
"""Byte-gate the bounded GameView/World primary move-touch source batch.

This verifies the checked-in instruction listings against one SHA-pinned ELF,
then checks the complete call/branch-site sets and records the hand-reviewed
receiver/selector map. It does not resolve new Objective-C symbols, emulate the
runtime, or claim APK integration.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
SHA256 = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
MSGSEND_STUB = 0x001C281C
PIC_BASE = 0x0105FAF4

METHODS = (
    {
        "class": "GameView",
        "selector": "moveTouch:",
        "types": "v16@0:4{CGPoint=ff}8",
        "start": 0x0092C148,
        "code_end": 0x0092C3C0,
        "end": 0x0092C3F4,
        "pic_add": 0x0092C158,
        "pic_literal": 0x0092C3F0,
        "direct_calls": {
            0x0092C1F8: "mainMenuUI -[moveTouch:]",
            0x0092C304: "World -[moveTouch:index:] (index literal 0)",
        },
        "indirect_calls": {
            0x0092C23C: "World -[loadComplete]",
            0x0092C288: "World -[isSimulating]",
        },
        "branches": (
            (0x0092C190, 0x0092C200, "beq: mainMenuUI == nil -> World path"),
            (0x0092C1B8, 0x0092C200, "bne: world != nil -> World path"),
            (0x0092C1FC, 0x0092C3B8, "b: menu callback done -> epilogue"),
            (0x0092C248, 0x0092C3B4, "beq: loadComplete byte == 0 -> return"),
            (0x0092C294, 0x0092C3B4, "bne: isSimulating byte != 0 -> return"),
            (0x0092C2B8, 0x0092C308, "beq: primaryTouchIsActiveInUI == 0 -> skip indexed send"),
            (0x0092C348, 0x0092C390, "bgt: abs(deltaX) > 2.0 -> clear latch"),
            (0x0092C38C, 0x0092C3B0, "ble: abs(deltaY) <= 2.0 or unordered -> preserve latch"),
            (0x0092C3B0, 0x0092C3B4, "b: join"),
            (0x0092C3B4, 0x0092C3B8, "b: epilogue"),
        ),
        "anchors": {
            0x0092C330: "vsub.f32",
            0x0092C2FC: "mov lr, 0",
            0x0092C300: "str lr, [ip]",
            0x0092C30C: "vmov.f64 d0, 2",
            0x0092C334: "vcvt.f64.f32",
            0x0092C338: "vabs.f64",
            0x0092C33C: "vcmpe.f64",
            0x0092C350: "vmov.f64 d0, 2",
            0x0092C374: "vsub.f32",
            0x0092C378: "vcvt.f64.f32",
            0x0092C37C: "vabs.f64",
            0x0092C380: "vcmpe.f64",
            0x0092C390: "movw r0, 0",
            0x0092C3AC: "strb",
        },
        "ivars": [
            {"name": "mainMenuUI", "offset": 20, "evidence": "previous hash-pinned GameView start-touch map"},
            {"name": "world", "offset": 24, "evidence": "previous hash-pinned GameView start-touch map"},
            {"name": "primaryTouchIsActiveInUI", "offset": 496, "evidence": "previous hash-pinned GameView start/cancel-touch maps"},
            {"name": "startTouchPos", "offset": 488, "evidence": "previous hash-pinned GameView start-touch map"},
            {"name": "startTouchHasntMoved", "offset": 486, "evidence": "previous hash-pinned GameView start/cancel-touch maps"},
        ],
    },
    {
        "class": "World",
        "selector": "moveTouch:index:",
        "types": "v20@0:4{CGPoint=ff}8i16",
        "start": 0x005B3278,
        "code_end": 0x005B32FC,
        "end": 0x005B3308,
        "pic_add": 0x005B32A8,
        "pic_literal": 0x005B3300,
        "direct_calls": {
            0x005B32F0: "UIManager -[moveTouch:index:]",
        },
        "indirect_calls": {},
        "branches": (),
        "anchors": {
            0x005B3284: "ldr ip, [fp, 8]",
            0x005B32E0: "str r1, [lr]",
            0x005B32F0: "bl",
        },
        "ivars": [
            {"name": "uiManager", "offset": 240, "evidence": "hash-pinned World start-touch map"},
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


def verify_method(memory: ELFMemory, spec: dict) -> dict:
    name = spec["selector"].split(":", 1)[0].lower()
    disasm_path = NATIVE / f"disasm_{spec['class'].lower()}_{name}.txt"
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

    calls = []
    for address, description in spec["direct_calls"].items():
        calls.append({"site": f"0x{address:08x}", "route": "bl objc_msgSend@plt",
                      "target": f"0x{MSGSEND_STUB:08x}", "selector_route": description})
    for address, description in spec["indirect_calls"].items():
        calls.append({"site": f"0x{address:08x}", "route": "blx r2 via objc_msgSend GLOB_DAT",
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
        "ivars": spec["ivars"],
        "claim": "bounded static method map + typed host snapshot; dynamic ObjC callees and original runtime are not verified",
    }


def recover(elf_path: Path) -> dict:
    blob = elf_path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != SHA256:
        raise ValueError(f"ELF SHA-256 mismatch: {digest}")
    memory = ELFMemory(elf_path)
    methods = [verify_method(memory, spec) for spec in METHODS]
    return {
        "schema": 1,
        "elf_sha256": digest,
        "batch": "GameView moveTouch: -> World moveTouch:index: forwarding tail",
        "methods": methods,
        "replacement_boundary": {
            "host_module": "blockheads_recovered_view",
            "host_test": "tools/test_gameview_movetouch.cpp",
            "android_apk_input_path": "GameActivity.onScroll -> handlePanNative remains separate and does not invoke these recovered methods",
            "apk_integration": False,
            "original_runtime_differential": False,
        },
        "symbol_mapping_basis": "manual cross-reference to the existing pinned startTouch/cancelTouch ivar maps and the checked-in ObjC method table; this generator verifies instruction bytes/call/branch sets but does not redo that symbol-resolution pass",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=NATIVE / "gameview_movetouch.json")
    args = parser.parse_args()
    result = recover(args.elf)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.check:
        if args.output.read_text(encoding="utf-8") != payload:
            raise SystemExit("stale gameview_movetouch.json")
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
