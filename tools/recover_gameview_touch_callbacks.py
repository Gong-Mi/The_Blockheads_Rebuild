#!/usr/bin/env python3
"""Generate a hash-pinned GameView touch callback evidence manifest."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
METHODS = [
    ("startTouch:withTouch:withEvent:", 0x0092BE2C),
    ("moveTouch:", 0x0092C148),
    ("endTouch:", 0x0092C3F4),
    ("cancelTouch:", 0x0092C638),
    ("startSecondaryTouch:withTouch:withEvent:", 0x0092C89C),
    ("moveSecondaryTouch:", 0x0092CBA8),
    ("endSecondaryTouch:", 0x0092CDD8),
    ("cancelSecondaryTouch:", 0x0092CFA0),
]
ENDS = [x[1] for x in METHODS[1:]] + [0x0092D188]
ROOT = Path(__file__).resolve().parents[1]


def run(cmd):
    return subprocess.check_output(cmd, text=True, errors="replace")


def references(elf, selector):
    out = run([
        "python3", str(ROOT / "tools/extract_objc_references.py"), str(elf),
        "--class", "^GameView$", "--selector", "^" + re.escape(selector) + "$",
        "--output", "/dev/stdout",
    ])
    rows = out.splitlines()
    if not rows:
        return []
    header = rows[0].split("\t")
    return [dict(zip(header, row.split("\t"))) for row in rows[1:] if row.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    ap.add_argument(
        "--output", type=Path,
        default=Path("reconstruction/reverse-v3/native/gameview_touch_callbacks.json"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    blob = args.elf.read_bytes()
    if hashlib.sha256(blob).hexdigest() != SHA:
        raise SystemExit("ELF SHA mismatch")
    records = []
    for (selector, start), end in zip(METHODS, ENDS):
        refs = references(args.elf, selector)
        records.append({
            "class": "GameView",
            "selector": selector,
            "implementation": hex(start),
            "arm_exidx_end": hex(end),
            "instruction_words": (end - start) // 4,
            "selector_references": [r.get("value") for r in refs],
            "reference_count": len(refs),
        })
    result = {
        "schema": 1,
        "elf_sha256": SHA,
        "scope": "static ARM/ObjC evidence; not runtime behavior verification",
        "methods": records,
        "replacement_boundary": {
            "input_state": "Player.inputAxis/jumpRequested",
            "consumer": "EntityManager::update -> Player::update",
            "original_callback_wiring": "pending",
        },
    }
    payload = json.dumps(result, indent=2) + "\n"
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit("stale output")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    print(json.dumps({"methods": len(records), "instruction_words": sum(x["instruction_words"] for x in records), "references": sum(x["reference_count"] for x in records)}))


if __name__ == "__main__":
    main()
