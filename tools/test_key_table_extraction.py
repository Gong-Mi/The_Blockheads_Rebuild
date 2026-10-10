#!/usr/bin/env python3
"""CI-safe guard for the execution-based key-table extractor.

The extractor is tools/test_specials_arm.py's --emit-spec mode: run the
original body under Unicorn, hook the instance writes, and value-pair each
conversion with its store (width-aware; pre-block writes fall out as
defaults).

CI mode (no ELF): asserts the extractor surfaces exist (the mode, the
value-pairing constants, the mid-tier ENTRIES rows) and that the ground-truth
tables this guard pins are the ones the ARM bridges carry.
Host mode (--elf): extracts three classes and compares every row against the
embedded ARM-verified ground truth.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ARM-verified ground truth (the midtier bridge rows; the same data the
# differentials pinned — extraction must reproduce it):
GROUND_TRUTH = {
    "Ladder": [("itemType", "Int", 4, 56), ("paintColor", "UInt", 2, 60),
               ("ownerID", "Object", 4, 36)],
    "Rail": [("itemType", "Int", 4, 56), ("ownedByStation", "Bool", 1, 65),
             ("configuration", "Int", 4, 60)],
    "Wire": [("itemType", "Int", 4, 56), ("configuration", "Int", 4, 60),
             ("solidConfiguration", "Int", 4, 64), ("ownerID", "Object", 4, 36)],
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path)
    a = ap.parse_args()
    harness = (ROOT / "tools/test_specials_arm.py").read_text()
    for needle in ("--emit-spec", "UC_HOOK_MEM_WRITE",
                   "match = 0x5E1B0000 <= val < 0x5E1C0000",
                   "expect = {'Int': 0x00012345", "('Ladder', 19,"):
        if needle not in harness:
            raise SystemExit(f"harness misses extractor surface: {needle}")
    for cls in GROUND_TRUTH:
        if not re.search(rf"['\"]{cls}['\"]", harness):
            raise SystemExit(f"harness misses the {cls} ENTRIES row")
    # the ground truth must be the module's own tables (the midtier bridge is
    # table-driven FROM midtier_full.{h,cpp})
    module = (ROOT / "reconstruction/recovered/midtier_full.cpp").read_text()
    for key in ("paintColor", "ownedByStation", "solidConfiguration"):
        if key not in module:
            raise SystemExit(f"midtier module misses {key}")

    if a.elf is None or not a.elf.exists():
        print("key-table-extraction: PASS (constants; run with --elf to execute)")
        return 0

    out = ROOT / "build-spec-extraction"
    out.mkdir(exist_ok=True)
    for cls, rows in GROUND_TRUTH.items():
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/test_specials_arm.py"),
             str(a.elf), "--output-dir", str(out), "--emit-spec", cls],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            return 1
        spec = json.loads((out / f"spec_{cls}.json").read_text())
        got = [(k["key"], k["conv"], k["width"], k["offset"])
               for k in spec["keys"]]
        if got != rows:
            print(f"{cls}: extraction mismatch\n  got      {got}\n"
                  f"  expected {rows}")
            return 1
    print("key-table-extraction: PASS (3 classes match the ARM ground truth)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
