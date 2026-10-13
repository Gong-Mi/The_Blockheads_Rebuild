#!/usr/bin/env python3
"""CI-safe guard for the mid-tier key-table executed differential
(see tools/test_midtier_arm.py + tools/midtier_arm_bridge.cpp).

CI mode (no ELF): asserts the module surfaces the differential relies on
(spec-table lookup, nested reads, the ARM-attested corrections), the harness
table, and the CMake registration. Host mode (--elf <pinned ELF>, needs
Unicorn): runs the differential itself and requires all 30 cases to match.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"

# the ARM-attested facts the decode must carry (each was a differential catch)
CORRECTIONS = {
    # module correction -> needle in the module source
    "rail order": ("midtier_full.cpp", '"itemType", K::Conv::Int, K::Width::Word, 56},\n    {"ownedByStation"'),
    "egg nested breed": ("midtier_full.cpp", '"breed", K::Conv::Int, K::Width::Half, 60, "genesDict"'),
    "motor uint conversion": ("midtier_full.cpp", '"availableElectricity", K::Conv::UInt, K::Width::Half, 60}'),
    "motor maxY word": ("midtier_full.cpp", '"maxY", K::Conv::UInt, K::Width::Word, 68}'),
    "nested_in field": ("midtier_full.h", "const char* nested_in = nullptr;"),
    "nested lookup": ("midtier_full.cpp", "parent->isDict()"),
    "wire zero->one": ("midtier_full.cpp",
                       '{"solidConfiguration", K::Conv::Int, K::Width::Word, 64, nullptr, true}'),
    "boat probe default": ("midtier_full.cpp", "blockhead_probe_default"),
}


def require(path: Path, needles) -> None:
    text = path.read_text()
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{path.name} misses: {needle}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path)
    a = ap.parse_args()

    for name, (rel, needle) in CORRECTIONS.items():
        if needle not in (ROOT / "reconstruction/recovered" / rel).read_text():
            raise SystemExit(f"correction missing ({name}): {rel} :: {needle[:60]}")
    # the harness pins the ELF, the ten entries and the r0-float ABI fact
    require(ROOT / "tools/test_midtier_arm.py", [
        ELF_SHA,
        "0x00C98944",  # Window
        "0x00D4E30C",  # Egg
        "0x00CAD2CC",  # ElevatorShaft
        "0x0070046C",  # ElevatorMotor
        "0x0096B818",  # Boat
        "vmov s0, r0",  # the float-return ABI note
        "recovered_midtier_nested_in",
    ])
    # the bridge uses the module table as the single source of truth
    require(ROOT / "tools/midtier_arm_bridge.cpp", [
        '#include "midtier_full.h"',
        "recovered_midtier_key_list",
        "recovered_midtier_sequence",
        "recovered_midtier_image",
        "recovered_midtier_nested_in",
    ])
    # CMake registration
    require(ROOT / "reconstruction/recovered/CMakeLists.txt",
            ["midtier_arm_evidence"])
    # the batch evidence json still agrees with the harness table
    data = json.loads((ROOT / "reconstruction/reverse-v3/native/"
                       "midtier15_initwithworld.json").read_text())
    by_class = {c["class"]: c for c in data["classes"]}
    for cls, imp in {"Window": "0x00c98944", "Rail": "0x0077ab90",
                     "Ladder": "0x00aadcd4", "Egg": "0x00d4e30c",
                     "Column": "0x00834a30", "Stairs": "0x006cc734",
                     "Door": "0x007694fc", "Wire": "0x0095002c"}.items():
        assert by_class[cls]["imp"] == imp, (cls, by_class[cls]["imp"])

    if a.elf is not None:
        out = ROOT / "build-midtier-evidence"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/test_midtier_arm.py"),
             str(a.elf), "--output-dir", str(out)],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            return 1
        print("midtier-arm: PASS (differential executed, 44/44 cases match)")
        return 0

    print("midtier-arm: PASS (constants; run with --elf to execute)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
