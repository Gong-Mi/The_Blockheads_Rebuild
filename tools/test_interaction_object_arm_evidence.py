#!/usr/bin/env python3
"""CI-safe guard for the InteractionObject init executed differential
(see reconstruction/reverse-v3/native/INTERACTION_OBJECT_INIT_ARM.md).

CI mode (no ELF): asserts the contract surfaces, the case table, the two
differential-caught facts (the third tail gate, the -1 default store), the
CMake registration and the harness's presence.
Host mode (--elf <pinned ELF>, needs Unicorn): runs the differential
itself and requires all 8 cases to match.
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"


def require(path: Path, needles) -> None:
    text = path.read_text()
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{path.name} misses: {needle}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path)
    a = ap.parse_args()

    # contract + the two differential-caught facts
    require(ROOT / "reconstruction/recovered/interaction_object_init.cpp", [
        "0xFFFFFFFFu",          # the unconditional -1 default store @80
        "current_owner_name == 0",  # the third tail gate (ownerName == nil)
        "current_owner_id != 0",
        "in.is_server",
    ])
    require(ROOT / "reconstruction/recovered/interaction_object_init.h", [
        "kInteractionImageSize = 96",
        "ObjectForKeyCurrentBlockheadIndexProbe",
        "RetainResolvedOwnerName",
    ])
    # the harness carries the same case count and the ELF pin
    require(ROOT / "tools/test_interaction_object_arm.py", [
        ELF_SHA, "0x005F4634", "SUPERREF_SLOT", "blockhead_reads",
    ])
    require(ROOT / "tools/interaction_object_arm_bridge.cpp", [
        "0x60001060u",  # the boxed-token convention
        "case 7",
    ])
    # CMake registration of the contract test
    require(ROOT / "reconstruction/recovered/CMakeLists.txt", [
        "recovered_interaction_object_init",
    ])

    if a.elf is not None:
        out = ROOT / "build-interaction-evidence"
        proc = subprocess.run([sys.executable,
                               str(ROOT / "tools/test_interaction_object_arm.py"),
                               str(a.elf), "--output-dir", str(out)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            return 1
        print("interaction-init-arm: PASS (differential executed, all cases match)")
        return 0
    print("interaction-init-arm: PASS (constants; run with --elf to execute)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
