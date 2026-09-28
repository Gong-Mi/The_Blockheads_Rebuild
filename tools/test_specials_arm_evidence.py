#!/usr/bin/env python3
"""CI-safe guard for the specials executed differential
(tools/test_specials_arm.py + tools/specials_arm_bridge.cpp).

CI mode (no ELF): asserts the module/bridge surfaces the differential pinned
(SteamTrain's own body has no hook; OwnershipSign's default-15 radii, the
[1,30] clamp and the ID-gated object block), the harness table and the CMake
registration. Host mode (--elf <pinned ELF>, needs Unicorn): runs the
differential itself and requires all modelled cases to match.
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

    # the module carries the ARM-attested OwnershipSign facts
    require(ROOT / "reconstruction/recovered/ownershipsign_full.h", [
        "kOwnershipDefaultRadius = 15",
        "kOwnershipRadiusMin = 1",
        "kOwnershipRadiusMax = 30",
        "ownershipClampRadius",
    ])
    require(ROOT / "reconstruction/recovered/ownershipsign_full.cpp", [
        "state.has_land_owner_name =",
        "id_present &&",
        "EXECUTED differential",
    ])
    # the bridge pins both modelled classes and their semantics
    require(ROOT / "tools/specials_arm_bridge.cpp", [
        "{42, kSteamTrain, 4, nullptr, \"\", false, 0, 0, 0}",
        "{60, kOwnershipSign, 4, nullptr, \"updateText\", true, 15, 1, 30}",
        "0x4BE068",
        "movw lr, #0xf",
    ])
    # the harness pins the ELF + the five entries
    require(ROOT / "tools/test_specials_arm.py", [
        ELF_SHA,
        "0x00D18834",  # SteamTrain
        "0x00A34B18",  # OwnershipSign
        "0x00AA81E8",  # Painting
        "0x0079D538",  # DropBear
        "0x00D538CC",  # CaveTroll
    ])
    # CMake registration
    require(ROOT / "reconstruction/recovered/CMakeLists.txt",
            ["specials_arm_evidence"])

    if a.elf is not None:
        out = ROOT / "build-specials-evidence"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/test_specials_arm.py"),
             str(a.elf), "--output-dir", str(out)],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            return 1
        print("specials-arm: PASS (differential executed, modelled cases match)")
        return 0

    print("specials-arm: PASS (constants; run with --elf to execute)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
