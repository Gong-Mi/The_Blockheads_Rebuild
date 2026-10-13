#!/usr/bin/env python3
"""CI-safe guard for the forwarder5b executed differential
(see tools/test_forwarder5b_arm.py + the batch evidence json).

CI mode (no ELF): asserts the contract surfaces, the per-class superref cells,
the hook split, the batch evidence json and the CMake registration.
Host mode (--elf <pinned ELF>, needs Unicorn): runs the differential itself and
requires all 10 cases to match.
"""
import argparse
import json
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

    # the contract carries the hook split (super-only vs hook-carrying)
    require(ROOT / "reconstruction/recovered/object_forwarder_init.h", [
        "bool hook_present = true;",
        "forwarder5b",
    ])
    require(ROOT / "reconstruction/recovered/object_forwarder_init.cpp", [
        "if (inputs.hook_present)",
    ])
    # the bridge keeps the b3f ABI and adds the hook-aware variant
    require(ROOT / "tools/object_forwarder_init_arm_bridge.cpp", [
        "recovered_forwarder_trace_ex",
        "recovered_forwarder_trace(std::int32_t super_returns_nil) {",
    ])
    # the harness pins the ELF and the five per-class cells
    require(ROOT / "tools/test_forwarder5b_arm.py", [
        ELF_SHA,
        "0x00E8BD70",  # SurfaceBlock superref
        "0x00E8BF38",  # SnowSurfaceBlock superref
        "0x00E8BE2C",  # HandCar superref
        "0x00E8BD78",  # PassengerCar superref
        "0x00E8BE5C",  # Mirror superref
        "initSubDerivedItems",
        "instance_window_zero",
    ])
    # the batch evidence json still agrees with the harness table
    data = json.loads((ROOT / "reconstruction/reverse-v3/native/"
                       "forwarder5b_initwithworld.json").read_text())
    by_class = {c["class"]: c for c in data["classes"]}
    expect = {"SurfaceBlock": "0x00812e64", "SnowSurfaceBlock": "0x00d8d89c",
              "HandCar": "0x00a4f564", "PassengerCar": "0x0081bcc8",
              "Mirror": "0x00a9f434"}
    for cls, imp in expect.items():
        assert by_class[cls]["imp"] == imp, (cls, by_class[cls]["imp"])
    assert by_class["SurfaceBlock"]["hook"] is None
    assert by_class["PassengerCar"]["hook"] is None
    assert by_class["HandCar"]["hook"] is None
    assert by_class["Mirror"]["hook"]["selector"] == "initSubDerivedItems"
    assert (by_class["SnowSurfaceBlock"]["hook"]["selector"] ==
            "initSubDerivedItems")
    # CMake registration of the differential guard
    require(ROOT / "reconstruction/recovered/CMakeLists.txt",
            ["forwarder5b_arm_evidence"])

    if a.elf is not None:
        out = ROOT / "build-forwarder5b-evidence"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/test_forwarder5b_arm.py"),
             str(a.elf), "--output-dir", str(out)],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            return 1
        print("forwarder5b-arm: PASS (differential executed, all cases match)")
        return 0

    print("forwarder5b-arm: PASS (constants; run with --elf to execute)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
