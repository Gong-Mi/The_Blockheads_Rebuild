#!/usr/bin/env python3
"""Contract test for the live runtime ivar offsets extracted from the running app.

Validates the 527 live ivar offsets extracted from process memory across the 4 core classes
(Blockhead, DynamicObject, World, DynamicWorld) against the pinned ground truth.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "live_runtime_ivar_offsets.json"

EXPECTED_COUNTS = {
    "total": 527,
    "Blockhead": 221,
    "DynamicObject": 13,
    "World": 227,
    "DynamicWorld": 66,
}

PINNED_OFFSETS = {
    # Blockhead core bones & rendering
    "Blockhead.headCube": 712,
    "Blockhead.bodyCube": 516,
    "Blockhead.armCube": 540,
    "Blockhead.legCube": 496,
    "Blockhead.skinOptions": 200,
    "Blockhead.state": 728,
    "Blockhead.toSquare": 2012,
    "Blockhead.traverseToKeyFrame": 2384,
    "Blockhead.walkTimer": 2365,
    "Blockhead.isInJetPackFreeFlightMode": 2156,
    # DynamicWorld linking
    "DynamicWorld.world": 9496,
    "DynamicWorld.blockheads": 7370,
    "DynamicWorld.dynamicObjects": 2432,
    "DynamicWorld.worldDatabase": 7892,
    "DynamicWorld.worldSaveDirectory": 6084,
    # World persistence & time
    "World.databaseEnvironment": 572,
    "World.mainDatabase": 552,
    "World.blockDatabase": 576,
    "World.dynamicObjectDatabase": 604,
    "World.randomSeed": 3380,
    "World.timeOfDayFraction": 3036,
    "World.saveID": 3460,
    "World.worldWidthMacro": 240,
}


def main() -> int:
    assert JSON_PATH.exists(), f"missing {JSON_PATH}"
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    assert data["ivar_count"] == EXPECTED_COUNTS["total"], data["ivar_count"]
    assert set(data["classes"]) == {"Blockhead", "DynamicObject", "World", "DynamicWorld"}

    offsets = data["offsets"]
    for cls in data["classes"]:
        count = sum(1 for k in offsets if k.startswith(cls + "."))
        assert count == EXPECTED_COUNTS[cls], f"{cls}: got {count}, expected {EXPECTED_COUNTS[cls]}"

    for k, expected_val in PINNED_OFFSETS.items():
        assert k in offsets, f"missing ivar {k}"
        assert offsets[k] == expected_val, f"{k}: got {offsets[k]}, expected {expected_val}"

    print(f"live-runtime-ivars: PASS ({data['ivar_count']} ivars across {len(data['classes'])} classes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
