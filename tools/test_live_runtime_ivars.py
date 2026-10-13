#!/usr/bin/env python3
"""Contract test for the corrected live runtime ivar offsets (no device needed).

Pins the corrected 527-value table and the object-graph-verified sample; the values the
first (invalid) table claimed must never come back.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "live_runtime_ivar_offsets.json"
FIELDS_PATH = NATIVE / "live_verified_fields.json"

EXPECTED_COUNTS = {
    "total": 527,
    "Blockhead": 221,
    "DynamicObject": 13,
    "World": 227,
    "DynamicWorld": 66,
}

# live object-graph verified (2026-10-02; see live_verified_fields.json)
VERIFIED_OFFSETS = {
    "Blockhead.headCube": 212,
    "Blockhead.bodyCube": 228,
    "Blockhead.armCube": 236,
    "Blockhead.legCube": 244,
    "DynamicObject.world": 4,
    "DynamicObject.dynamicWorld": 8,
    "DynamicWorld.world": 4,
    "DynamicWorld.blockheads": 44,
    "DynamicWorld.worldDatabase": 32,
    "DynamicWorld.worldSaveDirectory": 40,
    "World.saveID": 436,
    "World.worldName": 440,
    "World.dynamicWorld": 416,
    "World.uiManager": 240,
}

# values the invalid cross-build table claimed; they must never come back
FORMER_BAD_VALUES = {
    "Blockhead.headCube": 712,
    "Blockhead.state": 728,
    "World.saveID": 3460,
    "DynamicWorld.world": 9496,
    "DynamicWorld.blockheads": 7370,
}

VERIFIED_LIVE_COUNT = 90


def main() -> int:
    assert JSON_PATH.exists(), f"missing {JSON_PATH}"
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    assert "corrected" in data["status"], data["status"]
    assert data["ivar_count"] == EXPECTED_COUNTS["total"], data["ivar_count"]
    assert set(data["classes"]) == {"Blockhead", "DynamicObject", "World", "DynamicWorld"}

    offsets = data["offsets"]
    for cls in data["classes"]:
        count = sum(1 for k in offsets if k.startswith(cls + "."))
        assert count == EXPECTED_COUNTS[cls], f"{cls}: got {count}, expected {EXPECTED_COUNTS[cls]}"

    for k, expected_val in VERIFIED_OFFSETS.items():
        assert k in offsets, f"missing ivar {k}"
        assert offsets[k] == expected_val, f"{k}: got {offsets[k]}, expected {expected_val}"

    for k, bad in FORMER_BAD_VALUES.items():
        assert offsets.get(k) != bad, f"{k}: the invalid cross-build value {bad} is back"

    verified_live = data["verified_live"]
    assert len(verified_live) == VERIFIED_LIVE_COUNT, len(verified_live)
    for n in verified_live:
        assert n in offsets, f"verified_live name missing from offsets: {n}"

    assert FIELDS_PATH.exists(), f"missing {FIELDS_PATH}"
    f = json.loads(FIELDS_PATH.read_text(encoding="utf-8"))
    assert f["verified_field_count"] == 153, f["verified_field_count"]
    assert len(f["instances"]) >= 5, f["instances"]

    print(f"live-runtime-ivars: PASS ({data['ivar_count']} ivars across "
          f"{len(data['classes'])} classes; {len(verified_live)} object-graph verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
