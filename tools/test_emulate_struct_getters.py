#!/usr/bin/env python3
"""Contract test for tools/emulate_struct_getters.py.

Pins the three things that would silently rot:
  * all three struct getters execute with provenance, and each row records WHICH control it used -
    because two of them use a same-width value comparison and the third cannot;
  * the stret ABI stays fixed (self in r1, not r0) - the failure it causes looks like a bad offset;
  * widths stay parsed from the type encoding and checked against the observed copy length.

Self-skips when the pinned ELF is absent.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/struct_getter_emulation.json"


def main() -> int:
    tool = (ROOT / "tools/emulate_struct_getters.py").read_text()
    assert "r0 = hidden return buffer" in tool and "r1 = self" in tool, "stret ABI must stay documented"
    assert "UC_ARM_REG_R1, OBJ" in tool, "self must be passed in r1 for struct returns"
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    rep = json.loads(ART.read_text())
    by = {r["field"]: r for r in rep["results"]}
    assert set(by) == {"translation", "highestPoint", "sunDirection"}, sorted(by)
    assert all(r["status"] == "executed" for r in by.values()), by
    assert by["translation"]["width_from_type"] == 8 and by["sunDirection"]["width_from_type"] == 16
    assert by["sunDirection"]["shape"] == "copy-stub", by["sunDirection"]
    assert by["sunDirection"]["cross_control"]["control_kind"] == "source-address-follows-cell"
    assert by["sunDirection"]["cross_control"]["source_followed"] is True
    for name in ("translation", "highestPoint"):
        assert by[name]["cross_control"]["control_kind"] == "same-width-value", name
        assert by[name]["positive"]["source"] == by[name]["positive"]["expected_source"], name
    assert by["translation"]["symbol_cell_agrees"] is None, "World.translation has no ivar symbol"
    print(f"struct getters: {len(by)} executed, "
          f"{sum(1 for r in by.values() if r['positive']['bit_exact'])} byte-exact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
