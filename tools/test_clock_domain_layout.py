#!/usr/bin/env python3
"""Contract test for the derived clock/weather domain map.

The map is only worth having if it is re-derived rather than trusted, so this test re-runs the
derivation for every entry and compares slot, cell and offset, and it re-reads the writer's literal.
It also pins the two facts that would otherwise rot into folklore: the adjacent
`simulationProgress`/`isSimulating` offsets, and the writer writing 0.0f.

Self-skips when the pinned ELF is absent.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
ART = ROOT / "reconstruction/reverse-v3/native/clock_domain_layout.json"


def main() -> int:
    import struct
    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    if not pinned.is_file():
        print("skip: pinned ELF not present")
        return 0
    from emulate_float_getters import derive
    blob = pinned.read_bytes()
    rep = json.loads(ART.read_text())
    for row in rep["fields"]:
        d = derive(blob, int(row["imp"], 16))
        assert row["slot"] == hex(d["slot"]), row
        assert row["cell"] == hex(d["cell"]), row
        assert row["offset"] == d["offset"], row
    by = {r["field"]: r["offset"] for r in rep["fields"]}
    assert by["isSimulating"] - by["simulationProgress"] == 4, by
    w = rep["writer"]
    assert w["writes_constant"] == 0.0, w
    assert struct.unpack_from("<I", blob, w["imp"] and 0x5AC390)[0] == 0x00000000, "literal must be zero"
    assert w["to_offset"] > 0
    print(f"domain map re-derived: {len(rep['fields'])} fields, writer stores {w['writes_constant']} "
          f"to offset {w['to_offset']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
