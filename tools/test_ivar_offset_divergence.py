#!/usr/bin/env python3
"""Contract test for the ivar-offset divergence artifact (corrected; no device needed).

Pins the corrected same-build split (3714 identical / 79 rewritten) and forbids a
regression back to the invalid cross-build reading, which claimed almost all cells differ.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "live_ivar_offset_divergence.json"
DOC_PATH = NATIVE / "IVAR_OFFSET_READING.md"
FIELDS_PATH = NATIVE / "live_verified_fields.json"

CELLS_COMPARED = 3793          # OBJC_IVAR_$_ symbols; reproducible from the pinned ELF
CORRECTED_IDENTICAL = 3714
CORRECTED_REWRITTEN = 79
PRIOR_REWRITTEN = 3735         # the invalid cross-build reading, retained as a record


def main() -> int:
    assert JSON_PATH.exists(), f"missing {JSON_PATH}"
    d = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    prior = d["prior_measurement"]
    assert prior["cells_rewritten"] == PRIOR_REWRITTEN, prior
    assert "INVALID" in prior["verdict"], prior

    c = d["corrected_same_build"]
    assert c["cells_compared"] == CELLS_COMPARED, c["cells_compared"]
    assert c["cells_identical"] == CORRECTED_IDENTICAL, c["cells_identical"]
    assert c["cells_rewritten"] == CORRECTED_REWRITTEN, c["cells_rewritten"]
    assert c["cells_identical"] + c["cells_rewritten"] == c["cells_compared"]
    # the corrected reading is "almost all match"; a regression to the invalid
    # "almost all differ" reading must fail loudly
    assert c["cells_rewritten"] < 0.1 * c["cells_compared"], c
    assert len(c["rewritten_list"]) == CORRECTED_REWRITTEN
    names = [r["ivar"] for r in c["rewritten_list"]]
    assert len(set(names)) == CORRECTED_REWRITTEN
    # no game-class cell may be in the rewritten set
    for n in names:
        assert not n.startswith(("World.", "DynamicWorld.", "Blockhead.", "DynamicObject.")), n

    assert len(d["correction_evidence"]) >= 2, d.get("correction_evidence")
    assert d["verified_fields_artifact"] == "live_verified_fields.json"

    assert FIELDS_PATH.exists(), f"missing {FIELDS_PATH}"
    f = json.loads(FIELDS_PATH.read_text(encoding="utf-8"))
    assert f["verified_field_count"] == len(f["verified_fields"]) == 153, f["verified_field_count"]

    doc = DOC_PATH.read_text(encoding="utf-8")
    for needle in ("cross-build misread", "3714", "instance discovery",
                   "live_verified_fields.json"):
        assert needle in doc, f"doc needle missing: {needle}"

    tool = ROOT / "tools/probe_live_ivar_offsets.py"
    assert tool.exists(), f"missing {tool}"
    tsrc = tool.read_text(encoding="utf-8")
    assert "BUILD MISMATCH" in tsrc, "the build-identity guard is gone"

    print(f"ivar-offset-divergence: PASS (corrected {c['cells_identical']}/"
          f"{c['cells_compared']} identical; prior invalid reading retained as record)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
