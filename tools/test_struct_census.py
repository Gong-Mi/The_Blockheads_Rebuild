#!/usr/bin/env python3
"""Contract test for the struct census: there is exactly one parser, and it is the tool.

An earlier version of this test carried its own copy of the parse and the two copies disagreed about nested
pointer types, so the census read 43 structs in one place and 30 in the other. The test therefore does not
parse anything itself: it runs tools/extract_struct_census.py --check and lets the single implementation
decide, then pins the cross-checks that make the census trustworthy.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools/extract_struct_census.py"
ART = ROOT / "reconstruction/reverse-v3/native/struct_census.json"
TSV = ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv"


def main() -> int:
    run = subprocess.run([sys.executable, str(TOOL), str(TSV), "--check", str(ART)],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr[-400:]
    rep = json.loads(ART.read_text())
    structs = rep["structs"]
    # the two records modelled elsewhere must appear here at the sizes those models assert
    assert structs["CraftableItem"]["size"] == 124
    assert structs["InteractionTestResult"]["size"] == 12
    # Apple types at their independently known sizes: the parser's sanity check
    assert structs["CATransform3D"]["size"] == 64
    assert structs["CGAffineTransform"]["size"] == 24
    # the net-data family shares one nested header
    assert structs["DynamicObjectNetData"]["size"] == 24
    for k in ("TrainCarCreationNetData", "NPCCreationNetData", "PlantCreationNetData", "NPCUpdateNetData"):
        if k in structs:
            assert structs[k]["size"] >= 24, k
    assert rep["counts"]["distinct_structs"] == len(structs)
    assert rep["counts"]["skipped_unparsed_forms"] is not None
    print(f"struct census: {len(structs)} structs verified by the single parser; "
          f"{len(rep['counts']['skipped_unparsed_forms'])} forms explicitly skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
