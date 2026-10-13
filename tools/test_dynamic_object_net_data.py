#!/usr/bin/env python3
"""Contract test for the recovered DynamicObjectNetData header - checked against the single parser.

This test does NOT parse encodings itself (an earlier test of mine did, and its copy disagreed with the tool).
It runs the census tool's --check, then requires the header to agree with the census about the header struct's
field offsets and about the family's sizes, so the model and the census cannot drift apart.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "reconstruction/recovered/dynamic_object_net_data.h"
ART = ROOT / "reconstruction/reverse-v3/native/struct_census.json"
TSV = ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv"


def main() -> int:
    run = subprocess.run([sys.executable, str(ROOT / "tools/extract_struct_census.py"), str(TSV),
                          "--check", str(ART)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr[-300:]
    rep = json.loads(ART.read_text())
    net = rep["structs"]["DynamicObjectNetData"]
    hdr = HDR.read_text()

    # the header's field offsets must be the census's offsets for the same struct
    members = re.findall(r"\bf(\d+)\s*;|\bf(\d+)\[", hdr)
    for i, f in enumerate(net["layout"]):
        assert f"// +{f['offset']}" in hdr, (i, f)
    assert f"sizeof(DynamicObjectNetData) == {net['size']}" in hdr

    # the family: every *NetData struct that contains the header at offset 0
    family = {}
    for name, entry in rep["structs"].items():
        if name == "DynamicObjectNetData":
            continue
        for f in entry["layout"]:
            if f["type"].strip("{}") == "DynamicObjectNetData":
                family[name] = (entry["size"], f["offset"])
    assert len(family) >= 4, family
    for name, (size, off) in family.items():
        assert off == 0, (name, off)
        assert f"k{name}Size = {size};" in hdr, (name, size)
    print(f"dynamic object net data: {net['size']}-byte header shared by {len(family)} records, "
          f"all at offset 0 - sizes {sorted(s for s, _ in family.values())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
