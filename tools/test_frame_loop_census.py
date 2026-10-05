#!/usr/bin/env python3
"""Contract test for the frame-loop census and its traces.

The census is the simulation's participant list, so it is re-derived from the method table here rather
than trusted: count, class set and the single-signature property must all hold. The traces are checked
for what would quietly change their meaning - a non-zero unresolved count, or an empty first cycle next
to a non-zero send count - and the one trace that reached a send must keep doing so.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/frame_loop_protocol_census.json"
TSV = ROOT / "reconstruction/reverse-v3/native/libApplication_objc_methods.tsv"


def main() -> int:
    rep = json.loads(ART.read_text())
    family = rep["family"]
    live = []
    for line in TSV.read_text().splitlines()[1:]:
        p = line.split("\t")
        if len(p) >= 5 and p[2] == "instance" and p[3] == family:
            live.append({"class": p[1], "imp": p[0], "types": p[4]})
    assert len(live) == rep["census"]["members"], (len(live), rep["census"]["members"])
    assert sorted(m["class"] for m in live) == sorted(m["class"] for m in rep["census"]["classes"])
    assert len({m["types"] for m in live}) == 1, {m["types"] for m in live}
    assert rep["census"]["signature_uniform"] is True
    for name, t in rep["traces"].items():
        assert t["counts"]["unresolved_selectors"] == 0, name
        if t["counts"]["sends"]:
            assert t["first_cycle"] and all(f["selector"] for f in t["first_cycle"]), name
    pinch = [t for k, t in rep["traces"].items() if k.endswith("pinchScale:dragInProgress:")]
    assert pinch and pinch[0]["counts"]["sends"] >= 1, "the pinch/pan trace reached setTranslation:"
    assert pinch[0]["counts"]["vfp_skipped"] > 100, "that method is float-heavy; the count must show it"
    print(f"frame-loop protocol: {len(live)} classes, one signature; "
          f"{len(rep['traces'])} traces, sends={sorted(t['counts']['sends'] for t in rep['traces'].values())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
