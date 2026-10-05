#!/usr/bin/env python3
"""Contract test for the recovered audio wiring model, including the part that decays.

Two checks with different jobs:
  * the (method, sound) table must match audio_wiring_map.json exactly - the artifact is the evidence and
    the header is the model, so a generator bug shows up as a diff;
  * the "not yet wired in the replacement" list must match a FRESH measurement against the current
    sources. The artifact's own per-name boolean had gone stale (it claimed 120 unwired; measuring shows
    fewer every time someone wires sounds), so this test measures instead of trusting - a stored count
    would silently rot, and a TODO list that overstates itself wastes the next person's time.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "reconstruction/recovered/audio_wiring_model.h"
ART = ROOT / "reconstruction/reverse-v3/native/audio_wiring_map.json"
SOURCES = ["app/src/main/cpp", "reconstruction/recovered"]


# The model header itself lists the unwired sounds, so scanning it would mark the TODO list as DONE:
# measuring references must exclude the file that records the gap, or the gap closes itself. (Found by
# this test failing with "fresh measurement says 0" the first time it ran.)
SELF = {ROOT / "reconstruction/recovered/audio_wiring_model.h",
        ROOT / "reconstruction/recovered/audio_wiring_model.cpp"}


def measure_referenced() -> str:
    text = ""
    for base in SOURCES:
        for p in (ROOT / base).rglob("*"):
            if p.suffix in (".h", ".hpp", ".cpp", ".c", ".cc") and p not in SELF:
                text += p.read_text(errors="ignore")
    return text


def main() -> int:
    rep = json.loads(ART.read_text())
    hdr = HDR.read_text()
    per: dict[str, list[str]] = {}
    for r in rep["rows"]:
        for m in r.get("methods", []):
            per.setdefault(m, []).append(r["name"])
    pairs = sorted((m, snd) for m, names in per.items() for snd in names)
    # the header's table, parsed back out
    got = sorted((m, snd) for m, snd in re.findall(r'\{"([^"]+)", "([^"]+)"\}', hdr))
    assert len(got) == len(pairs), (len(got), len(pairs))
    assert got == pairs, "header wiring table does not match the artifact"

    declared = set(re.findall(r'^    "([^"]+\.(?:wav|mp3|mp4))",$', hdr, re.M))
    mapped_names = sorted({r["name"] for r in rep["rows"] if r.get("methods")})
    sources = measure_referenced()
    fresh = {n for n in mapped_names if n.split(".")[0] not in sources}
    assert declared == fresh, (
        f"stale list: header declares {len(declared)} unwired, fresh measurement says {len(fresh)}; "
        f"added={sorted(declared - fresh)[:5]} removed={sorted(fresh - declared)[:5]}")
    assert len(fresh) < 120, "the stale artifact said 120 - a fresh run must not reproduce a stale number"
    print(f"audio wiring: {len(pairs)} pairs over {len(per)} methods; "
          f"{len(mapped_names) - len(fresh)} wired in the replacement, {len(fresh)} still not")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
