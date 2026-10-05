#!/usr/bin/env python3
"""Contract test: the clock-field write watch is still empty, and still says why.

The value of this artifact is its size - a narrow negative. If a future run starts recording writes, the
doc's "what it does exclude" no longer holds and this test should be what notices.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/clock_field_write_watch.json"


def main() -> int:
    rep = json.loads(ART.read_text())
    assert rep["watched_offsets"] == [624, 648, 660, 934, 3072, 3136, 3140, 3264], rep["watched_offsets"]
    assert len(rep["runs"]) == 5, sorted(rep["runs"])
    for tgt, r in rep["runs"].items():
        assert r["field_writes"] == [], (tgt, r["field_writes"])
    biggest = max(r["instructions"] for r in rep["runs"].values())
    assert biggest > 1000, "the run must be substantial for the negative to mean anything"
    assert "stub" in rep["reading_both_ways"][0].lower(), rep["reading_both_ways"][0]
    print(f"clock-field write watch: 0 writes over {len(rep['runs'])} methods, "
          f"largest run {biggest} instructions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
