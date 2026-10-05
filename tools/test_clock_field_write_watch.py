#!/usr/bin/env python3
"""Contract test for the clock-field write watch and the chain that explains it.

The artifact's value is that a negative is paired with the reason it is a negative, so both halves are
pinned: the watch must still be empty over substantial runs, and the executed->static chain that explains
why (trace sends setTranslation:, the setter writes the translation cell, the body does not) must still
hold.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/clock_field_write_watch.json"


def main() -> int:
    rep = json.loads(ART.read_text())
    assert rep["watched_offsets"] == [624, 648, 660, 934, 3072, 3136, 3140, 3264], rep["watched_offsets"]
    assert len(rep["runs"]) >= 4, sorted(rep["runs"])
    for tgt, r in rep["runs"].items():
        assert r["field_writes"] == [], (tgt, r["field_writes"])
    biggest = max(r["instructions"] for r in rep["runs"].values())
    assert biggest > 1000, "the run must be substantial for the negative to mean anything"
    assert "invented" in rep["watch_extended"], rep["watch_extended"]
    chain = rep["chain_that_explains_the_negative"]
    assert len(chain["steps"]) == 4, chain
    assert "setTranslation:" in chain["steps"][0] and "0x553204" in chain["steps"][1]
    assert "624" in chain["steps"][2] and "zero times" in chain["steps"][3]
    assert "open_item" in rep and "sunDirection" in rep["open_item"]
    print(f"write watch: 0 writes over {len(rep['runs'])} methods (largest {biggest} instructions), "
          f"chain to the setter intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
