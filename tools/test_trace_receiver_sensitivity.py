#!/usr/bin/env python3
"""Contract test: pin the receiver sensitivity, so it cannot be forgotten.

The point of the experiment is that one fabricated receiver gave a different shape of run than another,
and both completed. If a future change makes the two agree, the claim in the doc is no longer true and
this test should be what says so.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "reconstruction/reverse-v3/native/trace_receiver_sensitivity.json"


def main() -> int:
    rep = json.loads(ART.read_text())
    runs = rep["runs"]
    assert len(runs) >= 3, sorted(runs)
    a = runs["World:incrementalLoad"]["all-zero receiver"]["counts"]
    b = runs["World:incrementalLoad"]["flat object graph"]["counts"]
    assert a["instructions"] != b["instructions"], "the sensitivity claim needs the two runs to differ"
    assert a["call_outs"] != b["call_outs"], (a, b)
    assert runs["World:incrementalLoad"]["all-zero receiver"]["stopped_by"] is None
    assert runs["World:incrementalLoad"]["flat object graph"]["stopped_by"] is None
    for tgt, v in runs.items():
        assert v["flat object graph"]["counts"]["sends"] == 0, tgt
        assert v["all-zero receiver"]["counts"]["unresolved_selectors"] == 0, tgt
    tool = (ROOT / "tools/trace_msg_sends.py").read_text()
    assert "--fill-pointers" in tool and "flat object graph" in tool
    print(f"receiver sensitivity: incrementalLoad {a['instructions']} -> {b['instructions']} instructions, "
          f"call-outs {a['call_outs']} -> {b['call_outs']}, no sends either way")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
