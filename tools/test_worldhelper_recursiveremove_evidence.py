#!/usr/bin/env python3
"""Regression contracts for the recursive-remove sunlight engine evidence.

CI-side test: no ELF needed (the hash-pinned extractor is the local acceptance
layer). It prevents a regenerated JSON from retaining known-wrong semantics:
the pop protocol, the clear-before-recalc order, the single-step design (no
internal loop), the neighbour level monotonicity and window bounds, and the
exact 40-site / 51-branch sets.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
EXPECTED_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"


def load():
    return json.loads((NATIVE / "worldhelper_recursiveremove.json").read_text(encoding="utf-8"))


def method():
    return load()["classes"][0]


def test_identity_and_bounds():
    report = load()
    assert report["elf_sha256"] == EXPECTED_SHA
    m = method()
    assert m["imp"] == "0x00a1bd10"
    assert m["boundary_end"] == "0x00a1c680"
    assert m["verified_words"] == 604
    assert m["pic_base"] == "0x0105faf4"
    assert "no own ARM.exidx entry" in m["boundary"]


def test_pop_protocol_and_clear_order():
    m = method()
    s = m["semantics"]
    assert "obj = [list objectAtIndex:0]" in s
    assert "[obj intValue]" in s
    assert "[list removeObjectAtIndex:0]" in s
    assert "[openIndices removeIndex:idx]" in s
    # clear happens before macroTiles/recalc
    assert "tile[7] = 0; mt = [world macroTiles];" in s
    sites = [c["site"] for c in m["calls"]]
    assert sites[:6] == ["0x00a1bdec", "0x00a1bdfc", "0x00a1be18",
                         "0x00a1be30", "0x00a1be50", "0x00a1be60"]
    selectors = {v.get("selector") for v in m["selectors"].values() if "selector" in v}
    assert {"objectAtIndex:", "intValue", "removeObjectAtIndex:", "removeIndex:",
            "macroTiles", "containsIndex:", "addIndex:", "addObject:",
            "numberWithInt:"} <= selectors
    classes = {v["class"] for v in m["classrefs"].values()}
    assert classes == {"OBJC_CLASS_$_NSNumber"}


def test_single_step_and_monotonicity():
    m = method()
    s = m["semantics"]
    assert "Exactly one work item per call" in s
    assert "tn[7] == 0 or tn[7] > lvl" in s
    assert "minx" in s and "maxX" in s
    assert "y+1, y-1, x+1, x-1" in s
    assert "skip when x+1 >= maxX" in s
    assert "skip when x+1 >= maxX (dx=+1) or x-1 < minx (dx=-1)" in s
    # no backward branch inside the body (single-step design)
    for b in m["branches"]:
        assert int(b["destination"], 16) > int(b["address"], 16) or b["mnemonic"] == "b", b


def test_call_and_branch_sets_are_exact():
    m = method()
    assert len(m["calls"]) == 40
    assert len(m["branches"]) == 51
    bl_targets = sorted({c["callee"] for c in m["calls"] if c["callee"]})
    assert bl_targets == ["0x00a12760", "0x00a12f24", "0x00a15518",
                          "0x00a156a8", "0x00a18f68"]
    # both current-tile aborts go to the epilogue; the lvl==0 one via the trampoline
    first = {b["address"]: (b["mnemonic"], b["destination"]) for b in m["branches"]}
    assert first["0x00a1be74"] == ("beq", "0x00a1c648")
    assert first["0x00a1be98"] == ("beq", "0x00a1c648")
    assert first["0x00a1bea8"] == ("beq", "0x00a1c648")
    assert first["0x00a1bec0"] == ("beq", "0x00a1c644")


if __name__ == "__main__":
    test_identity_and_bounds()
    test_pop_protocol_and_clear_order()
    test_single_step_and_monotonicity()
    test_call_and_branch_sets_are_exact()
    print("worldhelper-recursiveremove: PASS")
