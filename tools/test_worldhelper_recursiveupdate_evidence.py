#!/usr/bin/env python3
"""Regression contracts for the recursive-update sunlight engine evidence.

CI-side test: no ELF needed (the hash-pinned extractor is the local acceptance
layer). It prevents a regenerated JSON from retaining known-wrong semantics:
the pop protocol and gates, the lit path (0xff/0xef + 4-neighbour spread),
the six-neighbour shadow stencil with its attenuation tiers and window rule,
the server content activation table, and the exact 116-site / 164-branch sets.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
EXPECTED_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"


def load():
    return json.loads((NATIVE / "worldhelper_recursiveupdate.json").read_text(encoding="utf-8"))


def method():
    return load()["classes"][0]


def test_identity_and_bounds():
    report = load()
    assert report["elf_sha256"] == EXPECTED_SHA
    m = method()
    assert m["imp"] == "0x00a19c0c"
    assert m["boundary_end"] == "0x00a1b7d4"
    assert m["verified_words"] == 1778
    assert m["pic_base"] == "0x0105faf4"
    assert "no own ARM.exidx entry" in m["boundary"]


def test_lit_path():
    s = method()["semantics"]
    assert "tile[7] = 0xff" in s
    assert "0xef when tile[0xc] in {0x45, 0x5f}" in s
    assert "(tileIsAirOrSnow(tile) && tile[1] == 2)" in s
    assert "skip if tn[7] == 0xff" in s


def test_shadow_stencil_and_attenuation():
    s = method()["semantics"]
    assert "y+1, y-1, x+1, x-1, (+1,+1), (-1,+1)" in s
    assert "0xff for the y+1 window" in s
    assert "0xe0 for the other five windows" in s
    assert "base = (tn[7] > 0xef) ? 2 : 8" in s
    assert "raised to 0x10" in s
    assert "or to 0x41 when !tileIsAirOrSnow(tn)" in s
    assert "contribution = max(tn[7] - base, 0)" in s
    assert "If (max <= tile[7]) return" in s
    assert "[world saveSunlightChangedAtPos:makeIntpair(x, y)]" in s


def test_content_activation_table():
    s = method()["semantics"]
    for needle in ("0x34->0x33 torch 0x4b", "0x36->0x35 torch 0x4c",
                   "0x38->0x37 torch 0x56", "0x3a->0x39 torch 0x57",
                   "0x3c->0x3b torch 0x58"):
        assert needle in s, needle
    assert "loadTroll = (tile[3] != 0x91)" in s
    assert "loadTreasure = (tile[3] != 0x90)" in s
    assert "createTreasureChestOrTrollAtTile:tile atPos:pair loadTroll: loadTreasure:" in s
    selectors = {v.get("selector") for v in method()["selectors"].values()}
    assert "addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:" in selectors
    assert "createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:" in selectors
    assert "loadGlowBlockIfNeededAtPos:tile:" in selectors
    assert "saveSunlightChangedAtPos:" in selectors


def test_call_and_branch_sets_are_exact():
    m = method()
    assert len(m["calls"]) == 116
    assert len(m["branches"]) == 164
    bl_targets = sorted({c["callee"] for c in m["calls"] if c["callee"]})
    assert bl_targets == sorted([
        "0x001c281c", "0x004b49fc", "0x00a12760", "0x00a128b0", "0x00a12f24",
        "0x00a14824", "0x00a15518", "0x00a156a8", "0x00a16e68", "0x00a18f68",
    ])
    # single-step design: every branch goes forward
    for b in m["branches"]:
        if b["mnemonic"] == "b":
            assert int(b["destination"], 16) > int(b["address"], 16), b
        assert int(b["destination"], 16) != int(b["address"], 16)
    # the byte-9 gate and the lit-path stores are anchored instructions
    # (checked by the extractor); the JSON must carry the gate text
    assert "byte-9 gate" in m["semantics"] or "tile[9]" in m["semantics"]


if __name__ == "__main__":
    test_identity_and_bounds()
    test_lit_path()
    test_shadow_stencil_and_attenuation()
    test_content_activation_table()
    test_call_and_branch_sets_are_exact()
    print("worldhelper-recursiveupdate: PASS")
