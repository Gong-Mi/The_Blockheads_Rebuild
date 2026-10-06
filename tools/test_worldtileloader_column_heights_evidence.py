#!/usr/bin/env python3
"""Regression contracts for the WorldTileLoader column-height evidence.

This CI-side test intentionally does not require the copyrighted original ELF
(the hash-pinned extractor is the local acceptance layer). It prevents a
regenerated JSON/MD pair from retaining known-wrong semantics: the flag
arithmetic in unmodifiedGroundLevel, the shared wrap shape of the two array
accessors, the float-precision double constants of the cloud composition, and
the full call/branch site sets.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
EXPECTED_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"


def load():
    return json.loads((NATIVE / "worldtileloader_column_heights.json").read_text(encoding="utf-8"))


def by_name(report):
    return {m["name"]: m for m in report["classes"]}


def test_method_identity_and_bounds():
    report = load()
    assert report["elf_sha256"] == EXPECTED_SHA
    methods = by_name(report)
    assert [(m["imp"], m["boundary_end"], m["verified_words"], m["pic_base"])
            for m in methods.values()] == [
        ("0x00857a2c", "0x00857bf8", 115, "0x0105faf4"),
        ("0x00857bf8", "0x00857dc8", 116, "0x0105faf4"),
        ("0x00857dc8", "0x00857f48", 96, "0x0105faf4"),
        ("0x00857340", "0x00857684", 209, "0x0105faf4"),
    ]
    assert "no own ARM.exidx entry" in methods["maxOfRockAndDirtHeightForX"]["boundary"]


def test_wrap_shape_shared_by_the_two_accessors():
    methods = by_name(load())
    for name, array_symbol, offset in (
        ("maxOfRockAndDirtHeightForX", "rockHeights", 96),
        ("maxOfRockAndDirtHeightForX", "dirtHeights", 92),
        ("lakeHeightForX", "lakeHeights", 100),
    ):
        cell = [v for v in methods[name]["ivars"].values()
                if v["symbol"].endswith("." + array_symbol)]
        assert cell and cell[0]["offset"] == offset, (name, array_symbol)
    for name in ("maxOfRockAndDirtHeightForX", "lakeHeightForX"):
        wrap = methods[name]["semantics"]
        assert "if (x < 0) x += W" in wrap, name
        assert "else if (x > W) x -= W" in wrap, name
        assert "x == W is kept" in wrap, name
    wrap = methods["maxOfRockAndDirtHeightForX"]["semantics"]
    assert "rock = rockHeights[x]" in wrap
    assert "dirt = dirtHeights[x]" in wrap
    assert "return rock >= dirt ? rock : dirt" in wrap
    assert "lakeHeights[x]" in methods["lakeHeightForX"]["semantics"]


def test_unmodified_ground_level_flag_arithmetic():
    m = by_name(load())["unmodifiedGroundLevelForX"]
    s = m["semantics"]
    assert "i0 = max(rock, dirt)" in s
    assert "if (i > rock) return i" in s
    # the flag adds +1 when the descent entered a cave; the earlier revision
    # had the ternary inverted, which this pins
    assert "return i + (flag != 0 ? 1 : 0)" in s
    selector_names = {v["selector"] for v in m["selectors"].values() if "selector" in v}
    assert selector_names == {
        "getRockAndDirtHeightforX:rockHeight:dirtHeight:",
        "faultOffsetForX:y:",
        "isCaveForX:y:faultOffset:",
    }
    assert [c["site"] for c in m["calls"]] == ["0x00857a7c", "0x00857b10", "0x00857b74"]


def test_cloud_composition_constants_and_calls():
    m = by_name(load())["getCloudHeightForX"]
    constants = m["constants"]
    assert constants["0x00857638"]["bits"] == "0x3fc99999a0000000"  # (double)0.2f
    assert constants["0x00857640"]["bits"] == "0x3fe99999a0000000"  # (double)0.8f
    assert constants["0x00857648"]["bits"] == "0x3fd3333340000000"  # (double)0.3f
    assert constants["0x00857650"]["value"] == 40.0
    assert constants["0x00857654"]["value"] == 32.0
    callees = [c["callee"] for c in m["calls"] if c["callee"]]
    assert "0x004be068" in callees  # _Z5clampfff
    assert "0x00582a14" in callees  # _Z17linearInterpolatefff
    imports = [v for v in m["selectors"].values()
               if v.get("import") == "objc_msgSend" and v.get("slot") == "0x0105b7a0"]
    assert imports, "msgSend GOT slot anchor missing"
    s = m["semantics"]
    for needle in ("q+0.1", "q+0.07", "q+0.05", "octaves:3", "octaves:9",
                   "clamp(w3, 0.0, 1.0)", "linearInterpolate(w1, w2, t)"):
        assert needle in s, needle
    ivar_symbols = {v["symbol"] for v in m["ivars"].values()}
    assert "OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionA" in ivar_symbols
    assert "OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB" in ivar_symbols


def test_branch_sets_are_exact():
    methods = by_name(load())
    assert [(b["address"], b["destination"]) for b in methods["unmodifiedGroundLevelForX"]["branches"]] == [
        ("0x00857a9c", "0x00857aac"),
        ("0x00857aa8", "0x00857ab4"),
        ("0x00857ad4", "0x00857bd0"),
        ("0x00857b24", "0x00857b34"),
        ("0x00857b30", "0x00857bd8"),
        ("0x00857b80", "0x00857bb0"),
        ("0x00857bac", "0x00857bd8"),
        ("0x00857bb0", "0x00857bb4"),
        ("0x00857bcc", "0x00857acc"),
    ]
    assert [(b["address"], b["destination"]) for b in methods["maxOfRockAndDirtHeightForX"]["branches"]] == [
        ("0x00857c18", "0x00857c70"),
        ("0x00857c6c", "0x00857d1c"),
        ("0x00857cc4", "0x00857d18"),
        ("0x00857d18", "0x00857d1c"),
        ("0x00857d7c", "0x00857d8c"),
        ("0x00857d88", "0x00857d94"),
    ]
    assert methods["getCloudHeightForX"]["branches"] == []


if __name__ == "__main__":
    test_method_identity_and_bounds()
    test_wrap_shape_shared_by_the_two_accessors()
    test_unmodified_ground_level_flag_arithmetic()
    test_cloud_composition_constants_and_calls()
    test_branch_sets_are_exact()
    print("worldtileloader-column-heights: PASS")
