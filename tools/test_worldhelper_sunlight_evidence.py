#!/usr/bin/env python3
"""Regression contracts for the WorldHelper sunlight-pair evidence.

CI-side test: no ELF needed (the hash-pinned extractor is the local acceptance
layer). It prevents a regenerated JSON from retaining known-wrong semantics:
the five-block enqueue order of the update variant, the bounded
remove-then-conditionally-reupdate flow of the removed variant, the
class-reference and selector anchors, and the exact call/branch site sets.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
EXPECTED_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
WORLD_INDEX = "0x00a156a8"


def load():
    return json.loads((NATIVE / "worldhelper_sunlight.json").read_text(encoding="utf-8"))


def by_name(report):
    return {m["name"]: m for m in report["classes"]}


def test_identity_and_bounds():
    report = load()
    assert report["elf_sha256"] == EXPECTED_SHA
    methods = by_name(report)
    assert [(m["imp"], m["boundary_end"], m["verified_words"], m["pic_base"])
            for m in methods.values()] == [
        ("0x00a1b7d4", "0x00a1bd10", 335, "0x0105faf4"),
        ("0x00a1c680", "0x00a1ca64", 249, "0x0105faf4"),
    ]
    for m in methods.values():
        assert "no own ARM.exidx entry" in m["boundary"]


def test_class_references_are_relocation_backed():
    methods = by_name(load())
    expected = {
        "updateSunLightForTile": {
            "0x00a1bce8": ("0x00e8ae7c", "OBJC_CLASS_$_NSMutableIndexSet"),
            "0x00a1bcf0": ("0x00e8ae78", "OBJC_CLASS_$_NSMutableArray"),
            "0x00a1bd00": ("0x00e8ae74", "OBJC_CLASS_$_NSNumber"),
        },
        "updateSunLightRemovedForTile": {
            "0x00a1ca34": ("0x00e8ae7c", "OBJC_CLASS_$_NSMutableIndexSet"),
            "0x00a1ca3c": ("0x00e8ae78", "OBJC_CLASS_$_NSMutableArray"),
            "0x00a1ca48": ("0x00e8ae74", "OBJC_CLASS_$_NSNumber"),
        },
    }
    for name, cells in expected.items():
        got = {c: (v["slot"], v["class"]) for c, v in methods[name]["classrefs"].items()}
        assert got == cells, name


def test_update_variant_enqueue_and_drain():
    m = by_name(load())["updateSunLightForTile"]
    s = m["semantics"]
    assert "[(0,0), (0,+1), (0,-1), (+1,0), (-1,0)]" in s
    assert "[open addIndex:index]" in s
    assert "while ([array count] > 0)" in s
    assert "openIndices:open world:world]" in s
    # five worldIndex calls, innermost block last
    bl_sites = [c["site"] for c in m["calls"] if c["callee"]]
    assert bl_sites == ["0x00a1b880", "0x00a1b948", "0x00a1ba10",
                        "0x00a1bad8", "0x00a1bba0"]
    assert {c["callee"] for c in m["calls"] if c["callee"]} == {WORLD_INDEX}
    selectors = {v.get("selector") for v in m["selectors"].values()}
    assert "recursivelyUpdateSunLightWithList:openIndices:world:" in selectors
    assert "indexSet" in selectors and "array" in selectors


def test_removed_variant_bounded_remove_then_conditional_reupdate():
    m = by_name(load())["updateSunLightRemovedForTile"]
    s = m["semantics"]
    assert "minx:x-32 maxX:x+32" in s
    assert "if (![removeIndices containsIndex:index0])" in s
    assert "[lightWasRemovedList addObject:[NSNumber numberWithInt:index0]]" in s
    assert "[removeIndices addIndex:index0]" in s
    selectors = {v.get("selector") for v in m["selectors"].values()}
    assert "recursivelyRemoveAllSunLightWithList:openIndices:lightWasRemovedList:removeIndices:world:minx:maxX:" in selectors
    assert "containsIndex:" in selectors
    # the four container allocations happen before the single worldIndex call
    call_sites = [c["site"] for c in m["calls"]]
    assert call_sites[:5] == ["0x00a1c6fc", "0x00a1c720", "0x00a1c744",
                              "0x00a1c768", "0x00a1c77c"]
    assert [c["callee"] for c in m["calls"] if c["callee"]] == [WORLD_INDEX]
    # the index-not-removed gate is sxtb-tested and skips the re-update block
    assert m["branches"][4] == {"address": "0x00a1c8fc", "mnemonic": "bne",
                                "destination": "0x00a1c9a4"}


def test_branch_sets_are_exact():
    methods = by_name(load())
    assert [(b["address"], b["mnemonic"], b["destination"])
            for b in methods["updateSunLightForTile"]["branches"]] == [
        ("0x00a1b890", "blt", "0x00a1b938"),
        ("0x00a1b958", "blt", "0x00a1ba00"),
        ("0x00a1ba20", "blt", "0x00a1bac8"),
        ("0x00a1bae8", "blt", "0x00a1bb90"),
        ("0x00a1bbb0", "blt", "0x00a1bc58"),
        ("0x00a1bc58", "b", "0x00a1bc5c"),
        ("0x00a1bc8c", "bls", "0x00a1bcd8"),
        ("0x00a1bcd4", "b", "0x00a1bc5c"),
    ]
    assert [(b["address"], b["mnemonic"], b["destination"])
            for b in methods["updateSunLightRemovedForTile"]["branches"]] == [
        ("0x00a1c78c", "bge", "0x00a1c794"),
        ("0x00a1c790", "b", "0x00a1ca24"),
        ("0x00a1c854", "bls", "0x00a1c8c0"),
        ("0x00a1c8bc", "b", "0x00a1c824"),
        ("0x00a1c8fc", "bne", "0x00a1c9a4"),
        ("0x00a1c9a4", "b", "0x00a1c9a8"),
        ("0x00a1c9d8", "bls", "0x00a1ca24"),
        ("0x00a1ca20", "b", "0x00a1c9a8"),
    ]


if __name__ == "__main__":
    test_identity_and_bounds()
    test_class_references_are_relocation_backed()
    test_update_variant_enqueue_and_drain()
    test_removed_variant_bounded_remove_then_conditional_reupdate()
    test_branch_sets_are_exact()
    print("worldhelper-sunlight: PASS")
