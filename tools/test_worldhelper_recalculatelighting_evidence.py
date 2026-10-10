#!/usr/bin/env python3
"""Regression contracts for the per-block lighting orchestrator evidence.

CI-side test: no ELF needed (the hash-pinned extractor is the local acceptance
layer). It prevents a regenerated JSON from retaining known-wrong semantics:
the gates, the blockhead/portal center with margin, the wrap/cull window, the
32x32 walk's exact falloff arithmetic and saturating max, the updateSunLight
handoff conditions, the freeze path, and the exact 40-site / 62-branch sets.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"
EXPECTED_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"


def load():
    return json.loads((NATIVE / "worldhelper_recalculatelighting.json").read_text(encoding="utf-8"))


def method():
    return load()["classes"][0]


def test_identity_and_bounds():
    report = load()
    assert report["elf_sha256"] == EXPECTED_SHA
    m = method()
    assert m["imp"] == "0x00a1ca64"
    assert m["boundary_end"] == "0x00a1d730"
    assert m["verified_words"] == 819
    assert m["pic_base"] == "0x0105faf4"
    assert "no own ARM.exidx entry" in m["boundary"]
    assert m["types"].startswith("v24@0:4^{PhysicalBlock")


def test_gates_and_center():
    s = method()["semantics"]
    assert "if (clientLightBlockIndex == 0) return" in s
    assert "if ([dw isClient]) return" in s
    assert "isClientBlockheadBeingControlledByServer" in s
    assert "[blockhead pos]" in s and "[world startPortalPos]" in s
    assert "margin = max(22 - vr, 0)" in s
    assert "loadLightBlockForClientLightBlockIndex:idx intoPhysicalBlock:pb" in s


def test_walk_and_falloff():
    s = method()["semantics"]
    assert "Per tile loop (i = 0..31 rows, j = 0..31 cols)" in s
    assert "srcByte = extra ? extra[i*32+j] : tile[6]" in s
    assert "if (d2 >= 0x1e4) continue" in s
    assert "u = 4.0f - t * 4.0f" in s
    assert "lightI = (int)(255.0f * u)" in s
    assert "newLight = (lightI > srcByte) ? min(lightI, 0xff) : srcByte" in s
    assert "backWallIsMutable(tile) && !tileIsSolid(tile) && tile[3] == 0 && tile[0] != 3" in s
    assert "[WorldHelper updateSunLightForTile:tile atPos:worldPos world:world]" in s
    assert "fillTile:tile atPos:worldPos withType:0x422" in s
    assert "if (flag36) [dw lightChangedAtMacroPos:" in s
    assert "if (flag35) [dw exploreLightChangedAtMacroPos:" in s


def test_call_and_branch_sets_are_exact():
    m = method()
    assert len(m["calls"]) == 40
    assert len(m["branches"]) == 62
    bl_targets = sorted({c["callee"] for c in m["calls"] if c["callee"]})
    assert bl_targets == sorted([
        "0x001c281c", "0x001c2918", "0x001c2924", "0x001c2b28", "0x001c3728",
        "0x004b49fc", "0x00a1179c", "0x00a1234c", "0x00a14a48", "0x00a15404",
    ])
    selectors = {v.get("selector") for v in m["selectors"].values() if "selector" in v}
    for needle in ("updateSunLightForTile:atPos:world:", "getWeatherFractionForPos:",
                   "getDayNightFractionForX:atWorldTime:", "fillTile:atPos:withType:",
                   "lightChangedAtMacroPos:sendReliably:sendAtAll:",
                   "exploreLightChangedAtMacroPos:clientLightBlockIndex:"):
        assert needle in selectors, needle


if __name__ == "__main__":
    test_identity_and_bounds()
    test_gates_and_center()
    test_walk_and_falloff()
    test_call_and_branch_sets_are_exact()
    print("worldhelper-recalculatelighting: PASS")
