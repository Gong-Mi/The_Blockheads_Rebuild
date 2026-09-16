#!/usr/bin/env python3
"""Regression contracts for the checked-in ClientTileLoader semantic maps.

This CI-side test intentionally does not require the copyrighted original ELF.
The hash-pinned ELF extractors are the separate local acceptance layer; this
contract prevents a regenerated JSON/MD pair from retaining known-wrong
formula and call-set claims.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"


def load(name):
    return json.loads((NATIVE / name).read_text(encoding="utf-8"))


def by_site(rows):
    return {row["site"]: row for row in rows}


def test_initial_terrain_semantics():
    report = load("clienttileloader_getinitialrockdirt.json")
    calls = by_site(report["blx_calls"])
    assert [(calls[f"0x{x:08x}"]["selector"], calls[f"0x{x:08x}"]["note"])
            for x in (0x947CAC, 0x947D14, 0x947D74, 0x948000, 0x948068, 0x9480C8)] == [
        ("getX:Y:octaves:", "heightNoiseFunctionA; X=q+0.1, Y=0.5, octaves=3"),
        ("getX:Y:octaves:", "heightNoiseFunctionB; X=q+0.07, Y=0.5, octaves=5"),
        ("getX:Y:octaves:", "heightNoiseFunctionB; X=q+0.05, Y=0.75, octaves=9"),
        ("getX:Y:octaves:", "heightNoiseFunctionA; X=q+0.1, Y=0.5, octaves=3"),
        ("getX:Y:octaves:", "heightNoiseFunctionB; X=q+0.07, Y=0.5, octaves=3"),
        ("getX:Y:octaves:", "heightNoiseFunctionB; X=q+0.05, Y=0.75, octaves=9"),
    ]
    formula = report["formula"]
    assert formula["sample_shape"] == (
        "u=clamp(0.8*B(q+0.05,0.75,9)+0.2,0,1); "
        "v=lerp(0.3*A(q+0.1,0.5,3)+0.5, "
        "0.5*B(q+0.07,0.5,5)+0.5, u); r=(v-0.5)*2"
    )
    assert formula["small_shape"] == (
        "if abs(r)<0.1: r=powf(10*abs(r),2)/10; restore sign from original r"
    )
    assert formula["rock"] == "16.0 + 32.0 * 31.0 * (0.5 + r/2.0)"
    assert formula["dirt"] == "20.0 + 32.0 * 31.0 * (0.5 + r2/2.0)"
    assert report["cells"]["0x00948278"]["symbol"] == "objc_msgSend"


def test_fault_offset_semantics():
    report = load("clienttileloader_faultoffset.json")
    calls = by_site(report["blx_calls"])
    assert set(calls) == {
        "0x00948508", "0x00948560", "0x00948598",
        "0x00948688", "0x00948734",
    }
    assert report["formula"]["band"] == (
        "band=clamp(f32(0.8*double(B.getX(16*qx+0.05,0.75,1)) + 0.2),0,1)"
    )
    assert report["formula"]["shape"] == (
        "0 if a<=0; powf(2*a,2) if 0<a<0.2; "
        "powf(max(2*(a-0.2),0),2)+0.5*band otherwise"
    )
    branches = by_site(report["branches"])
    assert "0x0094885c" in branches
    assert report["cells"]["0x009488b0"]["symbol"] == "objc_msgSend"


if __name__ == "__main__":
    test_initial_terrain_semantics()
    test_fault_offset_semantics()
    print("clienttileloader-semantics: PASS")
