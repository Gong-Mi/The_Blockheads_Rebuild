#!/usr/bin/env python3
"""Contract test for the Blockhead clothing and accessory mesh pipeline (R52).

Pins the five wearable slots, auxiliary meshes, jetpack frame assets, and the
disassembly listing of -[Blockhead updateClothingCubes].
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
DISASM_PATH = NATIVE / "disasm_blockhead_updateclothingcubes.txt"
DOC_PATH = NATIVE / "BLOCKHEAD_CLOTHING_PIPELINE.md"

REQUIRED_SLOTS = [
    "hatCube",
    "hatRimCube",
    "hatPomPomCubes",
    "shirtBodyCube",
    "shirtArmCube",
    "pantsCube",
    "shoesCube",
    "shoesToeCube",
    "jetpackCubes",
]

JET_TEXTURES = ["jet1.png", "jet2.png", "jet3.png"]


def main() -> int:
    assert DISASM_PATH.exists(), f"missing {DISASM_PATH}"
    disasm = DISASM_PATH.read_text(encoding="utf-8")

    assert "# Blockhead -[updateClothingCubes]" in disasm
    assert "0x00b8cc0c" in disasm
    assert "0x00b8fccc" in disasm

    for slot in REQUIRED_SLOTS:
        assert f"OBJC_IVAR_$_Blockhead.{slot}" in disasm, f"missing ivar {slot}"

    for jet in JET_TEXTURES:
        assert jet in disasm, f"missing texture {jet}"

    assert DOC_PATH.exists(), f"missing {DOC_PATH}"
    doc = DOC_PATH.read_text(encoding="utf-8")
    assert "hatPomPomCubes" in doc
    assert "shoesToeCube" in doc

    print(f"blockhead-clothing-pipeline: PASS ({len(REQUIRED_SLOTS)} cube slots + {len(JET_TEXTURES)} jet textures verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
