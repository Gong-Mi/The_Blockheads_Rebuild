#!/usr/bin/env python3
"""Contract test for tools/extract_audio_wiring_map.py.

Layer 1 (runs everywhere): the pointer arithmetic the whole map rests on, plus the two control
classes that matter:

  * the pool word must be (cfstring_va - PIC_BASE) mod 2^32 - an unsigned wrap is required, since
    every real cfstring sits BELOW the PIC base (0xf8xxxx < 0x105faf4); treating it as signed, or
    forgetting the wrap, silently finds nothing;
  * the five hand-checked mappings must stay in SELF_CHECK, because a zero-hit sweep is not a result
    without them.

Layer 2: self-skips when the pinned ELF is absent.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import extract_audio_wiring_map as m  # noqa: E402


def main() -> int:
    # --- the wrap -----------------------------------------------------------
    for cfstring_va in (0xF85BA8, 0xFA2A28, 0xF7B178):
        pool = (cfstring_va - m.PIC_BASE) & 0xFFFFFFFF
        assert pool > 0x80000000, "the pool word must be a wrapped negative offset, not a signed one"
        assert (pool + m.PIC_BASE) & 0xFFFFFFFF == cfstring_va, "round-trip must reconstruct the VA"
    # a naive signed value would be negative and never match a 4-byte word
    assert (0xF85BA8 - m.PIC_BASE) < 0, "sanity: the raw difference IS negative, hence the wrap"

    assert m.PIC_BASE == 0x105FAF4, "PIC base is the value verified across 5730 sites elsewhere"
    assert m.TEXT_LO == 0x1C4500, "the code window must match the project's other sweeps"

    # --- the hand-checked controls must stay --------------------------------
    want = {"blockheadDie.wav": "Blockhead -[dieForGood]",
            "camera.wav": "World -[doCameraScreenshot]",
            "babyUnicorn.wav": "Donkey -[loadDerivedStuff]",
            "bow.wav": "Blockhead -[update:accurateDT:isSimulation:]"}
    for name, method in want.items():
        assert m.SELF_CHECK.get(name) == method, f"control for {name} changed: {m.SELF_CHECK.get(name)}"
    assert len(m.SELF_CHECK) == 5, m.SELF_CHECK
    assert all(v.startswith(("Blockhead ", "World ", "Donkey ", "Workbench "))
               for v in m.SELF_CHECK.values()), m.SELF_CHECK

    pinned = Path(os.environ.get("BH_ELF",
                  ROOT.parent.parent / "extracted/lib/armeabi-v7a/libApplication.so"))
    cover = ROOT / "reconstruction/reverse-v3/native/audio_asset_coverage.json"
    if not pinned.is_file() or not cover.is_file():
        print("skip: pinned ELF or coverage artifact not present (arithmetic + controls verified)")
        return 0
    print("arithmetic + controls verified; inputs present (run the tool directly)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
