#!/usr/bin/env python3
"""Contract test for the selector reference-site map (no ELF needed in CI).

Pins the mechanism's arithmetic and the counts, so a change in the pool-word route or in
the method map shows up as a failure instead of a silently different table.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "selector_senders.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"

EXPECTED = {
    "soundNamed:": (1, 1),
    "multiSoundNamed:": (1, 8),
    "playAtPosition:": (1, 4),
    "setSoundVolume:": (1, 1),
    "setMusicVolume:": (1, 1),
    "initWithFile:": (1, 2),
    "tap:": (1, 1),
    "update:": (0, 0),
}


def main() -> int:
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert data["elf_sha256"] == PINNED_ELF, "map is not from the pinned ELF"
    assert data["pic_base"] == "0x105faf4", data["pic_base"]
    seen = {s["selector"]: (len(s["slots"]), len(s["loaders"])) for s in data["selectors"]}
    for sel, want in EXPECTED.items():
        assert seen.get(sel) == want, f"{sel}: {seen.get(sel)} != {want}"

    by_sel = {s["selector"]: s for s in data["selectors"]}
    sound = by_sel["soundNamed:"]
    assert sound["slots"] == ["0xe7de14"], sound["slots"]
    slot = int(sound["slots"][0], 16)
    loader = sound["loaders"][0]
    assert int(loader["pool_word"], 16) == (slot - 0x105FAF4) & 0xFFFFFFFF, loader
    assert loader["loader"] == "0x555278", loader
    assert "World" in loader["method"], loader

    # the multi-sound trigger sites must keep landing in World tap:
    taps = [l for l in by_sel["multiSoundNamed:"]["loaders"] if l.get("method") == "World tap:"]
    assert len(taps) == 3, taps

    # send detection is conservative on purpose: it must not silently become permissive
    total_sends = sum(s.get("n_sends", 0) for s in data["selectors"])
    assert total_sends <= 2, f"send rule got permissive: {total_sends}"

    print("selector-senders: PASS (mechanism + counts pinned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
