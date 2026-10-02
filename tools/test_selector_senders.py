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
    # prologue-verified attribution fields (settles the old "nearest IMP only" caveat)
    assert loader["attribution"] == "prologue-verified", loader
    assert loader["fn_start"] == "0x00554f04", loader
    assert loader["offset"] == 0x374, loader
    assert loader["fn_start_mode"] == "A32", loader

    # the multi-sound trigger sites must keep landing in World tap:
    taps = [l for l in by_sel["multiSoundNamed:"]["loaders"] if l.get("method") == "World tap:"]
    assert len(taps) == 3, taps

    # all loader sites in the current table are prologue-verified (19/19 agreement with
    # nearest-IMP on 2026-10-02); a fallback appearing here is a drift alarm, not noise
    all_loaders = [l for s in data["selectors"] for l in s.get("loaders", [])
                   if l.get("loader")]
    assert len(all_loaders) == 19, len(all_loaders)
    bad = [l for l in all_loaders if l.get("attribution") != "prologue-verified"]
    assert not bad, bad

    # the common send form is `bl objc_msgSend` (PLT stub derived from rel.plt); the
    # stub identity and the exact send counts are pinned so the rule cannot drift
    assert data["objc_msgSend_stub"] == "0x1c281c", data.get("objc_msgSend_stub")
    via = {}
    for s in data["selectors"]:
        for entry in s.get("sends", []):
            via[entry["via"]] = via.get(entry["via"], 0) + 1
    assert sum(via.values()) == 15, via
    assert via.get("objc_msgSend") == 14 and via.get("blx-window") == 1, via

    # decoded static string args (__DATA,__cfstring cells, cstring at cell+8)
    multi = by_sel["multiSoundNamed:"]["sends"]
    tap_args = sorted(entry["static_args"][0] for entry in multi
                      if "World tap:" in entry["method"] and entry.get("static_args"))
    assert tap_args == ["noPath.wav"] * 3, tap_args
    fire = [entry for entry in multi
            if "placeWorkbench" in entry["method"] and entry.get("static_args")]
    assert len(fire) == 1 and fire[0]["static_args"] == ["fire.wav"], fire
    assert all("static_args" in entry for entry in multi), multi

    print("selector-senders: PASS (mechanism + counts pinned; 19/19 prologue-verified; "
          "15 send sites; trigger args decoded)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
