#!/usr/bin/env python3
"""Contract test for the audio call-site literal map (no ELF needed in CI).

Pins the pinned-ELF binding, per-selector function counts, the `soundNamed:` site with
its prologue-verified attribution, and the literal-count snapshot. These functions
currently load **no** cstring literals (sound names arrive from wire data / callers), so
zero is pinned deliberately: an extraction change shows up as a failure, not as a
silently different table.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "audio_call_site_literals.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"

EXPECTED_FUNCTIONS = {
    "soundNamed:": 1,
    "multiSoundNamed:": 5,
    "playAtPosition:": 2,
    "setSoundVolume:": 1,
    "setMusicVolume:": 1,
    "initWithFile:": 2,
}


def main() -> int:
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert data["elf_sha256"] == PINNED_ELF, "map is not from the pinned ELF"
    assert data["pic_base"] == "0x105faf4", data["pic_base"]
    assert data["shipped_audio_names"] > 0, data

    by_sel = {r["selector"]: r for r in data["selectors"]}
    for sel, want in EXPECTED_FUNCTIONS.items():
        assert len(by_sel[sel].get("functions", [])) == want, sel

    fn = by_sel["soundNamed:"]["functions"][0]
    assert fn["method"] == "World heartbeatDataRecieved:fromPeer:", fn["method"]
    assert fn["imp"] == "0x554f04", fn
    assert fn["fn_start"] == "0x00554f04", fn
    assert fn["fn_start_mode"] == "A32", fn
    assert fn["attribution"] == "prologue-verified", fn
    assert fn["sites"] == ["0x555278"], fn["sites"]

    fns = [f for r in data["selectors"] for f in r.get("functions", [])]
    assert len(fns) == 12, len(fns)
    bad = [f for f in fns if f.get("attribution") != "prologue-verified"]
    assert not bad, bad

    n_lits = sum(len(f["literals"]) for f in fns)
    assert n_lits == 0, f"literal extraction drifted: {n_lits}"
    n_sites = sum(len(f["sites"]) for f in fns)
    assert n_sites == 16, n_sites

    print(f"audio-call-site-literals: PASS ({len(fns)} functions, {n_sites} sites; "
          "attribution pinned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
