#!/usr/bin/env python3
"""Contract test for the audio API surface (no ELF needed in CI)."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "audio_api_surface.tsv"
JSON_PATH = NATIVE / "audio_api_surface.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {"classes": 4, "methods_total": 128, "ivars_total": 85, "classes_with_methods": 4}
PER_CLASS = {"MJSoundManager": (49, 30), "MJSound": (38, 25), "MJMultiSound": (28, 17),
             "SoundOptionsUI": (13, 13)}
REQUIRED_SELECTORS = ("soundNamed:", "multiSoundNamed:", "setListenerPosition:zoom:",
                      "playMP3IfSafe:", "fadeInMP3Playback", "initWithFile:",
                      "playAtPosition:", "setMultiSoundPlayBackFrequency:",
                      "backgroundThreadPlayWithDelay:")


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "surface is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]

    for cls, (methods, ivars) in PER_CLASS.items():
        entry = record["classes"][cls]
        assert len(entry["methods"]) == methods, (cls, len(entry["methods"]))
        assert len(entry["ivars"]) == ivars, (cls, len(entry["ivars"]))
    everything = {m["selector"] for entry in record["classes"].values()
                  for m in entry["methods"]}
    for selector in REQUIRED_SELECTORS:
        assert selector in everything, selector
    assert "alContext" in record["classes"]["MJSoundManager"]["ivars"], \
        record["classes"]["MJSoundManager"]["ivars"]

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["class", "kind", "implementation", "selector"], tsv_rows[0]
    assert len(tsv_rows) == 1 + EXPECTED["methods_total"] + EXPECTED["ivars_total"], len(tsv_rows)

    print(f"audio-api-surface: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
