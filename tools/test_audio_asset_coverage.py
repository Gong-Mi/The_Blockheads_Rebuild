#!/usr/bin/env python3
"""Contract test for the audio coverage join (no ELF or assets needed in CI).

Also pins the correction that matters most here: `_KelpPlant.wav` must never
reappear. It was a regex artifact of scanning raw bytes (the ObjC ivar
`OBJC_IVAR_$_KelpPlant.waveTimer` contains `.wav`), and both the per-row classes
and the "ELF strings that ship no file" list are asserted to stay clean of it.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "audio_asset_coverage.tsv"
JSON_PATH = NATIVE / "audio_asset_coverage.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {
    "ships": 161,
    "original_verbatim": 138,
    "original_format_string": 14,
    "original_suffix_composition": 0,
    "original_stem_exact": 0,
    "original_stem_prefix": 0,
    "original_substring_only": 0,
    "original_unattributed": 9,
    "original_named": 152,
    "replacement_referenced": 16,
    "original_named_not_in_replacement": 136,
    "no_original_evidence": 9,
    "original_names_absent_from_assets": 1,
}
CLASSES = ("verbatim", "format-string", "suffix-composition", "stem-exact",
           "stem-prefix", "substring", "unattributed")


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "coverage is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["original_only_names"] == ["bird%d.wav"], record["original_only_names"]
    assert "NUL-delimited" in record["string_extraction"], record["string_extraction"]

    rows = record["rows"]
    assert len(rows) == EXPECTED["ships"], len(rows)
    for row in rows:
        assert len(row["sha256"]) == 64, row
        assert row["bytes"] > 0, row
        assert row["original_class"] in CLASSES, row
        assert "_KelpPlant" not in row["name"], row
        if row["original_class"] == "format-string":
            assert row["original_evidence"] == "bird%d.wav", row
            assert row["name"].startswith("bird"), row
    bird = [r for r in rows if r["name"].startswith("bird")]
    assert len(bird) == 14, len(bird)
    assert all(r["original_class"] == "format-string" for r in bird), bird

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["name", "bytes", "sha256", "original_class",
                           "original_evidence", "replacement_referenced"], tsv_rows[0]
    assert len(tsv_rows) == len(rows) + 1, (len(tsv_rows), len(rows))
    for tsv_row, row in zip(tsv_rows[1:], rows):
        assert tsv_row[0] == row["name"] and tsv_row[2] == row["sha256"], (tsv_row, row)
        assert tsv_row[3] == row["original_class"], (tsv_row, row)
    print(f"audio-coverage: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
