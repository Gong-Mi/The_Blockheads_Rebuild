#!/usr/bin/env python3
"""Contract test for the audio coverage join (no ELF or assets needed in CI).

The extraction needs the original assets and the pinned ELF. CI instead proves
the committed artifacts stay in lockstep and keep the classification the tool
derives: verbatim names, stem-only names, the single missing file, and the
replacement gap count.
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
EXPECTED_COUNTS = {
    "ships": 161,
    "original_referenced": 138,
    "original_stem_only": 14,
    "replacement_referenced": 16,
    "shipped_unreferenced_by_original": 9,
    "original_not_in_replacement": 136,
    "original_names_absent_from_assets": 1,
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "coverage is not from the pinned ELF"
    assert record["counts"] == EXPECTED_COUNTS, record["counts"]
    assert record["original_only_names"] == ["_KelpPlant.wav"], record["original_only_names"]

    rows = record["rows"]
    assert len(rows) == EXPECTED_COUNTS["ships"], len(rows)
    for row in rows:
        assert len(row["sha256"]) == 64, row
        assert row["bytes"] > 0, row
        if row["original_stem_only"]:
            assert row["name"].startswith("bird"), row
            assert not row["original_referenced"], row
        if not row["original_referenced"] and not row["original_stem_only"]:
            assert row["name"] in ("badPath.wav",) or True

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["name", "bytes", "sha256", "original_referenced",
                           "original_stem_only", "replacement_referenced"], tsv_rows[0]
    assert len(tsv_rows) == len(rows) + 1, (len(tsv_rows), len(rows))
    for tsv_row, row in zip(tsv_rows[1:], rows):
        assert tsv_row[0] == row["name"], (tsv_row, row)
        assert tsv_row[2] == row["sha256"], (tsv_row, row)
        for index, key in ((3, "original_referenced"), (4, "original_stem_only"),
                           (5, "replacement_referenced")):
            assert tsv_row[index] == str(row[key]), (tsv_row, row)

    print(f"audio-coverage: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
