#!/usr/bin/env python3
"""Contract test for the shader coverage join (no ELF or assets needed in CI)."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "shader_asset_coverage.tsv"
JSON_PATH = NATIVE / "shader_asset_coverage.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {
    "ships": 92,
    "vertex": 46,
    "fragment": 46,
    "original_verbatim": 22,
    "original_suffix_composition": 70,
    "original_stem_exact": 0,
    "original_stem_prefix": 0,
    "original_substring_only": 0,
    "original_unattributed": 0,
    "original_named": 22,
    "replacement_referenced": 8,
    "mapped_in_class_table": 16,
    "not_named_by_replacement": 84,
}
CLASSES = ("verbatim", "format-string", "suffix-composition", "stem-exact",
           "stem-prefix", "substring", "unattributed")


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "coverage is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["unattributed"] == [], record["unattributed"]
    assert len(record["suffix_composition_names"]) == 70, record["suffix_composition_names"]
    assert "string_evidence" in record["string_extraction"], record["string_extraction"]

    rows = record["rows"]
    assert len(rows) == EXPECTED["ships"], len(rows)
    for row in rows:
        assert len(row["sha256"]) == 64, row
        assert row["bytes"] > 0, row
        assert row["original_class"] in CLASSES, row
        assert row["stage"] == ("vertex" if row["name"].endswith(".vsh") else "fragment"), row
        if row["original_class"] == "suffix-composition":
            assert row["original_evidence"] in ("%@.vsh", "%s.vsh", "%@.fsh", "%s.fsh"), row
    # Whole-APK sweep: nothing outside the pinned ELF names a shipped shader.
    sweep = record["sweep"]
    assert sweep["native_libraries"] == 24, sweep
    assert sweep["data_files"] == 20, sweep
    assert sweep["found_in_native"] == {}, sweep["found_in_native"]
    assert sweep["found_in_data"] == {}, sweep["found_in_data"]

    pairs = {r["name"].rsplit(".", 1)[0] for r in rows if r["stage"] == "vertex"}
    frags = {r["name"].rsplit(".", 1)[0] for r in rows if r["stage"] == "fragment"}
    assert pairs == frags, sorted(pairs ^ frags)

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["name", "stage", "bytes", "sha256", "original_class",
                           "original_evidence", "replacement_referenced",
                           "mapped_uses"], tsv_rows[0]
    assert len(tsv_rows) == len(rows) + 1, (len(tsv_rows), len(rows))
    for tsv_row, row in zip(tsv_rows[1:], rows):
        assert tsv_row[0] == row["name"] and tsv_row[3] == row["sha256"], (tsv_row, row)
        assert tsv_row[4] == row["original_class"], (tsv_row, row)
    print(f"shader-coverage: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
