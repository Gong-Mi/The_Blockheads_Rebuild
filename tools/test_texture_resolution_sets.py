#!/usr/bin/env python3
"""Contract test for the texture resolution sets (no assets needed in CI).

Pins the traps that make this table worth having: the ratio is not uniform, one
pair scales differently per axis, and HDTex/ membership does not imply a size
change.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "texture_resolution_sets.tsv"
JSON_PATH = NATIVE / "texture_resolution_sets.json"
EXPECTED = {
    "names_with_multiple_copies": 127,
    "identical_duplicate": 2,
    "sd_hd_pair": 122,
    "same_size_distinct_content": 2,
    "distinct_sizes_no_hd": 1,
    "non_uniform_ratio": 1,
    "non_integral_ratio": 0,
    "ratio_1x_hd_copies": 0,
}
HEADER = ["name", "kind", "copies", "sd_path", "sd_size", "hd_path", "hd_size",
          "ratio", "ratio_uniform", "integral_ratio"]


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["ratio_histogram"] == {"2x": 1, "32x": 1, "4x": 97, "8x": 23}, \
        record["ratio_histogram"]

    rows = {r["name"]: r for r in record["rows"]}
    assert len(rows) == EXPECTED["names_with_multiple_copies"], len(rows)

    yak = rows["yakNeck.png"]
    assert yak["ratio"] == [8.0, 4.0], yak["ratio"]
    assert yak["ratio_uniform"] is False, yak
    assert rows["Sun.png"]["ratio"] == [32.0, 32.0], rows["Sun.png"]["ratio"]
    assert rows["sharkSideFin.png"]["ratio"] == [2.0, 2.0]
    assert rows["hat_santa.png"]["kind"] == "identical-duplicate", rows["hat_santa.png"]
    assert rows["hat_santa.png"]["sd"] is not None and rows["hat_santa.png"]["hd"] is not None
    for name in ("bannedPainting.png", "tulipFlower.png"):
        row = rows[name]
        assert row["kind"] == "same-size-distinct-content", row
        assert row["sd"]["width"] == row["hd"]["width"], row
    assert rows["mainMenuBackground.png"]["kind"] == "distinct-sizes-no-hd"

    for row in record["rows"]:
        for entry in row["entries"]:
            assert len(entry["sha256"]) == 64, entry
            assert entry["width"] and entry["height"], entry
        if row["kind"] == "sd-hd-pair":
            assert row["integral_ratio"] is True, row

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == HEADER, tsv_rows[0]
    assert len(tsv_rows) == len(record["rows"]) + 1, len(tsv_rows)
    for tsv_row, row in zip(tsv_rows[1:], record["rows"]):
        assert tsv_row[0] == row["name"], (tsv_row, row)
        assert tsv_row[1] == row["kind"], (tsv_row, row)

    print(f"texture-sets: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
