#!/usr/bin/env python3
"""Contract test for the save-data field histogram (no archive needed in CI).

Pins the measured domains, including the two fields this world never sets (raw[5], raw[12])
and the single state behind every non-zero raw[8].
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "tile_record_save_data.tsv"
JSON_PATH = NATIVE / "tile_record_save_data.json"
EXPECTED = {
    "blocks_records": 40,
    "tiles": 40960,
    "decompressed_sizes": [65541],
    "tiles_per_record": 1024,
}
DOMAINS = {"0": (15, 0), "1": (7, 0), "3": (19, 40379), "5": (1, 40960),
           "6": (10, 40900), "7": (7, 36481), "8": (21, 40902), "12": (1, 40960)}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]
    assert len(record["archive_manifest_sha256"]) == 64, record["archive_manifest_sha256"]

    for field, (distinct, zero) in DOMAINS.items():
        entry = record["fields"][field]
        assert entry["distinct"] == distinct, (field, entry)
        assert entry["zero"] == zero, (field, entry)
    for field in ("5", "12"):
        assert record["fields"][field]["top"] == [[0, EXPECTED["tiles"]]], record["fields"][field]
    assert record["fields"]["0"]["top"][0] == [1, 26641], record["fields"]["0"]

    states = record["nonzero_offset8_states"]
    assert states and states[0] == {"type": 2, "back_wall": 2, "contents": 6,
                                    "temperature_scale_byte": 255, "tiles": 26}, states[0]
    assert all(s["temperature_scale_byte"] == 255 for s in states), states
    for window, entry in record["int16_windows"].items():
        assert entry["distinct_nonzero"] >= 1, (window, entry)
    assert record["int16_windows"]["8"]["small_nonzero"] == 20, record["int16_windows"]["8"]

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["field", "distinct", "zero", "top_values"], tsv_rows[0]
    assert any(row[0] == "raw[5]" for row in tsv_rows[1:]), tsv_rows[:4]

    print(f"tile-record-save-data: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
