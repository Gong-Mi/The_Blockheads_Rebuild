#!/usr/bin/env python3
"""Contract test for the record-field / header cross-check (no ELF needed in CI)."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "tile_record_header_crosscheck.tsv"
JSON_PATH = NATIVE / "tile_record_header_crosscheck.json"
EXPECTED = {
    "extracted_offsets": 4,
    "documented_offsets": 4,
    "agreeing_offsets": 2,
    "undocumented_extracted": 2,
    "documented_but_not_read_by_drawing_path": 2,
    "record_stride_extracted": 64,
    "record_size_declared": 64,
    "size_agrees": True,
}
NAMES = {1: "backWallType", 3: "contentsType"}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["header"]["documented_offsets"] == {
        "0": "type", "1": "backWallType", "3": "contentsType",
        "7": "temperatureScaleByte"}, record["header"]["documented_offsets"]
    assert record["header"]["asserts_size"] is True, record["header"]

    rows = {r["offset"]: r for r in record["rows"]}
    assert sorted(rows) == [1, 3, 8, 12], sorted(rows)
    for offset, name in NAMES.items():
        assert rows[offset]["header_name"] == name, rows[offset]
        assert rows[offset]["documented"] is True, rows[offset]
    for offset in (8, 12):
        assert rows[offset]["documented"] is False, rows[offset]
        assert rows[offset]["header_name"] == "", rows[offset]
    unread = {e["offset"] for e in record["documented_but_unread"]}
    assert unread == {0, 7}, unread

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["offset", "header_name", "documented", "read_sites", "purpose"], tsv_rows[0]
    assert len(tsv_rows) == 1 + EXPECTED["extracted_offsets"] + EXPECTED[
        "documented_but_not_read_by_drawing_path"], len(tsv_rows)

    print(f"tile-record-header-crosscheck: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
