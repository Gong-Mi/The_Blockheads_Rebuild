#!/usr/bin/env python3
"""Contract test for the reloadDrawBlock tile-content render map (no ELF in CI).

Enforces that the content domain [3, 123] is closed explicitly: every value has
exactly one row with a stated resolution, direct rows carry a consistent cell,
shared-body rows are not silently empty, and the one unresolved value stays
labelled with its case target so it cannot be forgotten.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "original_tile_content_render_map.tsv"
JSON_PATH = NATIVE / "tile_content_render_map.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
SHARED_BODY = "0x00a22d70"


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "map is not from the pinned ELF"
    assert record["table_address"] == "0x00a221f4"
    assert record["content_domain"] == [3, 123]
    assert record["shared_body_address"] == SHARED_BODY
    assert record["counts"] == {"direct": 61, "shared-body": 59, "unresolved": 1}, record["counts"]

    rows = record["rows"]
    values = [row["content_value"] for row in rows]
    assert values == list(range(3, 124)), "the domain must be closed with one row per value"

    for row in rows:
        res = row["resolution"]
        if res in ("direct", "conditional"):
            assert row["draw_image"] or row["paired_image"], row
            if row["draw_image"]:
                assert row["draw_col"] == str(int(row["draw_image"]) % 32), row
                assert row["draw_row"] == str(int(row["draw_image"]) // 32), row
        elif res == "shared-body":
            assert row["case_target"] == SHARED_BODY, row
            assert row["draw_image"] == "" and row["paired_image"] == "", row
        else:
            assert res == "unresolved", row
            # pinned follow-up marker: value 46 dispatches on its own body
            assert row["content_value"] == 46 and row["case_target"] == "0x00a22b90", row

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert len(tsv_rows) == len(rows) + 1, (len(tsv_rows), len(rows))
    assert tsv_rows[0][0] == "content_value" and tsv_rows[0][8] == "resolution"
    for tsv_row, row in zip(tsv_rows[1:], rows):
        assert int(tsv_row[0]) == row["content_value"], tsv_row
        assert tsv_row[8] == row["resolution"], (tsv_row, row)
        assert tsv_row[9] == row["case_target"], (tsv_row, row)

    print(f"tile-content-render: PASS (121 values: {record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
