#!/usr/bin/env python3
"""Contract test for the tile sprite domain join (no ELF needed in CI).

Pins that the domain is closed (77/77, nothing unresolved), that the provenance
of every cell is recorded rather than flattened, and that the 43 inline cells
still agree with the item sprite domain - the cross-check is the whole point of
the join, so a disagreement must fail here instead of shipping.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "tile_sprite_domain.tsv"
JSON_PATH = NATIVE / "tile_sprite_domain.json"
EXPECTED = {
    "tile-map-inline": 43,
    "item-sprite-domain": 25,
    "contents-conditional": 9,
    "unresolved": 0,
    "tile_types": 77,
    "cross_checked": 43,
    "cross_check_mismatches": 0,
    "with_cell": 68,
    "conditional_rows_in_table": 87,
}
FIELDS = ["tile_type", "tile_resolution", "item_type", "provenance", "image",
          "col", "row", "u", "v", "case_target", "cell_cross_check", "note",
          "conditional_cases", "reason"]


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["mismatches"] == [], record["mismatches"]
    for key in ("tile_item_map", "item_sprite_map", "tile_conditional"):
        assert len(record["inputs"][key]["sha256"]) == 64, key

    rows = record["rows"]
    assert len(rows) == EXPECTED["tile_types"], len(rows)
    assert [r["tile_type"] for r in rows] == list(range(1, 78)), "domain not contiguous"
    for row in rows:
        assert row["provenance"] in EXPECTED, row
        if row["provenance"] == "tile-map-inline":
            assert row["cell_cross_check"] == "match", row
        if row["provenance"] == "item-sprite-domain":
            assert row["col"] is not None and row["item_type"] is not None, row
        if row["provenance"] == "contents-conditional":
            assert row["conditional_cases"] >= 1, row
            assert "contentsType" in row["note"], row
    inline = [r for r in rows if r["provenance"] == "tile-map-inline"]
    assert len(inline) == EXPECTED["cross_checked"], len(inline)
    assert all(r["cell_cross_check"] == "match" for r in inline), inline

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == FIELDS, tsv_rows[0]
    assert len(tsv_rows) == len(rows) + 1, (len(tsv_rows), len(rows))
    for tsv_row, row in zip(tsv_rows[1:], rows):
        assert int(tsv_row[0]) == row["tile_type"], (tsv_row, row)
        assert tsv_row[3] == row["provenance"], (tsv_row, row)

    print(f"tile-sprite-domain: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
