#!/usr/bin/env python3
"""Contract test for the sprite cell content check (no assets or Pillow in CI).

Pins the convergence: the image-id domain has ink in all 82 cells of TileMap.png and
11 out-of-bounds rectangles in Items.png - the same 11 the geometry contract once
reported before the domain was re-attributed.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "sprite_cell_content.tsv"
JSON_PATH = NATIVE / "sprite_cell_content.json"
EXPECTED = {
    "formula_rows": 344,
    "formula_with_ink_in_items": 338,
    "image_rows": 82,
    "image_with_ink_in_tilemap": 82,
    "image_with_ink_in_items": 70,
    "image_out_of_bounds_in_items": 11,
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["cell_px"] == 64, record["cell_px"]
    for key in ("items", "tilemap"):
        assert len(record["atlases"][key]["sha256"]) == 64, key

    tilemap = record["image_domain_in_tilemap"]
    assert tilemap["with_ink"] == tilemap["rows"] == 82, tilemap
    assert tilemap["out_of_bounds"] == 0, tilemap
    items = record["image_domain_in_items"]
    assert items["out_of_bounds"] == 11, items
    assert items["rows"] == tilemap["rows"], (items, tilemap)
    formula = record["formula_domain_in_items"]
    assert formula["out_of_bounds"] == 0 and formula["empty"] == 6, formula
    for entry in (tilemap, items, formula):
        for sample in entry["samples"]:
            assert "ink" in sample and "in_bounds" in sample, sample

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["domain", "atlas", "rows", "with_ink", "empty",
                           "out_of_bounds"], tsv_rows[0]
    assert any(row[0] == "image_domain_in_tilemap" and row[1] == "TileMap.png"
               for row in tsv_rows[1:]), tsv_rows[:4]

    print(f"sprite-cell-content: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
