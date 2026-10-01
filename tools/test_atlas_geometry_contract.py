#!/usr/bin/env python3
"""Contract test for the atlas geometry contract (no assets needed in CI).

Pins the one real violation this check found: 11 cells of the
imageTypeForItemType domain cannot be placed in Items.png under the prototype
grid (their rectangles start past the atlas height). If a future change makes
those rows fit - by proving a different page or a different cell size - this test
must be updated deliberately, not incidentally.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "atlas_geometry_contract.tsv"
JSON_PATH = NATIVE / "atlas_geometry_contract.json"
EXPECTED = {
    "item_formula_rows": 344,
    "item_formula_violations": 0,
    "item_jump_rows": 82,
    "item_jump_violations": 11,
    "tile_rows": 68,
    "tile_violations": 0,
    "fonts": 5,
    "font_glyphs": 500,
    "font_glyphs_outside_canvas": 0,
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]

    items = record["checks"]["items"]
    assert [f["size"] for f in items["files"]] == [[512, 256], [2048, 1024]], items["files"]
    assert items["formula_domain"]["violations"] == 0, items["formula_domain"]
    assert items["formula_domain"]["cell_px"] == 64
    jump = items["jump_table_domain"]
    assert jump["violations"] == EXPECTED["item_jump_violations"], jump
    examples = {e["label"].split()[1]: e for e in jump["examples"]}
    assert examples["1087"]["row"] == 18, examples["1087"]
    assert examples["1087"]["rect"] == [448, 1152, 64, 64], examples["1087"]
    assert examples["1089"]["rect"] == [0, 1344, 64, 64], examples["1089"]
    for example in jump["examples"]:
        assert example["exceeds"].endswith("height"), example
        assert example["rect"][1] + example["rect"][3] > 1024, example

    tiles = record["checks"]["tiles"]
    assert [f["size"] for f in tiles["files"]] == [[512, 512], [2048, 2048]], tiles["files"]
    assert tiles["cells"]["violations"] == 0, tiles["cells"]
    assert "inherited" in tiles["note"], tiles["note"]

    fonts = record["checks"]["fonts"]["checks"]
    assert len(fonts) == EXPECTED["fonts"], fonts
    assert sum(f["glyphs"] for f in fonts) == EXPECTED["font_glyphs"]
    for font in fonts:
        assert font["exceeding_declared_canvas"] == 0, font
        assert font["duplicate_rects"] == 0, font
    odd = next(f for f in fonts if f["font"] == "04b03_16.fnt")
    assert odd["declared"] == [256, 128] and odd["actual_png"] == [2048, 1024], odd

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["scope", "label", "col", "row", "cell_px", "atlas", "violation"], tsv_rows[0]
    assert len(tsv_rows) == 1 + len(jump["examples"]) + len(tiles["cells"]["examples"]) + EXPECTED["fonts"], len(tsv_rows)
    assert any(row[0] == "items-jump" for row in tsv_rows[1:]), tsv_rows[:3]

    print(f"atlas-geometry: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
