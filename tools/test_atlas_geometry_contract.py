#!/usr/bin/env python3
"""Contract test for the atlas geometry contract (no assets needed in CI).

Pins the corrected attribution: the item sprite table holds two domains that belong
to two different atlases (`formula` -> Items.png 32x16, image ids -> TileMap.png
32x32), and both are fully placeable. An earlier revision measured the image-id
domain against Items.png and reported 11 violations; that false finding must not
come back, and the derivation of those cells must stay labelled as derived.
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
    "item_image_id_rows": 82,
    "item_image_id_violations": 0,
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
    assert items["formula_domain"]["atlas"] == [2048, 1024]
    image_id = items["image_id_domain"]
    assert image_id["violations"] == 0, image_id
    assert image_id["atlas"] == [2048, 2048], image_id
    attribution = items["atlas_attribution"]
    assert attribution["formula"]["atlas"] == "Items.png", attribution
    assert attribution["formula"]["grid"] == "32 cols x 16 rows x 64 px", attribution
    assert attribution["image-id"]["atlas"] == "TileMap.png", attribution
    assert attribution["image-id"]["grid"] == "32 cols x 32 rows x 64 px", attribution
    assert "TileMap:32x32" in attribution["image-id"]["evidence"], attribution
    assert "wrong attribution" in items["note"], items["note"]

    # The derived cells must stay labelled as derived in the image map too.
    image_map = (NATIVE / "original_item_image_map.tsv").read_text(encoding="utf-8")
    header = image_map.splitlines()[0].split("\t")
    assert header[2] == "col_from_image_a0" and header[3] == "row_from_image_a0", header
    assert header[-1] == "derivation", header
    assert all("col=image%32,row=image//32 (derived; TileMap:32x32)" in line
               for line in image_map.splitlines()[1:]), "derivation column not filled"

    tiles = record["checks"]["tiles"]
    assert [f["size"] for f in tiles["files"]] == [[512, 512], [2048, 2048]], tiles["files"]
    assert tiles["cells"]["violations"] == 0, tiles["cells"]
    assert "inherited" in tiles["note"], tiles["note"]

    fonts = record["checks"]["fonts"]["checks"]
    assert len(fonts) == EXPECTED["fonts"] and sum(f["glyphs"] for f in fonts) == 500
    for font in fonts:
        assert font["exceeding_declared_canvas"] == 0, font
        assert font["duplicate_rects"] == 0, font
    odd = next(f for f in fonts if f["font"] == "04b03_16.fnt")
    assert odd["declared"] == [256, 128] and odd["actual_png"] == [2048, 1024], odd

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["scope", "label", "col", "row", "cell_px", "atlas", "violation"], tsv_rows[0]
    assert any(row[0] == "items-image-id" for row in tsv_rows[1:]) or len(tsv_rows) == 1 + EXPECTED["fonts"], \
        "image-id scope missing and no examples to justify it"

    print(f"atlas-geometry: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
