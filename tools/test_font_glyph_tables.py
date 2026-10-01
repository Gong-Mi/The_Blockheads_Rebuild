#!/usr/bin/env python3
"""Contract test for the parsed BMFont metrics (no assets needed in CI).

Pins what the fonts actually say, including the two facts that would be easy to
"normalise away": one descriptor declaring a canvas its PNG is 8x larger than,
and two fonts sharing a single atlas page.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "font_glyph_tables.tsv"
JSON_PATH = NATIVE / "font_glyph_tables.json"
EXPECTED = {
    "fonts": 5,
    "glyphs": 500,
    "fonts_with_atlas": 5,
    "atlas_size_mismatches": 1,
    "ascii_codepoints_per_font": 95,
    "ascii_missing_total": 2,
    "kerning_pairs": 0,
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]
    fonts = {f["font"]: f for f in record["fonts"]}
    assert len(fonts) == EXPECTED["fonts"], sorted(fonts)

    odd = fonts["04b03_16.fnt"]
    assert odd["scale_w"] == 256 and odd["scale_h"] == 128, odd
    assert odd["atlas_size"] == [2048, 1024], odd
    assert odd["atlas_size_matches"] is False, odd
    others = [f for n, f in fonts.items() if n != "04b03_16.fnt"]
    assert all(f["atlas_size_matches"] is True for f in others), others

    # Two 64px fonts share one atlas; the black variant is not a separate page.
    assert fonts["Blockheads_64.fnt"]["atlas"] == "Blockheads_64.png"
    assert fonts["Blockheadsblack_64.fnt"]["atlas"] == "Blockheads_64.png"

    # Metrics stay inside the declared canvas even where the PNG is larger.
    for font in record["fonts"]:
        max_x = max(g["x"] + g["width"] for g in font["glyphs"])
        max_y = max(g["y"] + g["height"] for g in font["glyphs"])
        assert max_x <= font["scale_w"], (font["font"], max_x)
        assert max_y <= font["scale_h"], (font["font"], max_y)
    for name in ("Blockheads_64.fnt", "Blockheadsblack_64.fnt"):
        assert fonts[name]["ascii_missing"] == [126], fonts[name]["ascii_missing"]
    for name in ("04b03_16.fnt", "04b03black_16.fnt", "04b03embossed_16.fnt"):
        assert fonts[name]["ascii_missing"] == [], name

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["font", "char_id", "letter", "x", "y", "width", "height",
                          "xoffset", "yoffset", "xadvance", "page"], tsv_rows[0]
    assert len(tsv_rows) == EXPECTED["glyphs"] + 1, len(tsv_rows)
    assert len(record["rows"]) == EXPECTED["glyphs"], len(record["rows"])
    for tsv_row, row in zip(tsv_rows[1:], record["rows"]):
        assert tsv_row[0] == row["font"] and int(tsv_row[1]) == row["char_id"], (tsv_row, row)
        assert int(tsv_row[3]) == row["x"] and int(tsv_row[10]) == row["page"], (tsv_row, row)

    print(f"font-tables: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
