#!/usr/bin/env python3
"""Contract test for the glyph content check (no assets or Pillow needed in CI).

Pins the measured result: 51 inkless rectangles split into 47 on the 8x-scaled
`04b03_16` face and one space glyph per font, plus the scale probe proving those 47
fill in at 8x.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "font_glyph_content.tsv"
JSON_PATH = NATIVE / "font_glyph_content.json"
EXPECTED = {
    "fonts": 5,
    "fonts_needing_scale": 1,
    "glyphs_with_ink_at_implied_scale": 99,
    "atlases_present": 5,
    "glyphs": 500,
    "glyphs_with_ink": 449,
    "glyphs_empty": 51,
}
EMPTY_BY_FONT = {"04b03_16.fnt": 47, "04b03black_16.fnt": 1,
                 "04b03embossed_16.fnt": 1, "Blockheads_64.fnt": 1,
                 "Blockheadsblack_64.fnt": 1}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]

    fonts = {f["font"]: f for f in record["fonts"]}
    assert len(fonts) == EXPECTED["fonts"], sorted(fonts)
    for name, empty in EMPTY_BY_FONT.items():
        assert fonts[name]["glyphs_empty"] == empty, fonts[name]
        assert fonts[name]["atlas_present"] is True, fonts[name]
        assert len(fonts[name]["atlas_sha256"]) == 64, fonts[name]
    for font in record["fonts"]:
        assert font["glyphs_with_ink"] + font["glyphs_empty"] == font["glyphs"], font
        if font["glyphs_empty"]:
            assert font["empty_samples"], font

    probe = fonts["04b03_16.fnt"]["scale_probe"]
    assert probe["ratio"] == 8, probe
    assert probe["glyphs_with_ink_at_scale"] == 99, probe
    others = [f for name, f in fonts.items() if name != "04b03_16.fnt"]
    assert all("scale_probe" not in f for f in others), "scaled probe applied to a 1x font"

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["font", "atlas", "glyphs", "with_ink", "empty",
                           "max_ink_fraction"], tsv_rows[0]
    sample_rows = [r for r in tsv_rows[1:] if r[0] == "empty"]
    assert len(sample_rows) >= 5, tsv_rows[1:8]
    # header + 5 font rows, then the empty samples.
    assert tsv_rows[6][0] == "empty", tsv_rows[6]
    # The single empty glyph of the four sound fonts is the space character.
    for font in record["fonts"]:
        if font["glyphs_empty"] == 1:
            assert font["empty_samples"][0]["char_id"] == 32, font
    assert fonts["04b03_16.fnt"]["empty_samples"][0]["char_id"] == 32, fonts["04b03_16.fnt"]

    print(f"font-glyph-content: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
