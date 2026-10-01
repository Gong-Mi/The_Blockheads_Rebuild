#!/usr/bin/env python3
"""Contract test for the Items.png sprite-coordinate table (no ELF needed in CI).

The extraction needs the pinned original ELF, which is not in the repository.
CI enforces instead that the committed artifacts stay in lockstep with each
other and keep the properties the extractor derives from the binary.
"""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "original_item_sprite_map.tsv"
JSON_PATH = NATIVE / "item_sprite_map.json"
EXPLICIT = NATIVE / "original_item_image_map.tsv"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"

EXPECTED_CONSTANTS = {
    "half_texel": 1.0 / 2048.0,
    "u_step": 1.0 / 32.0,
    "v_step": 1.0 / 16.0,
    "u_span": 126.0 / 2048.0,
    "v_span": 62.0 / 2048.0,
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "table is not from the pinned ELF"
    assert record["function"] == "texCoordsForItemType"
    assert record["function_address"] == "0x004d6040"
    assert record["grid"] == {"cols": 32, "rows": 16, "cell_px": 64,
                              "atlas": "Items.png 2048x1024"}

    for name, expected in EXPECTED_CONSTANTS.items():
        entry = record["constants"][name]
        actual = entry.get("f64", entry.get("f32"))
        assert actual == expected, f"{name}: {actual!r} != {expected!r}"

    rows = record["rows"]
    assert len(rows) == 426, len(rows)
    counts = record["counts"]
    assert counts == {"formula": 344, "jump_table": 82, "unresolved": 0}, counts

    explicit = {}
    for row in csv.DictReader(EXPLICIT.open(newline="", encoding="utf-8"),
                              delimiter="\t"):
        explicit[int(row["item_type"])] = row

    for row in rows:
        item = row["item_type"]
        if row["source"].startswith("formula"):
            assert item < 1024, item
            assert row["col"] == item % 32, row
            assert row["row"] == item // 32, row
            assert abs(row["u"] - (row["col"] / 32 + 1.0 / 2048.0)) < 1e-12, row
            assert abs(row["v"] - (row["row"] / 16 + 1.0 / 2048.0)) < 1e-12, row
            assert abs(row["u_span"] - 126.0 / 2048.0) < 1e-12, row
            assert abs(row["v_span"] - 62.0 / 2048.0) < 1e-12, row
            assert row["atlas"] == "Items.png", row
        else:
            assert item >= 1024, item
            assert row["source"] == "imageTypeForItemType@0x004d71dc", row
            ref = explicit[item]
            assert row["image"] == ref["image_dataA0"], row
            assert str(row["col"]) == ref["col_dataA0"], row
            assert str(row["row"]) == ref["row_dataA0"], row

    # TSV <-> JSON lockstep
    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")),
                               delimiter="\t"))
    header, body = tsv_rows[0], tsv_rows[1:]
    assert header == ["item_type", "atlas", "image", "col", "row", "u", "v",
                      "u_span", "v_span", "source"], header
    assert len(body) == len(rows), (len(body), len(rows))
    for tsv_row, rec_row in zip(body, rows):
        for column, value in zip(header, tsv_row):
            if column in ("u", "v", "u_span", "v_span") and value:
                assert abs(float(value) - rec_row[column]) < 1e-12, (tsv_row, rec_row)
            elif column not in ("u", "v", "u_span", "v_span"):
                assert value == str(rec_row[column]), (tsv_row, rec_row)

    print(f"item-sprite: PASS ({len(rows)} rows; formula={counts['formula']} "
          f"jump_table={counts['jump_table']} unresolved={counts['unresolved']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
