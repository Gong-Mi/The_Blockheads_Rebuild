#!/usr/bin/env python3
"""Contract test for the shader declaration cross-check (no assets needed in CI).

The point of this artifact is the classification, not a diff: 63 of 147 tokens in
the mapping cells name something the shaders never declare. If a future edit
starts calling those mismatches, or starts treating the cells as declaration
lists, this test fails.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "shader_declaration_crosscheck.tsv"
JSON_PATH = NATIVE / "shader_declaration_crosscheck.json"
EXPECTED = {
    "mapping_rows": 34,
    "shaders_referenced": 8,
    "shaders_missing_source": 0,
    "tokens": 147,
    "declared_attribute": 41,
    "declared_uniform": 43,
    "optional_declared": 0,
    "undeclared_binding_markers": 63,
    "rows_with_undeclared_tokens": 27,
    "declared_attributes_never_claimed": 97,
}
FIELDS = ["class", "method", "shader", "shader_files_present", "declared_attributes",
          "attribute_tokens", "declared_uniforms", "uniform_tokens",
          "undeclared_tokens"]


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["counts"] == EXPECTED, record["counts"]
    assert len(record["mapping"]["sha256"]) == 64

    rows = record["rows"]
    assert len(rows) == EXPECTED["mapping_rows"], len(rows)
    for row in rows:
        assert row["shader_files_present"] is True, row
        declared = set(row["declared_attributes"]) | set(row["declared_uniforms"])
        for token in row["attribute_tokens"] + row["uniform_tokens"]:
            assert token["class"] in ("declared-attribute", "declared-uniform",
                                      "optional-declared", "undeclared"), token
            if token["class"] == "undeclared":
                assert token["token"] not in declared, token
        assert sorted(row["undeclared_tokens"]) == sorted(
            t["token"] for t in row["attribute_tokens"] + row["uniform_tokens"]
            if t["class"] == "undeclared"), row

    first = rows[0]
    assert first["shader"] == "StandardObject", first
    assert first["declared_attributes"] == ["position", "texCoord"], first
    assert sorted(first["undeclared_tokens"]) == ["ColoredNoTexture", "color"], first
    never = record["never_claimed_attributes"]
    assert never["Block.vsh" if "Block.vsh" in never else "Block"] == \
        ["other", "paintColor", "position", "texCoord"], never.get("Block")
    assert never["BlockheadBody"] == ["normal", "position", "texCoord"], never["BlockheadBody"]

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == FIELDS, tsv_rows[0]
    assert len(tsv_rows) == len(rows) + 1, (len(tsv_rows), len(rows))
    for tsv_row, row in zip(tsv_rows[1:], rows):
        assert tsv_row[2] == row["shader"], (tsv_row, row)
        assert tsv_row[8] == ",".join(row["undeclared_tokens"]), (tsv_row, row)

    print(f"shader-declaration-crosscheck: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
