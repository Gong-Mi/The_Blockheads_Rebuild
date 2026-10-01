#!/usr/bin/env python3
"""Contract test for the decoded item mappings (no ELF needed in CI)."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "item_mapping_functions.tsv"
JSON_PATH = NATIVE / "item_mapping_functions.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {"functions": 4, "with_tables": 2, "mapped_entries": 14,
            "pairs_decoded": 26, "pairs_with_output": 26, "table_values_resolved": 14}
TREE_PAIRS = {46: 6, 60: 7, 77: 8, 78: 9, 160: 10}
DYED_PAIRS = {85: 114, 84: 113, 117: 118, 115: 116, 122: 123, 130: 131, 124: 125,
              126: 128, 127: 129, 169: 172, 170: 173}
PLANT_PAIRS = {54: 1, 61: 2, 62: 3, 71: 4, 112: 5, 144: 6, 295: 7, 310: 9, 316: 10}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "mappings are not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]

    by_name = {f["name"]: f for f in record["functions"]}
    tree = {p["input"]: p["output"] for p in by_name["_Z23treeTypeForSeedItemType8ItemType"]["pairs"]}
    assert tree == TREE_PAIRS, tree
    plant = {p["input"]: p["output"] for p in by_name["_Z24plantTypeForSeedItemType8ItemType"]["pairs"]}
    assert plant == PLANT_PAIRS, plant

    cage = by_name["_Z23npcTypeFromCageItemType8ItemType"]
    assert [(p["input"], p["output"]) for p in cage["pairs"]] == [(303, 1)], cage["pairs"]
    table = cage["table"]
    assert table["entry_count"] == 7, table
    assert [e["output"] for e in table["entries"]] == [3, 8, 2, 7, 0, 0, 3], table

    dyed = by_name["_Z30genericDyedItemTypeForItemType8ItemType"]
    dyed_pairs = {p["input"]: p["output"] for p in dyed["pairs"]}
    assert dyed_pairs == DYED_PAIRS, dyed_pairs
    assert all(p.get("form") == "fallthrough" for p in dyed["pairs"]), dyed["pairs"]
    assert dyed["table"] is None, dyed

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["function", "kind", "input", "output", "target"], tsv_rows[0]
    assert len(tsv_rows) == 1 + EXPECTED["pairs_decoded"] + EXPECTED["mapped_entries"], len(tsv_rows)

    print(f"item-mappings: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
