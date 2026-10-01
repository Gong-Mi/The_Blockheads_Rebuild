#!/usr/bin/env python3
"""Contract test for the item attribute matrix (no ELF needed in CI).

Pins the decoded counts, the memorable predicates (luminous, gem blocks, the clothing
slot sets) and the honest parts: two always-constant predicates and 48 bodies still
unclassified.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "item_predicates.tsv"
JSON_PATH = NATIVE / "item_predicates.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXCLUSION = {"_Z28itemTypeIsValidInventoryItem8ItemType",
             "_Z19itemTypeIsStackable8ItemTypett", "_Z20itemTypeCanBeColored8ItemType",
             "_Z15itemTypeIsMoney8ItemType", "_Z17itemTypeIsPigment8ItemType",
             "_Z15itemTypeIsMetal8ItemType", "_Z13itemTypeIsGem8ItemType"}
EXPECTED = {
    "symbols_with_itemtype": 95,
    "decoded": 95,
    "by_kind": {"unclassified": 48, "equals-set": 45, "always-constant": 2},
    "with_returned_constant": 2,
    "predicates_naming_item_types": 51,
    "distinct_item_types_named": 191,
    "item_types_in_domain": 426,
    "predicates_with_accept_set": 37,
    "predicates_with_reject_set": 33,
    "composed_predicates": 32,
    "distinct_accepted_item_types": 261,
    "distinct_rejected_item_types": 195,
    "polarity_review_flags": 11,
}
CASES = {
    "_Z16itemTypeIsLiquid8ItemType": ("always-constant", []),
    "_Z22itemTypeCarriesLiquids8ItemType": ("always-constant", []),
    "_Z18itemTypeIsLuminous8ItemType": ("equals-set", [1105]),
    "_Z18itemTypeIsGemBlock8ItemType": ("equals-set", [1098, 1099, 1100, 1101, 1102]),
    "_Z23itemTypeCanBeWornOnHead8ItemType": ("equals-set", [289, 293]),
    "_Z23itemTypeCanBeWornOnLegs8ItemType": ("equals-set", [287, 291]),
    "_Z23itemTypeCanBeWornOnFeet8ItemType": ("equals-set", [290, 294]),
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "matrix is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]

    by_name = {p["name"]: p for p in record["predicates"]}
    for name, (kind, items) in CASES.items():
        assert name in by_name, name
        assert by_name[name]["kind"] == kind, by_name[name]
        assert by_name[name]["item_types"] == items, by_name[name]
    for name in ("_Z16itemTypeIsLiquid8ItemType", "_Z22itemTypeCarriesLiquids8ItemType"):
        assert by_name[name]["returned"] == 0, by_name[name]

    # The exclusion lists: positive-named predicates whose literals are all rejections.
    flagged = set(record["review_flags"])
    assert EXCLUSION <= flagged, sorted(EXCLUSION - flagged)
    by_name = {p["name"]: p for p in record["predicates"]}
    for name in EXCLUSION:
        assert by_name[name]["polarity_review"] is True, name
        assert by_name[name]["accepts"] == [], by_name[name]
        assert by_name[name]["rejects"], by_name[name]
    money = by_name["_Z15itemTypeIsMoney8ItemType"]
    assert money["rejects"] == [166, 167], money

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["name", "address", "size", "kind", "accepts", "rejects",
                           "calls"], tsv_rows[0]
    assert len(tsv_rows) == EXPECTED["decoded"] + 1, len(tsv_rows)

    print(f"item-predicates: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
