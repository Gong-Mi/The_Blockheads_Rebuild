#!/usr/bin/env python3
"""Contract test for the item display-name source audit (no ELF needed in CI).

Pins the audited result: no name table ships, the price data has no name field, and
the standalone-token hits are name-list/class contexts rather than item labels. The
test also pins that the artifact classifies hit contexts instead of returning a
boolean, which is the point of the audit.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "item_display_name_sources.tsv"
JSON_PATH = NATIVE / "item_display_name_sources.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {
    "reference_names": 426,
    "strings_files": 1,
    "strings_key_value_pairs": 0,
    "defaultprices_entries": 266,
    "defaultprices_fields": ["id", "old_price", "price"],
    "words_probed": 409,
    "words_with_standalone_hit": 34,
    "hit_context_name_list": 35,
    "hit_context_objc_symbol": 0,
    "hit_context_other": 81,
    "exact_objc_class_matches": 18,
    "partial_objc_class_matches": 72,
    "name_table_found": 0,
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "audit is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]
    assert "name field" in record["claim"] or "No name table" in record["claim"], record["claim"]

    exact = record["class_name_matches"]["exact"]
    for name in ("Torch", "Door", "Ladder", "FreightCar", "FishingRod"):
        assert name in exact, name
    assert len(exact) <= EXPECTED["exact_objc_class_matches"], len(exact)

    hits = record["word_hits"]
    assert len(hits) == EXPECTED["words_with_standalone_hit"], len(hits)
    for word, info in hits.items():
        assert info["offsets"] >= 1, (word, info)
        assert set(info["contexts"]) <= {"name-list", "objc-symbol", "other"}, (word, info)
    for word in ("Amethyst", "Clay"):
        assert word in hits, word
        assert "name-list" in hits[word]["contexts"], hits[word]

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["kind", "name", "value"], tsv_rows[0]
    assert any(row[0] == "source" and row[1] == "strings" for row in tsv_rows[1:])
    assert any(row[0] == "word-hit" and row[1] == "Amethyst" for row in tsv_rows[1:])

    print(f"item-display-name-sources: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
