#!/usr/bin/env python3
"""Contract test for the text asset inventory (no assets needed in CI).

Pins the finding that matters: there is no localization data to consume (one
45-byte iOS stub, zero key/value pairs), so labels have to come from the binary's
string table, and item display names are still open.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "text_asset_inventory.tsv"
JSON_PATH = NATIVE / "text_asset_inventory.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {
    "localization_files": 1,
    "localization_key_value_pairs": 0,
    "elf_nul_strings": 42357,
    "sentence_like_strings": 413,
    "replacement_localization_references": 0,
    "author_authored_data_files": 2,
    "probe_symbols": {"itemName": 0, "itemNameForType": 0, "nameForItemType": 0,
                      "displayName": 1, "localizedString": 0, "NSLocalizedString": 0},
}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "inventory is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["localization_files"] == [
        {"path": "en.lproj/InfoPlist.strings", "bytes": 45, "key_value_pairs": 0}
    ], record["localization_files"]
    assert record["filter"]["min_spaces"] == 2, record["filter"]

    sentences = record["sentences"]
    assert len(sentences) == EXPECTED["sentence_like_strings"], len(sentences)
    for sentence in sentences:
        assert len(sentence) >= 12 and sentence[0].isupper(), sentence
        assert scene := sentence.rstrip().endswith((".", "!", "?", ":")), sentence
        assert not any(ch in sentence for ch in "/\\{}[]<>@|"), sentence
    assert "A BETTER FASTER KILN." in sentences, sentences[:3]
    assert sentences == sorted(sentences), "catalogue is not deterministic"

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["kind", "key", "value"], tsv_rows[0]
    assert any(row[0] == "localization" for row in tsv_rows[1:]), tsv_rows[:3]
    assert any(row[0] == "probe-symbol" and row[1] == "displayName" for row in tsv_rows[1:])

    print(f"text-assets: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
