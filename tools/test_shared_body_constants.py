#!/usr/bin/env python3
"""Contract test for the shared-body constants join (no ELF needed in CI).

Pins the join that names the six constants: Apple/Cherry/Maple leaf and trunk-leaf
contents, exactly one producer each, and the write-site evidence that all 61 direct
cases write the compared slot.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "shared_body_constants.tsv"
JSON_PATH = NATIVE / "shared_body_constants.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {
    "constants": 6,
    "constants_with_a_producer": 6,
    "constants_with_exactly_one_producer": 6,
    "leaf_named_contents": 31,
    "special_cased_are_leaf_named": 6,
    "direct_cases_scanned": 61,
    "direct_cases_writing_the_compared_slot": 61,
}
PAIRS = {224: (5, "AppleTreeTrunkLeaf"), 256: (3, "AppleTreeLeaf"),
         265: (21, "CherryTreeLeaf"), 274: (23, "CherryTreeTrunkLeaf"),
         480: (11, "MapleTreeTrunkLeaf"), 512: (9, "MapleTreeLeaf")}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "join is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]

    entries = {e["constant"]: e for e in record["constants"]}
    assert sorted(entries) == sorted(PAIRS), sorted(entries)
    for constant, (content, name) in PAIRS.items():
        producers = entries[constant]["producers"]
        assert len(producers) == 1, (constant, producers)
        assert producers[0]["content_value"] == content, producers
        assert producers[0]["candidate_name"] == name, producers
        assert entries[constant]["is_leaf_named"] is True, entries[constant]
    for sample in record["slot_write_samples"]:
        assert any(w["slot"] in ("fp-0x540", "fp-0x544") for w in sample["writes"]), sample

    leaf_values = record["leaf_named_content_values"]
    assert len(leaf_values) == EXPECTED["leaf_named_contents"], len(leaf_values)
    for content, _ in PAIRS.values():
        assert content in leaf_values, content

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["constant", "content_value", "candidate_name", "draw_col",
                           "draw_row", "is_leaf"], tsv_rows[0]
    assert len(tsv_rows) == EXPECTED["constants"] + 1, len(tsv_rows)

    print(f"shared-body-constants: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
