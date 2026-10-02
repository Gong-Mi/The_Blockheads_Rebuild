#!/usr/bin/env python3
"""Contract test for the tile shared-body structure decode (no ELF needed in CI).

Pins that the body really is a dispatch: six constants compared, a 77-entry inline
jump table with 51 distinct targets, and an animated-offset arithmetic path. Those
numbers are what justifies calling 59 tile values "shared-body" instead of
"unresolved".
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "tile_shared_body_structure.tsv"
JSON_PATH = NATIVE / "tile_shared_body_structure.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {
    "immediate_comparisons": 4,
    "register_comparisons": 3,
    "constants_compared": 6,
    "distinct_immediates": 4,
    "duplicate_immediates": 0,
    "branches": 4,
    "jump_table_entries": 77,
    "jump_table_distinct_targets": 51,
    "helper_calls": 3,
    "frame_slots_touched": 5,
    "branches_decoded": 51,
    "branches_with_movw_assignment": 51,
    "branches_writing_draw_slots": 51,
    "distinct_draw_values": 49,
    "distinct_mode_values": 3,
    "branches_with_equal_pair": 39,
    "branches_setting_a_mode": 50,
}
MODE_VALUES = [0, 2, 3]
CONSTANTS = [0xE0, 0x100, 0x109, 0x112, 0x1E0, 0x200]


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "decode is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["constants"] == CONSTANTS, record["constants"]
    assert record["body_address"] == "0x00a22d70", record["body_address"]
    assert record["jump_table"]["base"] == "0x00a22ed0", record["jump_table"]

    # The duplicated 0x112 compare is real and must stay visible.
    dupes = [c for c in record["register_comparisons"] if c["immediate"] == 0x112]
    assert len(dupes) == 2, record["register_comparisons"]
    assert record["register_comparisons"][0]["immediate"] == 0x109, record["register_comparisons"]
    for row in record["jump_table"]["sample"]:
        assert row["target"].startswith("0x00a2"), row
    for call in record["helper_calls"]:
        assert call["target"].startswith("0x00"), call
    assert "fp-0x540" in record["frame_slots_touched"], record["frame_slots_touched"]

    # Branch bodies decoded PER SLOT. The earlier reading (a bag of immediates)
    # conflated the draw pair with the mode and produced a "five values" set; the
    # separation is the finding, so both halves are pinned.
    branches = record["branches"]
    assert len(branches) == EXPECTED["branches_decoded"], len(branches)
    modes = sorted({b["mode"] for b in branches.values() if b["mode"] is not None})
    assert modes == MODE_VALUES, branches
    assert sum(1 for b in branches.values() if b["mode"] is None) == 1, branches
    for name, entry in branches.items():
        assert entry["slots"], (name, entry)
        assert entry["draw_values"], (name, entry)
        assert "fp-0x548" in entry["slots"] or "fp-0x54c" in entry["slots"], (name, entry)
        assert entry["pair_equal"] in (True, False), (name, entry)
    assert 109 in record["draw_values"] and 129 in record["draw_values"], record["draw_values"]
    assert record["mode_values"] == MODE_VALUES, record["mode_values"]
    assert sum(1 for b in branches.values() if b["pair_equal"]) == 39, branches

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["kind", "address", "detail"], tsv_rows[0]
    assert sum(1 for row in tsv_rows[1:] if row[0] == "compare") == EXPECTED["immediate_comparisons"]
    assert sum(1 for row in tsv_rows[1:] if row[0] == "compare-reg") == EXPECTED["register_comparisons"]
    assert any(row[0] == "jump-table" for row in tsv_rows[1:]), tsv_rows[:3]

    print(f"tile-shared-body: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
