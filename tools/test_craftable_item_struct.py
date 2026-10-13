#!/usr/bin/env python3
"""Contract test for the CraftableItem layout (no ELF needed in CI).

Pins the parsed layout and the cross-check that makes it trustworthy: the packed size of
the encoding's fields equals the 124 bytes the savedict read-back measured.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "craftable_item_struct.tsv"
JSON_PATH = NATIVE / "craftable_item_struct.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {
    "fields": 11,
    "packed_size": 124,
    "blob_length_from_savedict": 124,
    "sizes_agree": True,
    "instance_size": 128,
    "int_arrays": 3,
    "array_bytes": 96,
}
LAYOUT = [(0, "i", 1, 4), (4, "i", 1, 4), (8, "i", 8, 32), (40, "i", 8, 32),
          (72, "i", 1, 4), (76, "i", 1, 4), (80, "i", 1, 4), (84, "S", 1, 2),
          (86, "S", 1, 2), (88, "i", 1, 4), (92, "i", 8, 32)]


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "layout is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["encoding"] == "{CraftableItem=ii[8i][8i]iiiSSi[8i]}", record["encoding"]

    fields = record["fields"]
    assert len(fields) == EXPECTED["fields"], len(fields)
    for field, (offset, kind, count, size) in zip(fields, LAYOUT):
        assert (field["offset"], field["type"], field["count"], field["size"]) == \
            (offset, kind, count, size), field
    # offsets must tile the blob with no gap and no overlap
    cursor = 0
    for field in fields:
        assert field["offset"] == cursor, (field, cursor)
        cursor += field["size"]
    assert cursor == EXPECTED["packed_size"], cursor

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["index", "offset", "type", "count", "size"], tsv_rows[0]
    assert len(tsv_rows) == EXPECTED["fields"] + 1, len(tsv_rows)

    print(f"craftable-item-struct: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
