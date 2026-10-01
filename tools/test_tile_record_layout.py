#!/usr/bin/env python3
"""Contract test for the tile record layout extraction (no ELF needed in CI)."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "tile_record_layout.tsv"
JSON_PATH = NATIVE / "tile_record_layout.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
EXPECTED = {"windows_scanned": 2, "record_field_reads": 4, "distinct_offsets": 4,
            "tail_constant": 69, "distinct_bases": 2, "fields_in_64_byte_record": 1,
            "fields_in_other_object": 3}
FIELDS = {1: ("0x00a22ea8", "shared body"), 3: ("0x00a23500", "tail"),
          8: ("0x00a22e00", "shared body"), 12: ("0x00a234e4", "tail")}


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "layout is not from the pinned ELF"
    assert record["counts"] == EXPECTED, record["counts"]
    assert record["record_stride"] == 64, record["record_stride"]

    fields = {f["offset"]: f for f in record["fields"]}
    assert sorted(fields) == sorted(FIELDS), sorted(fields)
    for offset, (site, window) in FIELDS.items():
        assert site in fields[offset]["read_sites"], (offset, fields[offset])
        assert fields[offset]["windows"] == [window], fields[offset]
        assert fields[offset]["purpose"] != "(not characterised)", fields[offset]
    assert "0x45" in fields[12]["purpose"], fields[12]
    assert "candidate" not in fields[12]["purpose"], "field 12 must not be over-claimed"

    # Base tracking: one field belongs to the 64-byte record, three to another object.
    # Conflating them was the defect this pin exists to prevent.
    fields_by_offset = {f["offset"]: f for f in record["fields"]}
    assert fields_by_offset[8]["in_64_byte_record"] is True, fields_by_offset[8]
    assert "index*64" in fields_by_offset[8]["bases"][0], fields_by_offset[8]
    for offset in (1, 3, 12):
        assert fields_by_offset[offset]["in_64_byte_record"] is False, fields_by_offset[offset]
        assert fields_by_offset[offset]["bases"] == ["fp-0x1c0"], fields_by_offset[offset]

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["offset", "size", "base", "in_64_byte_record", "windows",
                           "read_sites", "purpose"], tsv_rows[0]
    assert len(tsv_rows) == EXPECTED["distinct_offsets"] + 1, len(tsv_rows)

    print(f"tile-record-layout: PASS ({record['counts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
