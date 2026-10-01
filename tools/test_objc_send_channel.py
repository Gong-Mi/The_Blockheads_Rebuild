#!/usr/bin/env python3
"""Contract test for the ObjC send-channel probe (no ELF needed in CI).

Pins the negative result: the selector string has one holder (its selref slot), the slot
value appears only inside .rel.dyn, and no msgrefs unit carries either value.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
TSV = NATIVE / "objc_send_channel.tsv"
JSON_PATH = NATIVE / "objc_send_channel.json"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"


def main() -> int:
    record = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert record["elf_sha256"] == PINNED_ELF, "probe is not from the pinned ELF"
    assert record["selector"] == "soundNamed:", record["selector"]
    assert record["string_va"] == "0xecf8e2", record["string_va"]
    assert record["selref_slots"] == ["0xe7de14"], record["selref_slots"]
    assert record["msgrefs_unit_matches"] == [], record["msgrefs_unit_matches"]
    assert len(record["holders_of_string_va"]) == 1, record["holders_of_string_va"]
    holder = record["holders_of_string_va"][0]
    assert holder["va"] == record["selref_slots"][0], holder
    holders = record["holders_of_selref_slot"]
    assert len(holders) == 1 and holders[0]["section"] == ".rel.dyn", holders
    relocs = {r["name"]: r["entries"] for r in record["relocation_sections"]}
    assert relocs == {".rel.dyn": 148676, ".rel.plt": 611}, relocs
    assert "not statically" in record["claim"], record["claim"]
    assert record["send_idiom"]["function"] == "0x00b88aac", record["send_idiom"]

    tsv_rows = list(csv.reader(io.StringIO(TSV.read_text(encoding="utf-8")), delimiter="\t"))
    assert tsv_rows[0] == ["step", "result"], tsv_rows[0]
    assert any(row[0] == "msgrefs_unit_matches" for row in tsv_rows[1:]), tsv_rows[:6]

    print("objc-send-channel: PASS (negative result pinned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
