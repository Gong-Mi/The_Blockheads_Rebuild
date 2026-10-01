#!/usr/bin/env python3
"""Contract test for the sound registry extraction (no ELF needed in CI).

Pins the counts and the two caveats so a change in the descriptor walk or in the key set
cannot pass silently.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "sound_group_keys.json"
TSV_PATH = NATIVE / "sound_group_keys.tsv"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"


def main() -> int:
    d = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert d["elf_sha256"] == PINNED_ELF, "registry is not from the pinned ELF"
    assert d["descriptor_count"] == 17209, d["descriptor_count"]
    assert d["group_key_count"] == 117, d["group_key_count"]
    assert d["group_key_complete_count"] == 85, d["group_key_complete_count"]
    assert d["group_key_fragment_count"] == 32, d["group_key_fragment_count"]
    assert d["audio_name_count"] == 130, d["audio_name_count"]
    assert d["audio_name_shipped_count"] == 129, d["audio_name_shipped_count"]
    assert d["audio_names_not_shipped"] == ["bird%d.wav"], d["audio_names_not_shipped"]
    assert d["format_string_audio_names"] == ["bird%d.wav"], d["format_string_audio_names"]

    # the caveat must stay: prefixes are not silently deleted
    assert "not proof of being a fragment" in d["group_key_prefix_caveat"], d["group_key_prefix_caveat"]
    assert "grp.ruby" in d["group_keys"], "grp.ruby dropped"
    assert "grp.magn" in d["group_keys"] and "grp.magnet" in d["group_keys"], "magn/magnet pair lost"
    assert "not group membership" in d["boundary"] or "not group membership" in d["boundary"]
    assert "grp.death" in d["group_keys"] and "grp.northpole" in d["group_keys"]
    assert d["group_keys"]["grp.lime"]["descriptor_va"].startswith("0x")

    rows = list(csv.reader(io.StringIO(TSV_PATH.read_text(encoding="utf-8")), delimiter="\t"))
    assert rows[0] == ["kind", "token", "descriptor_va", "extra"], rows[0]
    kinds = {r[0] for r in rows[1:]}
    assert kinds == {"group_key", "audio_name"}, kinds
    assert len(rows) - 1 == d["group_key_count"] + d["audio_name_count"], len(rows)
    print("sound-registry: PASS (counts, caveats and the format string pinned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
