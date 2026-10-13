#!/usr/bin/env python3
"""Contract test for the grp.* identifier extraction (no ELF or plist needed in CI).

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
JSON_PATH = NATIVE / "grp_identifiers.json"
TSV_PATH = NATIVE / "grp_identifiers.tsv"
PINNED_ELF = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
PLIST_SHA = "2e8c77dd8309ca33f1a2fcde961f6377f5b733f208cd38a700a2ed0481bf23e8"


def main() -> int:
    d = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert d["elf_sha256"] == PINNED_ELF, "registry is not from the pinned ELF"
    assert d["descriptor_count"] == 17209, d["descriptor_count"]
    assert d["group_key_count"] == 117, d["group_key_count"]
    assert d["achievement_identifier_count"] == 91, d["achievement_identifier_count"]
    assert d["binary_only_literal_count"] == 26, d["binary_only_literal_count"]
    assert d["audio_name_count"] == 130, d["audio_name_count"]
    assert d["audio_name_shipped_count"] == 129, d["audio_name_shipped_count"]
    assert d["audio_names_not_shipped"] == ["bird%d.wav"], d["audio_names_not_shipped"]
    assert d["format_string_audio_names"] == ["bird%d.wav"], d["format_string_audio_names"]

    # evidence classification: plist defines the real identifiers; binary_only are fragments or near-misses
    assert "identifiers = literals that the shipped achievement plist" in d["classification_basis"]
    assert "grp.ruby" in d["group_keys"], "grp.ruby dropped"
    assert "grp.magn" in d["group_keys"] and "grp.magnet" in d["group_keys"], "magn/magnet pair lost"
    assert "grp.amethyst_pickax" in d["binary_only_near_misses"]
    assert "not group membership" in d["boundary"]
    assert "grp.death" in d["group_keys"] and "grp.northpole" in d["group_keys"]
    assert d["group_keys"]["grp.lime"]["descriptor_va"].startswith("0x")

    rows = list(csv.reader(io.StringIO(TSV_PATH.read_text(encoding="utf-8")), delimiter="\t"))
    assert rows[0] == ["kind", "token", "descriptor_va", "extra"], rows[0]
    kinds = {r[0] for r in rows[1:]}
    assert kinds == {"group_key", "audio_name"}, kinds
    assert len(rows) - 1 == d["group_key_count"] + d["audio_name_count"], len(rows)
    cc = d["achievement_crosscheck"]
    assert cc["available"] is True, "the achievement cross-check must be present, not skipped"
    assert cc["kind"] == "play-games achievement identifiers", cc["kind"]
    assert cc["entry_count"] == 91, cc["entry_count"]
    assert cc["plist_sha256"] == PLIST_SHA, cc["plist_sha256"]
    assert cc["google_identifiers"]["grp.bed"] == "CgkIv4aWlc0dEAIQCw", cc["google_identifiers"]["grp.bed"]
    assert cc["in_plist_not_in_binary"] == [], cc["in_plist_not_in_binary"]
    assert len(cc["in_binary_not_in_plist"]) == d["group_key_count"] - cc["entry_count"]
    assert "achievement" in d["what_these_are"], d["what_these_are"]
    print("grp-identifiers: PASS (counts, achievement cross-check and caveats pinned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
