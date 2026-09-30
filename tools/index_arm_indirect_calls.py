#!/usr/bin/env python3
"""Index ARM indirect call sites without guessing Objective-C dispatch.

This intentionally does not pair selectors with blx calls. It records the
machine-code call sites and leaves selector/receiver/argument dataflow unknown
until a later, register-aware pass proves the relation.
"""
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

ADDRESS = re.compile(r"^\s*(?:[^0-9a-f]*?)?(0x[0-9a-fA-F]+)\s+[0-9a-fA-F]{8}\s+(.+?)\s*$")
BLX = re.compile(r"\bblx\s+(r(?:1[0-2]|[0-9])|ip|lr)\b")
HEADER = "call_address\ttarget_register\tinstruction\tselector_pair\treceiver_pair\targument_pair"


def index(text: str) -> list[dict[str, str]]:
    rows = []
    for line in text.splitlines():
        match = ADDRESS.match(line)
        if not match:
            continue
        call = BLX.search(match.group(2))
        if not call:
            continue
        rows.append({
            "call_address": match.group(1).lower(),
            "target_register": call.group(1),
            "instruction": match.group(2).strip(),
            "selector_pair": "unknown",
            "receiver_pair": "unknown",
            "argument_pair": "unknown",
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("disassembly", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = index(args.disassembly.read_text(encoding="utf-8", errors="replace"))
    if not rows:
        raise SystemExit("no ARM blx call sites found")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=HEADER.split("\t"), delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"indirect-call-sites={len(rows)} selector-pairs=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
