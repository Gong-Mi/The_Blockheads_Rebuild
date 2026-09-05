#!/usr/bin/env python3
"""Build a conservative per-IMP reverse-engineering coverage ledger.

The ledger keeps evidence stages separate. A method is not marked semantic,
implemented, or behavior-verified merely because its name or selector exists.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Iterable

STAGES = (
    "indexed",
    "refs",
    "cfg",
    "semantics",
    "implemented",
    "behavior-verified",
)


def read_methods(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    expected = {"implementation", "class", "kind", "selector", "types"}
    if not rows or set(rows[0]) != expected:
        raise SystemExit(f"invalid Objective-C method map: {path}")
    seen: set[str] = set()
    for row in rows:
        imp = row["implementation"].lower()
        if not re.fullmatch(r"0x[0-9a-f]+", imp):
            raise SystemExit(f"invalid implementation address: {row['implementation']}")
        if imp in seen:
            raise SystemExit(f"duplicate implementation address: {imp}")
        seen.add(imp)
        row["implementation"] = imp
    return rows


def evidence_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in {".tsv", ".txt", ".md"})


def implementations_in_files(files: Iterable[Path]) -> tuple[set[str], set[str]]:
    refs: set[str] = set()
    cfg: set[str] = set()
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        addresses = {a.lower() for a in re.findall(r"0x[0-9a-fA-F]{8}", text)}
        if path.suffix in {".tsv", ".txt"} and ("refs_" in path.name or "disasm_" in path.name):
            refs |= addresses
        if "CONTROL_FLOW_STATS" in path.name or path.name.startswith("disasm_"):
            cfg |= addresses
    return refs, cfg


def build(rows: list[dict[str, str]], refs: set[str], cfg: set[str]) -> dict:
    entries = []
    for row in rows:
        imp = row["implementation"]
        stages = {stage: False for stage in STAGES}
        stages["indexed"] = True
        stages["refs"] = imp in refs
        stages["cfg"] = imp in cfg
        entries.append({
            "implementation": imp,
            "class": row["class"],
            "kind": row["kind"],
            "selector": row["selector"],
            "types": row["types"],
            "stages": stages,
            "semantic_status": "unknown",
            "implementation_status": "not-audited",
            "behavior_status": "not-tested",
        })
    counts = {stage: sum(e["stages"][stage] for e in entries) for stage in STAGES}
    return {
        "schema": 1,
        "method_count": len(entries),
        "unique_implementation_count": len({e["implementation"] for e in entries}),
        "stage_counts": counts,
        "entries": entries,
    }


def markdown(ledger: dict, source: Path) -> str:
    counts = ledger["stage_counts"]
    lines = [
        "# Reverse-engineering function coverage ledger",
        "",
        "This generated ledger is conservative: indexed methods are not claimed to",
        "have recovered semantics, replacement code, or behavioral verification.",
        "",
        f"- Source method map: `{source}`",
        f"- Methods: {ledger['method_count']}",
        f"- Unique IMPs: {ledger['unique_implementation_count']}",
        "",
        "| stage | count | meaning |",
        "|---|---:|---|",
        "| indexed | %d | present in the method map |" % counts["indexed"],
        "| refs | %d | implementation address appears in checked-in refs/disassembly evidence |" % counts["refs"],
        "| cfg | %d | address appears in CFG statistics or bounded disassembly evidence |" % counts["cfg"],
        "| semantics | 0 | requires an explicit semantic audit; never inferred from names |",
        "| implemented | 0 | requires an explicit replacement implementation record |",
        "| behavior-verified | 0 | requires a controlled runtime behavior record |",
        "",
        "Unknown/conditional/indirect cases remain unknown. This file is an index,",
        "not a completion percentage or an equivalence claim.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("methods", type=Path)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    rows = read_methods(args.methods)
    refs, cfg = implementations_in_files(evidence_files(args.evidence_root))
    ledger = build(rows, refs, cfg)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text(markdown(ledger, args.methods), encoding="utf-8")
    print(json.dumps({"methods": ledger["method_count"], "stages": ledger["stage_counts"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
