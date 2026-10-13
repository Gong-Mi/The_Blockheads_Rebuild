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
        if path.name.startswith("refs_") and path.suffix == ".tsv":
            with path.open(encoding="utf-8", newline="") as stream:
                reader = csv.DictReader(stream, delimiter="\t")
                if not reader.fieldnames or "implementation" not in reader.fieldnames:
                    raise ValueError(f"missing implementation column: {path}")
                for row in reader:
                    address = row.get("implementation", "")
                    if not re.fullmatch(r"0x[0-9a-fA-F]{8}", address or ""):
                        raise ValueError(f"invalid evidence implementation in {path}: {address!r}")
                    refs.add(address.lower())
        elif path.name.startswith("disasm_") and path.suffix == ".txt":
            # Only explicit function owners, never instruction/callee/end addresses.
            owners = {a.lower() for a in re.findall(
                r"^# implementation: (0x[0-9a-fA-F]{8})\s*$", text, re.MULTILINE)}
            refs |= owners
            cfg |= owners
        elif "CONTROL_FLOW_STATS" in path.name and path.suffix == ".md":
            # Explicit IMP labels only; prose mentions do not establish ownership.
            cfg |= {a.lower() for a in re.findall(
                r"^IMP:\s*`?(0x[0-9a-fA-F]{8})`?\s*$", text, re.MULTILINE)}
    return refs, cfg


def read_implementation_records(path: Path, source_root: Path) -> dict:
    data = json.loads(path.read_text())
    if data.get("schema") != 1 or not isinstance(data.get("methods"), list):
        raise ValueError("invalid implementation manifest schema")
    records = {}
    root = source_root.resolve()
    for record in data["methods"]:
        required = {"implementation", "class", "kind", "selector", "types", "source", "test", "evidence", "scope", "integration"}
        if not required.issubset(record) or not all(isinstance(record[k], str) and record[k] for k in required):
            raise ValueError("incomplete implementation record")
        imp = record["implementation"]
        if not re.fullmatch(r"0x[0-9a-f]{8}", imp) or imp in records:
            raise ValueError("invalid/duplicate record implementation")
        if record["integration"] != "recovered-method-module":
            raise ValueError("unsupported implementation scope")
        for field in ("source", "test", "evidence"):
            relative = Path(record[field])
            target = (root / relative).resolve()
            if relative.is_absolute() or not target.is_relative_to(root) or not target.is_file():
                raise ValueError("missing/outside implementation record file: " + record[field])
        records[imp] = record
    return records


def read_runtime_records(path: Path, source_root: Path, implementation_records: dict) -> dict:
    """Records that a method's BEHAVIOUR was measured on the running original.

    Deliberately separate from the implementation registry: a runtime claim adds a measurement and a boundary, while
    the implementation, source, test and evidence paths live in one place. A runtime record must name an
    implementation that already has an implementation record - a method whose behaviour was measured but which has
    no recorded source/test/evidence would be a contradiction, not a promotion.
    """
    data = json.loads(path.read_text())
    if data.get("schema") != 1 or not isinstance(data.get("methods"), list):
        raise ValueError("invalid origin-runtime manifest schema: " + str(path))
    here = source_root.resolve()
    out = {}
    for record in data["methods"]:
        imp = str(record.get("implementation", "")).lower()
        if not re.fullmatch(r"0x[0-9a-f]{8}", imp):
            raise ValueError("invalid runtime record implementation: " + repr(record.get("implementation")))
        if imp in out:
            raise ValueError("duplicate runtime record: " + imp)
        if imp not in implementation_records:
            raise ValueError("runtime record must also be an implementation record: " + imp)
        for field in ("measured_on", "boundary", "evidence"):
            if not isinstance(record.get(field), str) or not record[field]:
                raise ValueError("runtime record missing " + field + ": " + imp)
        rel = Path(record["evidence"])
        target = (here / rel).resolve()
        if rel.is_absolute() or not target.is_relative_to(here) or not target.is_file():
            raise ValueError("missing/outside runtime evidence file: " + record["evidence"])
        out[imp] = record
    return out


def build(rows: list[dict[str, str]], refs: set[str], cfg: set[str], records: dict | None = None,
          runtime_records: dict | None = None) -> dict:
    records = records or {}
    runtime_records = runtime_records or {}
    by_imp = {row["implementation"]: row for row in rows}
    for imp, record in records.items():
        if imp not in by_imp or any(record.get(k) != by_imp[imp][k] for k in ("implementation", "class", "kind", "selector", "types")):
            raise ValueError("implementation record identity mismatch: " + imp)
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
    for entry in entries:
        record = records.get(entry["implementation"])
        if record:
            for stage in ("refs", "cfg", "semantics", "implemented"):
                entry["stages"][stage] = True
            entry["semantic_status"] = "reviewed-with-recorded-boundaries"
            entry["implementation_status"] = "explicit-record"
            entry["implementation_record"] = record
            # Local interface/fixture tests do not establish original-runtime parity.
    # The last stage is fed ONLY by records pointing at a measurement of the running original. It was
    # structurally pinned at 0 before this existed: the generator wrote behavior_status = not-tested and
    # had no path by which a runtime measurement could leave that state, however much evidence there was.
    for imp, record in runtime_records.items():
        entry = next((e for e in entries if e["implementation"] == imp), None)
        if entry is None:
            raise ValueError("runtime record for an unknown implementation: " + imp)
        if imp not in records:
            raise ValueError("runtime record must also be an implementation record: " + imp)
        entry["stages"]["behavior-verified"] = True
        entry["behavior_status"] = "measured-on-original-runtime"
        entry["runtime_record"] = record
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
        "| refs | %d | explicit implementation owner in refs/disassembly evidence |" % counts["refs"],
        "| cfg | %d | explicit IMP owner in CFG statistics or bounded disassembly; not a completeness claim |" % counts["cfg"],
        "| semantics | %d | explicit reviewed method records and their stated limits |" % counts["semantics"],
        "| implemented | %d | explicit source/test/evidence records; not gameplay integration |" % counts["implemented"],
        "| behavior-verified | %d | controlled original-runtime evidence, not local fixtures |" % counts["behavior-verified"],
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
    parser.add_argument("--implementation-records", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--origin-runtime-records", type=Path,
                        help="records whose behaviour was MEASURED on the running original; they must be a subset of the implementation records")
    args = parser.parse_args()
    rows = read_methods(args.methods)
    refs, cfg = implementations_in_files(evidence_files(args.evidence_root))
    records = read_implementation_records(args.implementation_records, args.source_root) if args.implementation_records else {}
    runtime_records = (read_runtime_records(args.origin_runtime_records, args.source_root, records)
                       if args.origin_runtime_records else {})
    ledger = build(rows, refs, cfg, records, runtime_records)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text(markdown(ledger, args.methods), encoding="utf-8")
    print(json.dumps({"methods": ledger["method_count"], "stages": ledger["stage_counts"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
