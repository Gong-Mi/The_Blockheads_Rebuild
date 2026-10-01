#!/usr/bin/env python3
"""Stale-consumer check: does a tool still read a column that no artifact has?

Renaming a column is a schema change, and this repository has several tools that
read each other's TSV artifacts by column name. Three separate CI failures came
from exactly that fan-out: `original_item_image_map.tsv` gained
`col_from_image_a0`, and the item-types tool, the sprite-map join and the
validator all still said `col_dataA0`.

This check closes the loop. It collects the column names that actually exist in the
artifacts under `reconstruction/reverse-v3/native/*.tsv`, collects the string
subscripts the tools use on parsed rows (`row["..."]`, `images[i]["..."]`, ...),
and flags subscripts that *look like artifact columns* but exist in no header. A
look-alike is a name containing a field-ish token (`dataA`, `from_image`,
`item_type`, `tile_type`, `shader`, `atlas`, `font`, `char_id`, `provenance`,
`col_`, `row_`, `image`, `case_target`, `helper`, `uniform`, `attribute`) - narrow
enough that in-memory row keys do not trip it, wide enough to catch a rename.

Exit codes: 0 clean, 1 stale references found.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
NATIVE = ROOT / "reconstruction/reverse-v3/native"
SUBSCRIPT_RE = re.compile(r"""\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]""")
LOOKALIKE = ("dataA", "from_image", "item_type", "tile_type", "shader", "atlas",
             "font", "char_id", "provenance", "col_", "row_", "image",
             "case_target", "helper", "uniform", "attribute", "resolution",
             "contents_type", "step_index", "original_")
SKIP_TOOLS = {"check_artifact_consumers.py", "test_check_artifact_consumers.py"}


def _json_keys(node, out: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            out.add(str(key))
            _json_keys(value, out)
    elif isinstance(node, list):
        for item in node:
            _json_keys(item, out)


def artifact_columns() -> dict[str, set[str]]:
    """Names that exist in some artifact: TSV headers and every JSON key.

    JSON keys matter because the tools read artifacts through `record["..."]` just
    as often as through `row["..."]`; without them a rename check flags every dict
    access as stale.
    """
    columns: dict[str, set[str]] = {}
    for path in sorted(NATIVE.glob("*.tsv")):
        text = path.read_text(encoding="utf-8", errors="replace")
        first = text.splitlines()[0] if text.splitlines() else ""
        columns[path.name] = set(first.split("\t"))
    json_keys: set[str] = set()
    for path in sorted(NATIVE.glob("*.json")):
        try:
            _json_keys(json.loads(path.read_text(encoding="utf-8")), json_keys)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
    if json_keys:
        columns["<json keys>"] = json_keys
    return columns


def looks_like_column(name: str) -> bool:
    return any(token in name for token in LOOKALIKE)


DICT_KEY_RE = re.compile(r"""["']([A-Za-z_][A-Za-z0-9_]*)["']\s*:""")


def scan(path: Path, known: set[str]) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    # A tool that builds its own dict (`{"attribute": set(), ...}`) is reading its
    # own keys, not an artifact column; local literals count as known for that file.
    local_keys = set(DICT_KEY_RE.findall(text))
    path_known = known | local_keys
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        for name in SUBSCRIPT_RE.findall(line):
            if not looks_like_column(name) or name in path_known:
                continue
            findings.append(f"{path.name}:{number}: reads column '{name}' which "
                            f"exists in no native/*.tsv header")
    return findings


def main() -> int:
    columns = artifact_columns()
    known: set[str] = set()
    for names in columns.values():
        known |= names
    checked = 0
    findings: list[str] = []
    for path in sorted(TOOLS.glob("*.py")):
        if path.name in SKIP_TOOLS or path.name.startswith("test_"):
            continue
        checked += 1
        findings.extend(scan(path, known))
    for item in findings:
        print(item, file=sys.stderr)
    print(f"artifact-consumer check: {checked} tools, {len(columns)} artifact headers, "
          f"{len(findings)} stale references")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
