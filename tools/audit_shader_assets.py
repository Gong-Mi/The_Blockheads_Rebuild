#!/usr/bin/env python3
"""Shader asset coverage: what ships, how the original names it, what the
replacement names, and which shader the class/method mapping attributes.

The original does not store most shader filenames: it keeps the stem (a class or
effect name) and appends ".vsh"/".fsh" at load time (`stringByAppendingString`),
so a verbatim-only test would call 66 of the 92 shipped programs "unreferenced".
Classes recorded per file:

  verbatim     - the full filename appears as a byte string in the ELF
  stem-only    - only the stem appears (extension composed at runtime)
  unattributed - neither the filename nor its stem appears in the ELF

Membership only: no draw, no uniform binding and no rendering claim.

Usage:
  python3 tools/audit_shader_assets.py <assets-root> <libApplication.so> \
      [--repo .] [--mapping TSV] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

SHADER_SUFFIXES = (".vsh", ".fsh")
NAME_RE = re.compile(rb"[A-Za-z0-9_]{3,40}\.(?:vsh|fsh)")
SOURCE_SUFFIXES = (".cpp", ".h", ".java", ".kt")
SOURCE_DIRS = ("app/src",)


def shipped(root: Path) -> dict[str, dict]:
    out = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SHADER_SUFFIXES:
            continue
        data = path.read_bytes()
        out[path.name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return out


def replacement_mentions(repo: Path) -> set[str]:
    found: set[str] = set()
    for base in SOURCE_DIRS:
        target = repo / base
        if not target.exists():
            continue
        for path in target.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            text = path.read_text(errors="replace")
            found.update(re.findall(r"[A-Za-z0-9_]{3,40}\.(?:vsh|fsh)", text))
    return found


def mapping_usage(path: Path) -> dict[str, list[str]]:
    """shader name -> ['Class selector', ...] from the class/method mapping."""
    out: dict[str, list[str]] = {}
    if not path.exists():
        return out
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            shader = (row.get("shader") or "").strip()
            if not shader:
                continue
            for suffix in SHADER_SUFFIXES:
                name = f"{shader}{suffix}"
                out.setdefault(name, []).append(
                    f"{row.get('class','?')} {row.get('method','?')}"
                )
    return out


def build(assets: Path, elf: Path, repo: Path, mapping: Path) -> dict:
    ship = shipped(assets)
    blob = elf.read_bytes()
    verbatim = {m.decode() for m in NAME_RE.findall(blob)}
    replacement = replacement_mentions(repo)
    usage = mapping_usage(mapping)

    rows = []
    for name in sorted(ship):
        stem = name.rsplit(".", 1)[0]
        if name in verbatim:
            klass = "verbatim"
        elif len(stem) >= 3 and stem.encode() in blob:
            klass = "stem-only"
        else:
            klass = "unattributed"
        rows.append({
            "name": name,
            "stage": "vertex" if name.endswith(".vsh") else "fragment",
            "bytes": ship[name]["bytes"],
            "sha256": ship[name]["sha256"],
            "original_class": klass,
            "replacement_referenced": name in replacement,
            "mapped_uses": len(usage.get(name, [])),
        })
    counts = {
        "ships": len(rows),
        "vertex": sum(1 for r in rows if r["stage"] == "vertex"),
        "fragment": sum(1 for r in rows if r["stage"] == "fragment"),
        "original_verbatim": sum(1 for r in rows if r["original_class"] == "verbatim"),
        "original_stem_only": sum(1 for r in rows if r["original_class"] == "stem-only"),
        "original_unattributed": sum(1 for r in rows if r["original_class"] == "unattributed"),
        "replacement_referenced": sum(1 for r in rows if r["replacement_referenced"]),
        "mapped_in_class_table": sum(1 for r in rows if r["mapped_uses"]),
        "not_named_by_replacement": sum(1 for r in rows if not r["replacement_referenced"]),
    }
    return {
        "schema": 1,
        "assets_root": str(assets),
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "counts": counts,
        "claim": ("shader coverage join: shipped programs vs how the pinned ELF "
                  "names them (verbatim / stem-only / unattributed) vs the "
                  "replacement sources vs the class-method mapping table"),
        "rows": rows,
        "unattributed": [r["name"] for r in rows if r["original_class"] == "unattributed"],
    }


def render_tsv(rows: list[dict]) -> str:
    header = ["name", "stage", "bytes", "sha256", "original_class",
              "replacement_referenced", "mapped_uses"]
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(str(row[h]) for h in header))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("elf", type=Path)
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--mapping", type=Path,
                    default=Path("reconstruction/reverse-v3/native/shader_mapping.tsv"))
    ap.add_argument("--tsv", type=Path,
                    default=Path("reconstruction/reverse-v3/native/shader_asset_coverage.tsv"))
    ap.add_argument("--json", type=Path,
                    default=Path("reconstruction/reverse-v3/native/shader_asset_coverage.json"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets, args.elf, args.repo, args.mapping)
    tsv = render_tsv(record["rows"])
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        bad = 0
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                bad = 1
        if not bad:
            print(f"check ok: {record['counts']}")
        return bad
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}: {record['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
