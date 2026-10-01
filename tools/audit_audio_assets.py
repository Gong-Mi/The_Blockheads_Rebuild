#!/usr/bin/env python3
"""Audio asset coverage: what ships, what the original references, what the
replacement actually names.

Three independent sets are joined by filename so the gaps are visible instead of
implied:

  ships       - the file exists in the extracted original assets (size + sha256)
  original    - the name appears as a C string in the pinned libApplication.so
  replacement - the name appears in the replacement's own sources

A file that ships and the original references but the replacement never names is
a concrete integration gap; a file that ships but nobody references is dead
weight worth listing rather than assuming.

Usage:
  python3 tools/audit_audio_assets.py <assets-root> <libApplication.so> \
      [--repo .] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

AUDIO_SUFFIXES = (".wav", ".mp4", ".m4a", ".ogg")
NAME_RE = re.compile(rb"[A-Za-z0-9_+\-]{2,48}\.(?:wav|mp4|m4a|ogg)")
SOURCE_SUFFIXES = (".cpp", ".h", ".java", ".kt", ".gradle", ".txt", ".json")
SOURCE_DIRS = ("app/src", "assets/gamedata")


def shipped_audio(root: Path) -> dict[str, dict]:
    out = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in AUDIO_SUFFIXES:
            continue
        data = path.read_bytes()
        out[path.name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "path": str(path.relative_to(root)),
        }
    return out


def original_names(elf: Path) -> set[str]:
    data = elf.read_bytes()
    return {m.decode() for m in NAME_RE.findall(data)}


def replacement_names(repo: Path) -> set[str]:
    found: set[str] = set()
    for base in SOURCE_DIRS:
        target = repo / base
        if not target.exists():
            continue
        for path in target.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            text = path.read_text(errors="replace")
            for match in re.findall(r"[A-Za-z0-9_+\-]{2,48}\.(?:wav|mp4|m4a|ogg)", text):
                found.add(match)
    return found


def build(assets: Path, elf: Path, repo: Path) -> dict:
    ships = shipped_audio(assets)
    original = original_names(elf)
    replacement = replacement_names(repo)
    # Some original names are composed at runtime (the ELF carries the stem and
    # appends an index - e.g. "bird" + n + ".wav"). A stem hit is recorded as its
    # own evidence class: it explains why the exact filename has no string,
    # without claiming which index maps to which file.
    original_blob = elf.read_bytes()
    rows = []
    for name in sorted(ships):
        stem = name.rsplit(".", 1)[0].rstrip("0123456789")
        stem_hit = len(stem) >= 3 and stem.encode() in original_blob
        rows.append({
            "name": name,
            "bytes": ships[name]["bytes"],
            "sha256": ships[name]["sha256"],
            "original_referenced": name in original,
            "original_stem_only": (name not in original) and stem_hit,
            "replacement_referenced": name in replacement,
        })
    counts = {
        "ships": len(rows),
        "original_referenced": sum(1 for r in rows if r["original_referenced"]),
        "original_stem_only": sum(1 for r in rows if r["original_stem_only"]),
        "replacement_referenced": sum(1 for r in rows if r["replacement_referenced"]),
        "shipped_unreferenced_by_original": sum(
            1 for r in rows if not r["original_referenced"] and not r["original_stem_only"]),
        "original_not_in_replacement": sum(
            1 for r in rows if (r["original_referenced"] or r["original_stem_only"])
            and not r["replacement_referenced"]),
        "original_names_absent_from_assets": len(original - set(ships)),
    }
    return {
        "schema": 1,
        "assets_root": str(assets),
        "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
        "counts": counts,
        "claim": ("audio coverage join: shipped files vs names referenced by the "
                  "pinned original ELF vs names the replacement sources mention; "
                  "membership only, no playback claim"),
        "rows": rows,
        "original_only_names": sorted(original - set(ships))[:200],
    }


def render_tsv(rows: list[dict]) -> str:
    header = ["name", "bytes", "sha256", "original_referenced", "original_stem_only",
              "replacement_referenced"]
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(str(row[h]) for h in header))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("elf", type=Path)
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--tsv", type=Path,
                    default=Path("reconstruction/reverse-v3/native/audio_asset_coverage.tsv"))
    ap.add_argument("--json", type=Path,
                    default=Path("reconstruction/reverse-v3/native/audio_asset_coverage.json"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets, args.elf, args.repo)
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
