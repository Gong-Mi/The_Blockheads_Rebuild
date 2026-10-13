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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from string_evidence import classify, contains_token, nul_strings  # noqa: E402

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
    """Deprecated: raw-byte regex, kept only so older callers keep importing.

    It matched inside unrelated strings (`.waveTimer` -> a bogus
    `_KelpPlant.wav`); use `string_evidence.nul_strings` + `classify` instead.
    """
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


DATA_SUFFIXES = (".json", ".plist", ".txt", ".strings", ".nib", ".xml", ".html", ".css", ".dex")


def sweep_sources(lib_dir: Path | None, data_dir: Path | None, names: list[str],
                  pinned: Path | None = None) -> dict:
    """Search every native library and every data file for the shipped names.

    The pinned ELF is where the classes come from, but leaving it at that makes
    "unattributed" mean "not in one file". This sweep backs the class with the
    whole APK: all .so under lib/ and all non-raster/non-audio data files.
    """
    pinned_name = pinned.name if pinned is not None else None
    scan = {"native_libraries": 0, "data_files": 0, "found_in_native": {},
            "found_in_data": {},
            "claim": ("every .so under lib/ and every data file swept for the "
                      "shipped names; hits inside the pinned ELF are counted but "
                      "not listed, since that file is where the classes come from")}
    if lib_dir is not None and lib_dir.exists():
        for so in sorted(lib_dir.rglob("*.so")):
            if so.name == pinned_name:
                continue
            scan["native_libraries"] += 1
            blob = so.read_bytes()
            for name in names:
                if contains_token(blob, name):
                    scan["found_in_native"].setdefault(name, []).append(so.name)
    if data_dir is not None and data_dir.exists():
        for path in sorted(data_dir.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in DATA_SUFFIXES:
                continue
            scan["data_files"] += 1
            blob = path.read_bytes()
            for name in names:
                if contains_token(blob, name):
                    scan["found_in_data"].setdefault(name, []).append(path.name)
    return scan


def build(assets: Path, elf: Path, repo: Path, lib_dir: Path | None = None,
          data_dir: Path | None = None) -> dict:
    ships = shipped_audio(assets)
    blob = elf.read_bytes()
    strings = nul_strings(blob)
    string_set = set(strings)
    replacement = replacement_names(repo)
    rows = []
    for name in sorted(ships):
        klass, detail = classify(name, strings, string_set)
        rows.append({
            "name": name,
            "bytes": ships[name]["bytes"],
            "sha256": ships[name]["sha256"],
            "original_class": klass,
            "original_evidence": detail,
            "replacement_referenced": name in replacement,
        })
    def count(klass: str) -> int:
        return sum(1 for r in rows if r["original_class"] == klass)

    named = ("verbatim", "format-string")
    counts = {
        "ships": len(rows),
        "original_verbatim": count("verbatim"),
        "original_format_string": count("format-string"),
        "original_suffix_composition": count("suffix-composition"),
        "original_stem_exact": count("stem-exact"),
        "original_stem_prefix": count("stem-prefix"),
        "original_substring_only": count("substring"),
        "original_unattributed": count("unattributed"),
        "original_named": sum(1 for r in rows if r["original_class"] in named),
        "replacement_referenced": sum(1 for r in rows if r["replacement_referenced"]),
        "original_named_not_in_replacement": sum(
            1 for r in rows if r["original_class"] in named and not r["replacement_referenced"]),
        "no_original_evidence": sum(
            1 for r in rows if r["original_class"] not in named),
        "original_names_absent_from_assets": len(
            {s for s in strings if s.endswith((".wav", ".mp4", ".m4a", ".ogg"))} - set(ships)),
    }
    sweep = sweep_sources(lib_dir, data_dir, sorted(ships), pinned=elf)
    return {
        "schema": 1,
        "assets_root": str(assets),
        "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
        "counts": counts,
        "claim": ("audio coverage join: shipped files vs how the pinned original "
                  "ELF names them (verbatim / format-string / stem-exact / "
                  "stem-prefix / substring / unattributed) vs names the "
                  "replacement sources mention; membership only, no playback claim"),
        "rows": rows,
        "original_only_names": sorted(
            {s for s in strings if s.endswith((".wav", ".mp4", ".m4a", ".ogg"))} - set(ships))[:200],
        "string_extraction": ("NUL-delimited printable runs; a raw byte regex "
                              "false-positived on OBJC_IVAR_$_KelpPlant.waveTimer"),
        "sweep": sweep,
    }


def render_tsv(rows: list[dict]) -> str:
    header = ["name", "bytes", "sha256", "original_class", "original_evidence",
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
    ap.add_argument("--lib-dir", type=Path,
                    help="directory holding every original .so (whole-APK sweep)")
    ap.add_argument("--data-dir", type=Path,
                    help="asset tree scanned for the shipped names as data")
    ap.add_argument("--tsv", type=Path,
                    default=Path("reconstruction/reverse-v3/native/audio_asset_coverage.tsv"))
    ap.add_argument("--json", type=Path,
                    default=Path("reconstruction/reverse-v3/native/audio_asset_coverage.json"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets, args.elf, args.repo, args.lib_dir, args.data_dir)
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
