#!/usr/bin/env python3
"""Where the game's text lives: localization files vs in-binary strings.

The question this answers is concrete - can the replacement load its labels from
shipped localization data? - and the answer is no, with evidence:

  * the APK ships exactly one `.strings` file (`en.lproj/InfoPlist.strings`, 45
    bytes) and it contains no key/value pairs at all, only a comment;
  * the text the game shows is in the binary's string table, so a replacement
    cannot get display names without either extracting them or authoring them.

The sentence catalogue below uses an explicit, conservative filter and is labelled
as a catalogue, not a verified UI string list. `displayName` exists as a selector,
but no `itemName`/`nameForItemType` symbol was found, so item display names are
still an open reverse-engineering item - recorded here rather than guessed.

Usage:
  python3 tools/audit_text_assets.py <assets-root> <libApplication.so> \
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
from string_evidence import nul_strings  # noqa: E402

PROBE_SYMBOLS = ("itemName", "itemNameForType", "nameForItemType", "displayName",
                 "localizedString", "NSLocalizedString")
LOCALIZATION_SUFFIXES = (".strings", ".stringsdict", ".po", ".xliff")
REPO_DATA_SUFFIXES = (".json", ".tsv", ".txt")


def sentence_like(text: str) -> bool:
    """Conservative catalogue filter; every rule is listed in the output."""
    if len(text) < 12 or " " not in text:
        return False
    if not text[0].isupper():
        return False
    if not text.rstrip().endswith((".", "!", "?", ":")):
        return False
    if any(ch in text for ch in "/\\{}[]<>@|"):
        return False
    return text.count(" ") >= 2


def build(assets: Path, elf: Path, repo: Path) -> dict:
    blob = elf.read_bytes()
    strings = nul_strings(blob)

    localization_files = []
    for path in sorted(assets.rglob("*")):
        if path.is_file() and path.suffix.lower() in LOCALIZATION_SUFFIXES:
            text = path.read_text(encoding="utf-8", errors="replace")
            pairs = len(re.findall(r'^\s*"[^"]*"\s*=\s*"', text, re.M))
            localization_files.append({
                "path": path.relative_to(assets).as_posix(),
                "bytes": path.stat().st_size,
                "key_value_pairs": pairs,
            })

    sentences = sorted({s for s in strings if sentence_like(s)})
    repo_data = []
    gamedata = repo / "assets" / "gamedata"
    if gamedata.exists():
        for path in sorted(gamedata.rglob("*")):
            if path.is_file() and path.suffix.lower() in REPO_DATA_SUFFIXES:
                repo_data.append({"path": path.relative_to(repo).as_posix(),
                                  "bytes": path.stat().st_size})

    replacement_localization_refs = 0
    app = repo / "app" / "src"
    if app.exists():
        for path in app.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in (".cpp", ".h", ".java", ".kt"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            replacement_localization_refs += len(
                re.findall(r"NSLocalizedString|localizedString|\.strings\b", text))

    symbols = {name: sum(1 for s in strings if s == name) for name in PROBE_SYMBOLS}
    counts = {
        "localization_files": len(localization_files),
        "localization_key_value_pairs": sum(f["key_value_pairs"] for f in localization_files),
        "elf_nul_strings": len(strings),
        "sentence_like_strings": len(sentences),
        "replacement_localization_references": replacement_localization_refs,
        "author_authored_data_files": len(repo_data),
        "probe_symbols": symbols,
    }
    return {
        "schema": 1,
        "assets_root": str(assets),
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "claim": ("text asset inventory: shipped localization files and their key "
                  "counts, plus a conservatively filtered catalogue of sentence-like "
                  "strings in the binary; the filter is a heuristic, not a UI audit"),
        "filter": {
            "min_length": 12,
            "requires_space": True,
            "requires_capital_start": True,
            "requires_sentence_punctuation": [".", "!", "?", ":"],
            "rejects_chars": "/\\{}[]<>@|",
            "min_spaces": 2,
        },
        "counts": counts,
        "localization_files": localization_files,
        "author_authored_data_files": repo_data,
        # The full catalogue: an earlier revision stored only the first 400 of 413
        # while the count field said 413, so the artifact disagreed with itself.
        "sentences": sentences,
    }


def render_tsv(record: dict) -> str:
    lines = ["kind\tkey\tvalue"]
    for entry in record["localization_files"]:
        lines.append(f"localization\t{entry['path']}\tkeys={entry['key_value_pairs']}")
    for name, hits in record["counts"]["probe_symbols"].items():
        lines.append(f"probe-symbol\t{name}\t{hits}")
    for sentence in record["sentences"][:200]:
        lines.append(f"sentence\t\t{sentence}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("elf", type=Path)
    ap.add_argument("--repo", type=Path, default=Path("."))
    native = Path("reconstruction/reverse-v3/native")
    ap.add_argument("--tsv", type=Path, default=native / "text_asset_inventory.tsv")
    ap.add_argument("--json", type=Path, default=native / "text_asset_inventory.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets, args.elf, args.repo)
    tsv = render_tsv(record)
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        status = 0
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists():
                print(f"CHECK FAILED: {path} is missing", file=sys.stderr)
                status = 1
            elif path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                status = 1
        if status == 0:
            print(f"check ok: {record['counts']}")
        return status
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}: {record['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
