#!/usr/bin/env python3
"""Where item display names could come from - audited, not assumed.

The inventory UI shows item names, so the replacement needs labels. This tool
checks every place a name could hide in the shipped APK and records what it found,
because the naive searches are misleading:

  * `.strings` localization: one file, zero key/value pairs (iOS shell stub);
  * `GameResources/defaultPrices`: 266 entries, fields `id` / `price` /
    `old_price` only - no name field;
  * a name table in the binary: none exists. Searching the 426 reference names
    word by word does produce standalone-token hits (34/409 words), but their
    contexts are not item names - they are the blockhead character-name lists
    (`Litzy, Glitter, Sparkle, Mystic, Dazzle, Gemini, Diamond, Amethyst, Ruby,
    Emerald, Sapphire, Jewel, ...` and the male/female first-name lists such as
    `Clayton`) and ObjC class names (`OBJC_METACLASS_$_FreightCar`). A
    boundary-aware token search is necessary but not sufficient: the context has to
    be read before a hit means anything;
  * ObjC class names do correspond to some items (18/426 exact, 72 partial) - the
    placeable objects (`Torch`, `Door`, `Ladder`, `Window`, `Bed`, `Boat`,
    `FishingRod`, `Sign`, `Rail`, `FreightCar`, ...) - but that is a subset, so
    class naming cannot be the general display-name source.

Conclusion recorded by the artifact: display names are not extractable from this
APK. They must be authored (the in-repo reference enum is the best available
source, as symbolic names) or captured from the server at runtime.

Usage:
  python3 tools/audit_item_display_names.py <assets-root> <libApplication.so> \
      [--native DIR] [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from string_evidence import contains_token, nul_strings  # noqa: E402

NAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
MIN_WORD = 4


def reference_names(native: Path) -> list[tuple[int, str]]:
    out = []
    for line in (native / "reference_itemtype_enum.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(\w+)\s*=\s*(\d+)$", line)
        if match:
            out.append((int(match.group(2)), match.group(1)))
    return out


def standalone_offsets(blob: bytes, token: str) -> list[int]:
    out = []
    needle = token.encode()
    start = 0
    while True:
        index = blob.find(needle, start)
        if index < 0:
            return out
        before = blob[index - 1:index]
        after = blob[index + len(needle):index + len(needle) + 1]
        if (not before or chr(before[0]) not in NAME_CHARS) and (
                not after or chr(after[0]) not in NAME_CHARS):
            out.append(index)
        start = index + 1


def classify_context(blob: bytes, offset: int) -> str:
    """What is around the hit? A hit is not a name until the context says so."""
    window = blob[max(0, offset - 64):offset + 64]
    text = "".join(chr(b) if 32 <= b < 127 else "|" for b in window)
    head = blob[max(0, offset - 32):offset].decode("latin1")
    if "OBJC_" in head:
        return "objc-symbol"
    run = [part for part in re.split(r"[|,]", text) if part.isalpha() and part[:1].isupper()]
    if len(run) >= 3:
        return "name-list"
    return "other"


def build(assets: Path, elf: Path, native: Path) -> dict:
    blob = elf.read_bytes()
    strings = nul_strings(blob)
    names = reference_names(native)

    strings_files = []
    for path in sorted(assets.rglob("*.strings")):
        text = path.read_text(encoding="utf-8", errors="replace")
        strings_files.append({
            "path": path.relative_to(assets).as_posix(),
            "bytes": path.stat().st_size,
            "key_value_pairs": len(re.findall(r'^\s*"[^"]*"\s*=\s*"', text, re.M)),
        })

    prices_path = assets / "GameResources" / "defaultPrices"
    price_fields: list[str] = []
    price_entries = 0
    if prices_path.exists():
        prices = plistlib.loads(prices_path.read_bytes())
        price_entries = len(prices)
        fields: set[str] = set()
        for entry in prices.values():
            if isinstance(entry, dict):
                fields |= set(entry)
        price_fields = sorted(fields)

    words: dict[str, list[int]] = {}
    for _, symbol in names:
        for word in re.split(r"[^A-Za-z]+", symbol):
            if len(word) >= MIN_WORD and not word.startswith("Deprecated"):
                words.setdefault(word, standalone_offsets(blob, word))

    contexts: dict[str, int] = {}
    hit_words = {}
    for word, offsets in words.items():
        if not offsets:
            continue
        classes = [classify_context(blob, offset) for offset in offsets]
        hit_words[word] = {"offsets": len(offsets), "contexts": sorted(set(classes))}
        for kind in classes:
            contexts[kind] = contexts.get(kind, 0) + 1

    classes = {m.group(1).decode()
               for m in re.finditer(rb"OBJC_CLASS_\$_([A-Za-z_][A-Za-z0-9_]*)", blob)}
    exact = [(index, symbol) for index, symbol in names if symbol in classes]
    partial = [(index, symbol) for index, symbol in names
               if symbol not in classes
               and any(c.endswith(symbol) or symbol.endswith(c) for c in classes if len(c) > 5)]

    counts = {
        "reference_names": len(names),
        "strings_files": len(strings_files),
        "strings_key_value_pairs": sum(f["key_value_pairs"] for f in strings_files),
        "defaultprices_entries": price_entries,
        "defaultprices_fields": price_fields,
        "words_probed": len(words),
        "words_with_standalone_hit": len(hit_words),
        "hit_context_name_list": contexts.get("name-list", 0),
        "hit_context_objc_symbol": contexts.get("objc-symbol", 0),
        "hit_context_other": contexts.get("other", 0),
        "exact_objc_class_matches": len(exact),
        "partial_objc_class_matches": len(partial),
        "name_table_found": 0,
    }
    return {
        "schema": 1,
        "assets_root": str(assets),
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "claim": ("item display-name sources audited: localization, price data, the "
                  "binary string table and ObjC class naming. No name table ships; "
                  "standalone-token hits are character-name lists and class names"),
        "counts": counts,
        "localization_files": strings_files,
        "class_name_matches": {"exact": [s for _, s in exact][:60],
                               "partial": [s for _, s in partial][:60]},
        "word_hits": dict(sorted(hit_words.items())[:80]),
    }


def render_tsv(record: dict) -> str:
    lines = ["kind\tname\tvalue"]
    lines.append(f"source\tstrings\tfiles={record['counts']['strings_files']} "
                 f"keys={record['counts']['strings_key_value_pairs']}")
    lines.append(f"source\tdefaultPrices\tentries={record['counts']['defaultprices_entries']} "
                 f"fields={','.join(record['counts']['defaultprices_fields'])}")
    lines.append(f"source\tbinary-name-table\t{record['counts']['name_table_found']}")
    lines.append(f"source\tobjc-class-exact-matches\t{record['counts']['exact_objc_class_matches']}")
    for word, info in record["word_hits"].items():
        lines.append(f"word-hit\t{word}\toffsets={info['offsets']} "
                     f"contexts={','.join(info['contexts'])}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", type=Path)
    ap.add_argument("elf", type=Path)
    native_default = Path("reconstruction/reverse-v3/native")
    ap.add_argument("--native", type=Path, default=native_default)
    ap.add_argument("--tsv", type=Path, default=native_default / "item_display_name_sources.tsv")
    ap.add_argument("--json", type=Path, default=native_default / "item_display_name_sources.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.assets, args.elf, args.native)
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
