#!/usr/bin/env python3
"""Census every named C struct the binary declares in its method table.

The type encodings in libApplication_objc_methods.tsv ARE layout descriptions, so a struct's size and field
offsets can be read rather than measured. Two of this project's record models were built that way
(CraftableItem, InteractionTestResult), and this generalises it to all of them.

Exactly ONE parser lives here, on purpose: an earlier version had the parsing logic duplicated in a test, the
two copies disagreed about nested pointer types (`^{PhysicalBlock}`) and the census came out as 43 structs in
one place and 30 in the other. A rule written twice is a rule that will diverge.

Usage:
  python3 tools/extract_struct_census.py <methods.tsv> --json OUT      # write the census
  python3 tools/extract_struct_census.py <methods.tsv> --check OUT     # fail if OUT is stale
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

SIZES = {"i": 4, "I": 4, "S": 2, "s": 2, "c": 1, "C": 1, "f": 4, "d": 8, "B": 1, "q": 8, "Q": 8,
         "l": 4, "L": 4, "@": 4, ":": 4, "^": 4, "*": 4, "?": 1, "b": 4, "T": 8}
STRUCT_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)=((?:[^{}]|\{[^{}]*\})*)\}")


def _layout(body: str):
    """Field layout of an encoding body, or None when it uses a form this parser does not know."""
    out, off, i = [], 0, 0
    while i < len(body):
        m = re.match(r"\[(\d+)([a-zA-Z@:^*?])\]", body[i:])
        if m:
            ch = m.group(2)
            if ch not in SIZES:
                return None
            n = int(m.group(1)) * SIZES[ch]
            out.append({"offset": off, "type": f"{m.group(1)}x{ch}", "size": n})
            off += n
            i += m.end()
            continue
        ch = body[i]
        if ch == "{":                      # a nested struct, possibly behind a pointer (^{Name=...})
            depth, j = 0, i
            while j < len(body):
                if body[j] == "{":
                    depth += 1
                elif body[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            inner = body[i + 1:j]
            m2 = re.match(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", inner)
            sub = _layout(m2.group(2) if m2 else inner)
            if sub is None:
                return None
            size = max((x["offset"] + x["size"] for x in sub), default=0)
            out.append({"offset": off, "type": "{" + (m2.group(1) if m2 else "anonymous") + "}", "size": size})
            off += size
            i = j + 1
            continue
        if ch == "^":                      # pointer
            out.append({"offset": off, "type": "^", "size": 4})
            off += 4
            i += 1
            continue
        if ch not in SIZES:
            return None
        out.append({"offset": off, "type": ch, "size": SIZES[ch]})
        off += SIZES[ch]
        i += 1
    return out


def census(text: str) -> dict:
    found: OrderedDict = OrderedDict()
    skipped = set()
    for m in STRUCT_RE.finditer(text):
        name, body = m.group(1), m.group(2)
        lay = _layout(body)
        if lay is None:
            skipped.add(name)
            continue
        size = max((x["offset"] + x["size"] for x in lay), default=0)
        e = found.setdefault(name, {"name": name, "size": size, "occurrences": 0, "layout": lay,
                                    "encodings": set()})
        e["occurrences"] += 1
        e["encodings"].add(f"{{{name}={body}}}")
    structs = {k: {**v, "encodings": sorted(v["encodings"])} for k, v in found.items()}
    return {"schema": 1,
            "scope": "every named C struct the binary declares in its method table",
            "method": "the type encodings ARE layout descriptions, so each size and offset is parsed from one "
                      "rather than measured; this tool is the single parser (see the module docstring)",
            "counts": {"distinct_structs": len(structs),
                       "total_occurrences": sum(v["occurrences"] for v in structs.values()),
                       "skipped_unparsed_forms": sorted(skipped)},
            "structs": structs,
            "reading_notes": [
                "the net-data family shares one 24-byte header ({DynamicObjectNetData=QIIC[7C]}) nested inside "
                "TrainCarCreationNetData, NPCCreationNetData, PlantCreationNetData and NPCUpdateNetData",
                "PhysicalBlock and Tile are the world's own records; WindowInfo is the most-referenced one",
                "CATransform3D (64) and CGAffineTransform (24) are Apple types whose sizes are known "
                "independently, which is what makes them a sanity check on the parser rather than a finding"],
            "boundary": "sizes and offsets are parsed facts; field NAMES are not claimed. Encodings this "
                        "parser does not understand are listed in skipped_unparsed_forms instead of guessed, "
                        "so a struct missing from the census is a parser limitation until shown otherwise."}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("methods", type=Path)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--check", type=Path, default=None)
    args = ap.parse_args()
    rep = census(args.methods.read_text())
    payload = json.dumps(rep, indent=1) + "\n"
    if args.check:
        if not args.check.is_file():
            print(f"missing census: {args.check}", file=sys.stderr)
            return 1
        current = json.loads(args.check.read_text())
        fresh = json.loads(payload)
        for key in ("counts", "structs"):
            if current.get(key) != fresh.get(key):
                print(f"census is stale in '{key}' - re-run without --check", file=sys.stderr)
                return 1
        print(f"census up to date: {fresh['counts']['distinct_structs']} structs, "
              f"{len(fresh['counts']['skipped_unparsed_forms'])} unparsed forms")
        return 0
    if args.json:
        args.json.write_text(payload)
    print(json.dumps({k: v for k, v in rep["counts"].items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
