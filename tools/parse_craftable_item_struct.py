#!/usr/bin/env python3
"""Parse the CraftableItem struct layout out of the ObjC type encoding.

The crafting recipe data is a POD blob inside every CraftableItemObject: the
`savedict` read-back evidence records `[[saveDict objectForKey:@"craftableItem"]
getBytes:&self->craftableItem length:124]`, i.e. a 124-byte struct copied verbatim out of
the save. Its layout is not a guess - the binary carries the type encoding:

    @132@0:4{CraftableItem=ii[8i][8i]iiiSSi[8i]}8

That is the authoritative field list. This tool parses it into byte offsets and checks
the total against the 124-byte blob length the savedict evidence measured; the two come
from unrelated places in the binary, so agreement is a cross-check rather than a
restatement.

Field meanings are NOT claimed here: the encoding gives types and offsets only.

Usage:
  python3 tools/parse_craftable_item_struct.py <libApplication.so> [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ENCODING_RE = re.compile(rb"\{CraftableItem=([A-Za-z0-9\[\]]+)\}")
BLOB_LENGTH = 124          # from CRAFTABLEITEM_INITSAVEDICT.md (getBytes: length:124)
INSTANCE_SIZE = 128        # CraftableItemObject class struct instance_size
TYPE_SIZES = {"i": 4, "I": 4, "S": 2, "s": 2, "c": 1, "C": 1, "B": 1,
              "f": 4, "d": 8, "q": 8, "Q": 8, "L": 4, "l": 4}


def parse_fields(encoded: bytes) -> list[dict]:
    """Split `ii[8i][8i]iiiSSi[8i]` into ordered (type, count, size) entries."""
    text = encoded.decode()
    fields, index = [], 0
    while index < len(text):
        if text[index] == "[":
            end = text.index("]", index)
            inner = text[index + 1:end]
            count = int(re.match(r"\d+", inner).group(0))
            elem = inner[len(str(count)):]
            fields.append({"type": elem, "count": count,
                           "size": TYPE_SIZES.get(elem, 0) * count})
            index = end + 1
        else:
            fields.append({"type": text[index], "count": 1,
                           "size": TYPE_SIZES.get(text[index], 0)})
            index += 1
    return fields


def build(elf: Path) -> dict:
    blob = elf.read_bytes()
    match = ENCODING_RE.search(blob)
    if not match:
        raise SystemExit("CraftableItem type encoding not found")
    encoding = match.group(0).decode()
    fields = parse_fields(match.group(1))
    offset = 0
    for field in fields:
        field["offset"] = offset
        offset += field["size"]
    total = offset

    return {
        "schema": 1,
        "elf_sha256": hashlib.sha256(blob).hexdigest(),
        "claim": ("field layout of the CraftableItem blob parsed from the ObjC type "
                  "encoding in the pinned binary, checked against the 124-byte length the "
                  "savedict read-back measured; field meanings are not claimed"),
        "encoding": encoding,
        "encoding_offset": match.start(),
        "counts": {
            "fields": len(fields),
            "packed_size": total,
            "blob_length_from_savedict": BLOB_LENGTH,
            "sizes_agree": total == BLOB_LENGTH,
            "instance_size": INSTANCE_SIZE,
            "int_arrays": sum(1 for f in fields if f["count"] == 8),
            "array_bytes": sum(f["size"] for f in fields if f["count"] == 8),
        },
        "fields": fields,
    }


def render_tsv(record: dict) -> str:
    lines = ["index\toffset\ttype\tcount\tsize"]
    for index, field in enumerate(record["fields"]):
        lines.append(f"{index}\t{field['offset']}\t{field['type']}\t"
                     f"{field['count']}\t{field['size']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("elf", type=Path)
    ap.add_argument("--tsv", type=Path, default=native / "craftable_item_struct.tsv")
    ap.add_argument("--json", type=Path, default=native / "craftable_item_struct.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    record = build(args.elf)
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
