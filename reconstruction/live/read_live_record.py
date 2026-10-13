#!/usr/bin/env python3
"""Read a live instance's inline record for an arbitrary class/ivar, using the validated class resolution.

Generalises the CraftableItem scan: the class object is relocated from the ELF's __objc_classlist through the
live rw segment and cross-checked against the relocated classlist cell, instances are found by scanning
anonymous rw regions for that class pointer, and the record is read at the requested ivar offset.

Read-only: /proc/<pid>/maps + pread on /proc/<pid>/mem.

Usage:
  python3 read_live_record.py --elf <1.7.5 .so> --pid <pid> --cls Action --ivar 52 --size 12 \
      [--fields 0,4,8,10] [--max 8] [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_clock_175 import Probe                     # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--cls", required=True)
    ap.add_argument("--ivar", type=int, required=True, help="byte offset of the inline record in the instance")
    ap.add_argument("--size", type=int, required=True)
    ap.add_argument("--fields", default="", help="comma-separated offsets to decode; default: words throughout")
    ap.add_argument("--max", type=int, default=8)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    p = Probe(args.pid, args.elf)
    cls = p.live_class(args.cls)
    reloc = p.classlist_reloc(args.cls)
    print(f"{args.cls}: live class {cls if cls is None else hex(cls)} | classlist cross-check "
          f"{reloc if reloc is None else hex(reloc)} | agree={cls == reloc}")
    if not cls:
        return 1

    hits = []
    for lo, hi, prot, _off, name in p.maps:
        if prot != "rw-p" or name.strip() or hi - lo > 64 * 1024 * 1024:
            continue
        step = 0x100000
        for base in range(lo, hi, step):
            chunk = p.rds(base, min(step, hi - base))
            if not chunk:
                continue
            needle = struct.pack("<I", cls)
            start = 0
            while True:
                i = chunk.find(needle, start)
                if i < 0:
                    break
                if i % 4 == 0:
                    hits.append(base + i)
                start = i + 4
    print(f"anonymous-rw words equal to the class pointer: {len(hits)}")

    offs = [int(x, 0) for x in args.fields.split(",") if x.strip()] if args.fields else \
        list(range(0, args.size, 4))
    rows = []
    for obj in hits[:args.max]:
        rec = p.rds(obj + args.ivar, args.size)
        if len(rec) < args.size:
            continue
        vals = {f"+{o}": struct.unpack_from("<I", rec, o)[0] for o in offs if o + 4 <= len(rec)}
        rows.append({"object": hex(obj), "fields": vals, "raw": rec.hex()})
    rep = {"cls": args.cls, "class_ptr": hex(cls), "classlist_agrees": cls == reloc,
           "ivar_offset": args.ivar, "size": args.size, "candidates": len(hits), "records": rows}
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=1) + "\n")
    for r in rows:
        print(f"\n  {r['object']}: " + "  ".join(f"{k}={v}" for k, v in r["fields"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
