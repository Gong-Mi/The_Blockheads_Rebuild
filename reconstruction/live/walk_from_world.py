#!/usr/bin/env python3
"""Walk the live object graph from the World instance instead of guessing instances from the heap.

Why: scanning heap words for a class pointer matched class references held in tables and caches, not
instances (that attempt is recorded as a negative in live_craftable_records.json). The reliable route is to
identify a root object with a strong signature - find_world does that, checking the header class, the
DynamicWorld hop, its backref and the saveID string - and then follow KNOWN ivar offsets, which is what this
project's world_layout.h and the ivar tables provide.

Usage: python3 walk_from_world.py --elf <1.7.5 .so> --pid <pid> [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_clock_175 import Probe, find_world          # noqa: E402

INTERESTING = ["PaintMixUI", "Workbench", "UIManager", "Action", "CraftableItemObject",
               "PaintingCraftableItemObject", "BlockheadCraftableItemObject", "DynamicWorld", "Blockhead",
               "GameView", "WorldTileLoader", "ScrollingButtons"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--json", default=None)
    ap.add_argument("--depth", type=int, default=3)
    args = ap.parse_args()

    p = Probe(args.pid, args.elf)
    world, info = find_world(p)
    print(f"World: {world if world is None else hex(world)}")
    print(json.dumps({k: v for k, v in info.items() if k != "heap_verified"}, indent=1)[:600])
    if not world:
        return 1

    live = {}
    for name in INTERESTING:
        try:
            live[name] = p.live_class(name)
        except Exception:
            live[name] = None
    by_ptr = {v: k for k, v in live.items() if v}
    print(f"interesting classes resolved: {sum(1 for v in live.values() if v)}/{len(INTERESTING)}")

    # bounded BFS: from World, follow every ivar of every object reached, up to --depth hops, and report
    # which of the interesting classes show up with the path that reached them. Verified by isa at every hop,
    # which is what the heap scan could not do.
    ivars_by_class: dict[str, dict[str, int]] = {}
    for key, sym in getattr(p, "ivar_sym", {}).items():
        if "." not in key:
            continue
        cls, name = key.split(".", 1)
        try:
            off = p.cell(sym)
        except Exception:
            continue
        if off is None or off <= 0 or off > 4096:
            continue
        ivars_by_class.setdefault(cls, {})[name] = off
    print(f"classes with usable ivar offsets: {len(ivars_by_class)} "
          f"(World: {len(ivars_by_class.get('World', {}))})")
    found, seen, frontier = [], {world}, [(world, "World", "root")]
    for depth in range(args.depth):
        nxt = []
        for obj, cls, path in frontier:
            clsname = None
            if cls == "root":
                clsname = "World"
            else:
                clsname = cls
            for name, off in ivars_by_class.get(clsname, {}).items():
                val = p.rdw(obj + off)
                if not val or val in seen or val > 0x100000000:
                    continue
                icls = p.rdw(val)
                iname = by_ptr.get(icls)
                if not iname:
                    continue
                seen.add(val)
                found.append({"path": f"{path} -> {name}", "depth": depth + 1, "class": iname,
                              "object": hex(val), "offset": off})
                nxt.append((val, iname, f"{path} -> {name}"))
        frontier = nxt
    print(f"\ninteresting objects reachable within {args.depth} hops: {len(found)}")
    for f in found:
        print(f"   depth {f['depth']} {f['class']:28s} {f['object']}  via {f['path']}")

    # if a CraftableItemObject is reachable, read its inline record (ivar offset from its own cell)
    records = []
    for f in found:
        if f["class"] not in ("CraftableItemObject", "PaintingCraftableItemObject",
                             "BlockheadCraftableItemObject", "Action"):
            continue
        try:
            off = p.cell(p.ivar_sym[f"{f['class']}.craftableItem"])
        except Exception:
            continue
        rec = p.rds(int(f["object"], 16) + off, 124)
        if len(rec) == 124:
            records.append({"object": f["object"], "class": f["class"], "ivar_offset": off,
                            "raw": rec.hex(),
                            "words": [struct.unpack_from("<i", rec, o)[0] for o in range(0, 124, 4)]})
    rep = {"elf": args.elf, "pid": args.pid, "world": hex(world), "world_info": info,
           "reachable": found, "records": records}
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=1) + "\n")
    for r in records:
        print(f"\n   {r['class']} {r['object']} record @+{r['ivar_offset']}: {r['words']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
