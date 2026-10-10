#!/usr/bin/env python3
"""Rate table for ANY live object's numeric ivars: sample twice and print units/second.

The World rate table showed no field advancing with the day phase, so the driver is elsewhere. This runs the
same measurement against another object reached by the validated walk (e.g. DynamicWorld at World+416), so the
comparison is between two objects rather than between a measurement and a guess. Read-only.

Usage: rate_table_any.py --elf <so> --pid <pid> --cls DynamicWorld [--gap 25] [--top 24] [--json OUT]
"""
import argparse, json, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_clock_175 import Probe, find_world

ap = argparse.ArgumentParser()
ap.add_argument("--elf", required=True); ap.add_argument("--pid", type=int, required=True)
ap.add_argument("--cls", default="DynamicWorld"); ap.add_argument("--gap", type=float, default=25.0)
ap.add_argument("--top", type=int, default=24); ap.add_argument("--json", default=None)
a = ap.parse_args()
p = Probe(a.pid, a.elf)
world, info = find_world(p)
if not world: print("no world"); sys.exit(1)
# reach the object: DynamicWorld sits at World.dynamicWorld
if a.cls == "DynamicWorld":
    off = p.cell(p.ivar_sym["World.dynamicWorld"])
    obj = p.rdw(world + off)
else:
    print("only DynamicWorld is wired here"); sys.exit(1)
print(f"World {world:#x} -> {a.cls} {obj:#x} (isa {p.rdw(obj):#x} vs class {p.live_class(a.cls):#x})")
table, *_ = p.ivar_table(a.cls)
NUM = ("d", "f", "i", "I", "q", "Q", "c", "C", "B", "s", "S")
fields = []
for iv in table:
    if iv["encoding"] not in NUM: continue
    o = p.cell(iv["offset_ptr"])
    if o is None or not (0 < o <= 65536): continue
    fields.append((iv["name"], iv["encoding"], o))
def val(enc, o):
    size = {"d": 8, "q": 8, "Q": 8}.get(enc, {"f": 4, "i": 4, "I": 4, "S": 2, "s": 2}.get(enc, 1))
    raw = p.rds(obj + o, size)
    return struct.unpack({"d": "<d", "q": "<q", "Q": "<Q", "f": "<f", "i": "<i", "I": "<I",
                          "S": "<H", "s": "<h"}.get(enc, "<b"), raw)[0] if len(raw) == size else None
first = {n: (e, o, val(e, o)) for n, e, o in fields}
time.sleep(a.gap)
second = {n: val(e, o) for n, (e, o, _) in first.items()}
rows = []
for n, (e, o, v0) in first.items():
    v1 = second[n]
    if v0 is None or v1 is None: continue
    d = (v1 - v0) / a.gap
    if abs(d) > 1e-6: rows.append((abs(d), d, n, e, v0, v1))
rows.sort(reverse=True)
print(f"gap {a.gap}s, numeric ivars sampled: {len(first)}, moving: {len(rows)}")
for _, d, n, e, v0, v1 in rows[:a.top]:
    print(f"   {d:+12.6f}/s  {n:38s} {e}  {v0!r} -> {v1!r}")
if a.json:
    Path(a.json).write_text(json.dumps({"object": hex(obj), "gap": a.gap,
        "moving": [{"name": n, "enc": e, "delta_per_s": d, "from": v0, "to": v1} for _, d, n, e, v0, v1 in rows]},
        indent=1) + "\n")
