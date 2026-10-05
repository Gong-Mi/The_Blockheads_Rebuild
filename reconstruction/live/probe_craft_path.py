#!/usr/bin/env python3
"""Follow the known ivar path from World toward a crafting record, printing every hop (read-only).

The names in the ivar tables are the map: PaintMixUI.workbench / incomingCraftableItemObject / craftButton,
Workbench.craftableItems / craftingItemObject. This walks that path explicitly rather than by BFS, so each hop
is visible and a null one is reported as null instead of as "nothing found".
"""
import argparse, json, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_clock_175 import Probe, find_world

ap = argparse.ArgumentParser()
ap.add_argument("--elf", required=True); ap.add_argument("--pid", type=int, required=True)
ap.add_argument("--json", default=None)
a = ap.parse_args()
p = Probe(a.pid, a.elf)
world, info = find_world(p)
if not world: print("no world"); sys.exit(1)
print(f"World {world:#x}")

def off(cls, name):
    sym = p.ivar_sym.get(f"{cls}.{name}")
    if sym is None: return None
    o = p.cell(sym)
    return o if o and o > 0 else None

def clsname(ptr):
    if not ptr: return None
    c = p.rdw(ptr) or 0
    for name in ("World", "UIManager", "PaintMixUI", "Workbench", "CraftableItemObject",
                 "PaintingCraftableItemObject", "BlockheadCraftableItemObject", "Blockhead", "Action"):
        try:
            if p.live_class(name) == c: return name
        except Exception:
            pass
    return f"isa={c:#x}"

steps = []
ui_off = off("World", "uiManager")
ui = p.rdw(world + ui_off) if ui_off else 0
steps.append(("World.uiManager", ui_off, ui, clsname(ui)))
pm_off = off("UIManager", "paintMixUI")
pm = p.rdw(ui + pm_off) if (ui and pm_off) else 0
steps.append(("UIManager.paintMixUI", pm_off, pm, clsname(pm)))
for name in ("workbench", "incomingCraftableItemObject", "craftButton", "countSlider", "currentCount",
             "blockhead", "world"):
    o = off("PaintMixUI", name)
    v = p.rdw(pm + o) if (pm and o) else 0
    steps.append((f"PaintMixUI.{name}", o, v, clsname(v)))
wb_off = off("PaintMixUI", "workbench")
wb = p.rdw(pm + wb_off) if (pm and wb_off) else 0
for name in ("craftableItems", "craftingItemObject", "selectedIndex", "numberOfCraftableItems", "type",
             "sourceItems", "level"):
    o = off("Workbench", name)
    v = p.rdw(wb + o) if (wb and o) else 0
    steps.append((f"Workbench.{name}", o, v, clsname(v)))
print(f"\n{'path':44s} {'off':>5s} {'value':>12s}  class")
for path, o, v, c in steps:
    print(f"   {path:41s} {str(o):>5s} {v:#12x}  {c}")

# if a CraftableItemObject is anywhere in the path, read its inline record
records = []
for path, o, v, c in steps:
    if c and "CraftableItemObject" in c and v:
        rec_off = off(c, "craftableItem")
        if not rec_off: continue
        rec = p.rds(v + rec_off, 124)
        if len(rec) == 124:
            records.append({"path": path, "object": hex(v), "class": c, "record_ivar": rec_off,
                            "words": [struct.unpack_from("<i", rec, x)[0] for x in range(0, 124, 4)],
                            "raw": rec.hex()})
for r in records:
    print(f"\n   RECORD via {r['path']} ({r['class']} {r['object']} @+{r['record_ivar']}):\n      {r['words']}")
if a.json:
    Path(a.json).write_text(json.dumps({"world": hex(world), "steps":
        [{"path": s[0], "offset": s[1], "value": hex(s[2]), "class": s[3]} for s in steps],
        "records": records}, indent=1) + "\n")
