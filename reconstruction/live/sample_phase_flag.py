#!/usr/bin/env python3
"""Sample timeOfDayFraction and isHeadingTowardsMIdday every N seconds and print the pairs, to find the flip.

The rate table showed the phase advancing 0.0118/s and that one-byte flag toggling, so a flag that means
"heading towards midday" should flip at a fixed phase value. This samples fast enough to see the pair change
and prints (fraction, flag) so the threshold can be read instead of guessed. Read-only.

Usage: sample_phase_flag.py --elf <so> --pid <pid> [--seconds 90] [--period 2]
"""
import argparse, json, struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_clock_175 import Probe, find_world

ap = argparse.ArgumentParser()
ap.add_argument("--elf", required=True); ap.add_argument("--pid", type=int, required=True)
ap.add_argument("--seconds", type=float, default=90.0); ap.add_argument("--period", type=float, default=2.0)
ap.add_argument("--json", default=None)
a = ap.parse_args()
p = Probe(a.pid, a.elf)
world, info = find_world(p)
if not world:
    print("world not found"); sys.exit(1)
# resolve the two ivars by NAME through the ivar table, so the offsets are not hand-copied
table, *_ = p.ivar_table("World")
offs = {}
for iv in table:
    if iv["name"] in ("timeOfDayFraction", "isHeadingTowardsMIdday", "sunDirection", "worldTime"):
        off = p.cell(iv["offset_ptr"])
        offs[iv["name"]] = off if off is not None else iv["offset_ptr"]
print(f"world {world:#x} offsets {offs}")
rows = []
t_end = time.time() + a.seconds
while time.time() < t_end:
    frac = struct.unpack_from("<f", p.rds(world + offs["timeOfDayFraction"], 4), 0)[0]
    flag = struct.unpack_from("<b", p.rds(world + offs["isHeadingTowardsMIdday"], 1), 0)[0]
    sun = struct.unpack_from("<4f", p.rds(world + offs["sunDirection"], 16), 0)
    wt = struct.unpack_from("<d", p.rds(world + offs["worldTime"], 8), 0)[0]
    rows.append({"t": round(time.time() % 10000, 2), "fraction": frac, "flag": flag,
                 "sun_y": sun[1], "worldTime": wt})
    print(f"   fraction={frac:.6f}  flag={flag}  sun_y={sun[1]:+.6f}  worldTime={wt:.2f}")
    time.sleep(a.period)
# find the flips
flips = [(rows[i-1], rows[i]) for i in range(1, len(rows)) if rows[i]["flag"] != rows[i-1]["flag"]]
print(f"\nflips observed: {len(flips)}")
for before, after in flips:
    print(f"   flag {before['flag']} -> {after['flag']} between fraction {before['fraction']:.6f} "
          f"and {after['fraction']:.6f} (sun_y {before['sun_y']:+.4f} -> {after['sun_y']:+.4f})")
if a.json:
    Path(a.json).write_text(json.dumps({"world": hex(world), "offsets": offs, "samples": rows}, indent=1) + "\n")
