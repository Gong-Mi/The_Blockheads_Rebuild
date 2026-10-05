#!/usr/bin/env python3
"""Fit the day phase against worldTime from the long sample, instead of eyeballing a window.

The earlier 96 s window contained a turnaround, which produced both a wrong period and a wrong "the phase
correlates with the sun" reading. This takes the long sample (several full cycles) and asks the question in a
form that can be answered: if the phase is a triangle wave of worldTime, then

    phase = triangle((worldTime - t0) / P)

for some period P, and P can be fitted and the residual checked. If the residual is large, the phase is NOT a
function of worldTime and the record should say that instead.

Usage: fit_phase.py <phase_long.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def triangle(x: float) -> float:
    f = x % 1.0
    return 2 * f if f < 0.5 else 2 * (1 - f)


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "phase_long.json")
    data = json.loads(path.read_text())
    samples = data["samples"]
    print(f"samples: {len(samples)}  span: {samples[-1]['worldTime'] - samples[0]['worldTime']:.1f} world units "
          f"({samples[-1]['t'] - samples[0]['t']:.0f} s)")

    # turning points from the flag, which the short sample showed flips exactly at them
    flips = []
    for a, b in zip(samples, samples[1:]):
        if a["flag"] != b["flag"]:
            flips.append((a, b))
    print(f"flag flips: {len(flips)}")
    for a, b in flips:
        print(f"   flag {a['flag']}->{b['flag']} at worldTime {a['worldTime']:.1f}..{b['worldTime']:.1f} "
              f"phase {a['fraction']:.4f}..{b['fraction']:.4f}")

    # period estimate from consecutive same-type flips (trough to trough), then an amplitude-scaled fit
    peak_wt = [b["worldTime"] for a, b in flips if a["flag"] == 1 and b["flag"] == 0]
    if len(peak_wt) >= 2:
        gaps = [peak_wt[i + 1] - peak_wt[i] for i in range(len(peak_wt) - 1)]
        print(f"peak-to-peak worldTime gaps: {[round(g, 1) for g in gaps]}")
        P = sum(gaps) / len(gaps)
    else:
        P = None
    if P:
        phase_max = max(s["fraction"] for s in samples)
        phase_min = min(s["fraction"] for s in samples)
        amp = (phase_max - phase_min) / 2
        t0 = samples[0]["worldTime"]
        resid = []
        for s in samples:
            pred = phase_min + amp * triangle((s["worldTime"] - t0) / P)
            resid.append(abs(pred - s["fraction"]))
        worst = max(resid)
        mean = sum(resid) / len(resid)
        print(f"period P = {P:.1f} world units ({P / 20:.1f} s at 20 units/s)  amplitude {amp:.4f} "
              f"(min {phase_min:.4f} max {phase_max:.4f})")
        print(f"triangle fit residual: mean {mean:.5f}  worst {worst:.5f}")
        verdict = ("the phase IS a triangle wave of worldTime" if worst < 0.02 else
                   "the phase is NOT a triangle wave of worldTime - the driver is something else")
        print("verdict:", verdict)
    else:
        print("not enough flips for a period estimate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
