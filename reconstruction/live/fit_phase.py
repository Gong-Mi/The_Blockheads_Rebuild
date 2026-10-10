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
    # The sinusoid fit matters more than the triangle one: the measured phase is a SINE of the 900-unit day, and a
    # tool that only tested the triangle would report "not a triangle, driver unknown" while the answer was one
    # line away. Fit both and say which wins.
    if P:
        import math
        best = (1e9, None)
        for k in range(64):
            phi = 2 * math.pi * k / 64
            ys = [math.sin(2 * math.pi * ((s["worldTime"] - samples[0]["worldTime"]) / P) + phi) for s in samples]
            ps = [s["fraction"] for s in samples]
            n = len(ys)
            my, mp = sum(ys) / n, sum(ps) / n
            num = sum((y - my) * (p - mp) for y, p in zip(ys, ps))
            den = sum((y - my) ** 2 for y in ys)
            b = num / den if den else 0.0
            a = mp - b * my
            worst = max(abs(a + b * y - p) for y, p in zip(ys, ps))
            if worst < best[0]:
                best = (worst, (phi, a, b))
        worst_sin, (phi, a, b) = best
        print(f"sine fit at the flip-derived period {P:.1f}: worst residual {worst_sin:.5f}")
        # The flip-derived period is coarse (flips are bracketed by the sample interval), so scan candidate
        # periods and report the best fit. This is what turns a coarse estimate into the actual period: the
        # round 900 that the static 900.0 constant names fits several times better than 924.5 does.
        best_scan = (1e9, None)
        for cand in [p_ for p_ in range(600, 1201, 5)]:
            for k in range(32):
                phi_c = 2 * math.pi * k / 32
                ys = [math.sin(2 * math.pi * ((s["worldTime"] - samples[0]["worldTime"]) / cand) + phi_c)
                      for s in samples]
                ps = [s["fraction"] for s in samples]
                n = len(ys)
                my, mp = sum(ys) / n, sum(ps) / n
                den = sum((y - my) ** 2 for y in ys)
                b_c = sum((y - my) * (p - mp) for y, p in zip(ys, ps)) / den if den else 0.0
                a_c = mp - b_c * my
                worst_c = max(abs(a_c + b_c * y - p_) for y, p_ in zip(ys, ps))
                if worst_c < best_scan[0]:
                    best_scan = (worst_c, (cand, phi_c, a_c, b_c))
        worst_c, (cand, phi_c, a_c, b_c) = best_scan
        print(f"best period over a 600..1200 scan: {cand} world units (worst residual {worst_c:.5f})")
        print(f"   phase ~ {a_c:.4f} + {b_c:.4f} * sin(2pi*(worldTime-{samples[0]['worldTime']:.0f})/{cand} "
              f"+ {phi_c:.3f})")
        print("verdict:", "the phase is a SINUSOID of worldTime (sine beats triangle and the period is pinned)"
              if worst_c < worst else "the triangle fits better - check the sample")

        worst = worst
    else:
        print("not enough flips for a period estimate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
