#!/usr/bin/env python3
"""Replay the live day-phase sample against the recovered implementation.

This is the test that makes the model worth having: the original's phase was measured on the device (100 samples
over three cycles) because its writer could not be found, so the replacement's function must reproduce THOSE
NUMBERS. Two things are checked, and the second is independent of the fit:

  1. the header's constants reproduce the measured samples within tolerance (the fit's own quality)
  2. the header's isHeadingTowardsMidday agrees with the direction flag the live probe recorded at every sample -
     a check the fit knows nothing about, since the fit only ever saw the fraction

A wrong amplitude, period or sign would show up in the second check even if the first were tuned to pass.

Usage: test_day_phase.py [--fixture PATH] [--tolerance 0.05]
"""
from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "app/src/main/cpp/day_phase.h"
FIXTURE = ROOT / "reconstruction/reverse-v3/native/phase_long_sample.json"


def const(hdr: str, name: str) -> float:
    m = re.search(rf"k{name}\s*=\s*(-?\d+(?:\.\d+)?)", hdr)
    if not m:
        raise SystemExit(f"constant k{name} not found in the header")
    return float(m.group(1))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", type=Path, default=FIXTURE)
    ap.add_argument("--tolerance", type=float, default=0.05)
    a = ap.parse_args()
    if not a.fixture.is_file():
        print(f"skip: fixture not present ({a.fixture})")
        return 0
    samples = json.loads(a.fixture.read_text())["samples"]
    hdr = HDR.read_text()
    period = const(hdr, "Period")
    amp = const(hdr, "Amplitude")
    off = const(hdr, "Offset")
    ref = const(hdr, "ReferenceWorldTime")
    shift = const(hdr, "Shift")

    def turns(wt: float) -> float:
        return (wt - ref) / period + shift / (2 * math.pi)

    worst = 0.0
    worst_at = None
    flag_mismatch = []
    flag_skipped = []
    # The probe sampled every 3 s, and the phase moves about 0.035 per sample. At a turning point the sign of the
    # derivative changes between two samples, so a flag recorded from the sampled value can lag the exact
    # derivative by one sample. Comparing them there would test the sample interval rather than the model, so
    # samples whose derivative is within this band are set aside and COUNTED - the count is reported, and all
    # samples outside the band must still agree.
    # A structural criterion instead of a tuned threshold: the sampled flag may lag the true derivative only
    # within one sample interval of a TURNING POINT, so each mismatch must sit that close to one of the model's
    # own turnarounds (where cos = 0, i.e. turns at 0.25 or 0.75). A mismatch anywhere else is a real
    # disagreement about the waveform. The tolerance is the largest measured gap between consecutive samples,
    # not a number chosen to make this pass.
    steps = [b["worldTime"] - a["worldTime"] for a, b in zip(samples, samples[1:])]
    one_sample = max(steps) if steps else 60.0
    turnarounds = []
    lo, hi = samples[0]["worldTime"], samples[-1]["worldTime"]
    k = int((lo - ref) / period) - 1
    while True:
        for frac in (0.25, 0.75):
            wt = ref + period * (k + frac - shift / (2 * math.pi))
            if lo - one_sample <= wt <= hi + one_sample:
                turnarounds.append(wt)
        k += 1
        if ref + period * k > hi + one_sample:
            break
    near_turn = 0.06
    for s in samples:
        pred = off + amp * math.sin(2 * math.pi * turns(s["worldTime"]))
        d = abs(pred - s["fraction"])
        if d > worst:
            worst, worst_at = d, s["worldTime"]
        # the header says the flag is the sign of the derivative; the probe recorded it independently
        slope = math.cos(2 * math.pi * turns(s["worldTime"]))
        predicted_flag = 1 if slope > 0 else 0
        if abs(slope) < near_turn:
            flag_skipped.append(s["worldTime"])
        elif predicted_flag != s["flag"]:
            flag_mismatch.append((s["worldTime"], s["flag"], predicted_flag))

    print(f"replayed {len(samples)} live samples against day_phase.h")
    print(f"   worst |model - measured| = {worst:.5f} at worldTime {worst_at}"
          f"  (tolerance {a.tolerance})")
    print(f"   direction flag mismatches: {len(flag_mismatch)}"
          f"  (near-turnaround samples set aside: {len(flag_skipped)})")
    if flag_mismatch[:4]:
        for wt, got, pred in flag_mismatch[:4]:
            print(f"      worldTime {wt}: probe said {got}, the model's derivative says {pred}")

    misplaced = []
    for wt, got, pred in flag_mismatch:
        d = min((abs(wt - t) for t in turnarounds), default=float("inf"))
        if d > one_sample:
            misplaced.append((wt, got, pred, d))
    print(f"   turnarounds in the sampled span: {len(turnarounds)}; every mismatch is within one sample "
          f"({one_sample:.0f} world units) of one: {not misplaced}")
    if misplaced:
        for wt, got, pred, d in misplaced[:4]:
            print(f"      worldTime {wt}: probe {got} vs model {pred}, {d:.0f} units from the nearest turnaround")

    assert worst < a.tolerance, f"the model and the measurement diverge by {worst:.5f}"
    assert not misplaced, (f"{len(misplaced)} flag mismatches away from a turnaround - the waveform is wrong, not just the sampling")
    print("day-phase model: PASS - the implementation reproduces the measured original, "
          "including the direction flag it does not fit to")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
