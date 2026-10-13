# worldTime domain: one clock, in seconds; a day is 900 seconds

Evidence grade: **A** — read directly from the pinned original ARM ELF, with the
literal-pool constants that fix the scale.

- Original ELF: `libApplication.so` (armeabi-v7a), SHA-256
  `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
- Function: `-[World getDayNightFractionForX:atWorldTime:]` @ `0x00582ad8`
  (type encoding `f20@0:4f8d12` — the worldTime argument is a **double**)
- Function: `-[World getWeatherFractionForPos:atWorldTime:]` @ `0x00582408`
  (`f24@0:4{?=ii}8d16` — again a double)

## What the disassembly proves about the domain

The prologue of `getDayNightFractionForX:atWorldTime:` normalises worldTime before
any trigonometry:

```text
0x00582aec: vldr  d1, [fp, #8]      ; worldTime (double)
0x00582b10: vldr  d2, [pc, #0x2c8]  ; literal pool 0x00582de0
0x00582b14: vdiv.f64 d1, d1, d2     ; worldTime / 900.0
0x00582b18: vcvt.f32.f64 s0, d1
0x00582b24: bl    #0x1c3d4c         ; fractional part (modf/fmod)
...
0x00582b34: vmov.f64 d2, #0.5
0x00582b38: vsub.f64 d1, d2, d1     ; 0.5 - dayFraction
0x00582b3c: vldr  d3, [pc, #0x2a4]  ; literal pool 0x00582de8
0x00582b40: vmul.f64 d1, d1, d3     ; (0.5 - dayFraction) * 2*pi
```

Literal-pool values read from the same ELF:

| pool address | f64 value | role |
|---|---:|---|
| `0x00582de0` | **900.0** | seconds per in-game day (the divisor) |
| `0x00582de8` | **6.283185307179586** (2*pi) | phase conversion to radians |
| `0x00582df0` | 0.40927970959267024 | amplitude scaling applied to the cosine term |

So `worldTime` is a **single monotonically increasing clock measured in seconds**,
and an in-game day is **900 seconds**. Everything day/night-related derives its
0..1 fraction from it; `worldTime` itself is never a fraction.

## Consequence for the assembled snapshot

The real `worldv2` record of the assembled save carries `worldTime: 900.0` — i.e.
this world has run **exactly one in-game day**. Together with `saveDate`
(2026-09-05 16:52:35) and `creationDate` (16:43:32), the 543-second wall-clock gap
between creation and save is *not* consistent with a 1-unit-per-second clock (900
units cannot elapse in 543 s); it is consistent with the 20-units-per-second state
measured live in `LIVE_WORLD_CLOCK.md`, where 900 units is 45 s of unpaused
simulation inside that window.

## Regeneration

`tools/extract_world_time_domain.py <libApplication.so> --json
reconstruction/reverse-v3/native/world_time_domain.json` regenerates the record
(pool addresses, constants, and the domain claim) from the pinned ELF;
`--check` fails when the committed JSON drifts. `tools/validate_reverse_evidence.py`
requires this document and pins the constants' needles.

## Why this matters for the season gate (and the replacement)

`-[Plant loadSaveDictValues:]` gates on `worldTime - saveTime > 1800.0`
(`PLANT_LOADSAVE_ARM.md`): **1800 seconds = 2 in-game days**, boundary-pinned at
1800.5 reset / 1800.0 no-reset / 1799.9999 no-reset. That comparison only means
anything if both sides are in the seconds domain.

The replacement engine currently drives `GameWorld::worldTime` from
`world_renderer`'s `worldTime`, which is a **day fraction in [0,1]** (the frame
loop tests `worldTime > 0.25f && worldTime < 0.3f`, and
`updateTemperature` treats 0.25..0.75 as "day"). That is the *derived* quantity,
not the original clock. Feeding a 0..1 fraction into a 1800-second gate would make
the gate unfireable and the comparison meaningless.

The correct mapping, given A-grade evidence:

```text
original worldTime (double, seconds)  ->  dayFraction = fmod(worldTime / 900.0, 1.0)
```

So a replacement that wants original-compatible plant/tree behaviour must keep a
**seconds** clock and derive the fraction, rather than keeping the fraction as the
only representation.

## Boundary

- This document establishes the domain and the 900-second day. It does **not**
  claim the full day/night curve is decoded: the cosine branch, the `x` argument's
  role (day-length dependence on position) and the weather fractions are not
  recovered here.
- The 0.40927970959267024 constant is recorded as read, without asserting its meaning.
- No device run, no original-runtime differential, and no replacement-side change
  is claimed by this document.

## Rate qualifier: the unit is fixed, the rate is not (live)

The divisor above fixes that a day is **900 `worldTime` units**. How long that is in real
time is state-dependent, and the state is `World.fastForward`:

- with `fastForward` set, the live original advanced `worldTime` at **20.0 units per real
  second** (measured against `lastUpdateTime`, an NSDate-reference wall clock that the same
  probe verified at 1.000/s) — so one 900-unit day took ~45 real seconds, and the
  1800-unit plant gate fires after ~90 s;
- `-[DynamicWorld update:accurateDT:isSimulation:]` applies the constant `20.0f` only
  under that flag (`LIVE_WORLD_CLOCK.md` has the instruction sequence);
- no `fastForward == 0` session has been observed, so the 1x rate is inferred from the
  `beq` that skips the whole block, not measured.

Read the claim below as "900 units, whose real-time length depends on `fastForward`" —
and never record a rate without recording the flag.
