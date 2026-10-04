# Live world clock: `worldTime` runs 20 units per real second while `fastForward` is set

Evidence grade: **B** — measured on the running original over `/proc/<pid>/mem`, with the
build bound by sha256 and every field offset cross-checked against two independent
structures in the pinned ELF. It is a live measurement, so it is true of *the observed
session and state*, and says nothing about a session with the flag clear.

Companion artifact: `live_world_clock.json`. Probe: `tools/probe_live_world_clock.py`
(+ `tools/test_probe_live_world_clock.py`).

## What was measured

Device build: `com.noodlecake.blockheads` 1.7.5, running `libApplication.so`
`d09418e9c0865902054a71358dcff3264d47f7b24ede58667cb5ea0e6f269b96`
(the sha256 of the **mapped** library, not of any APK).

`World` instance located by signature, not by a 4-byte class-pointer search: header word
== the runtime `World` class, `World+416 -> DynamicWorld` with `DynamicWorld+4` pointing
back, and `World+436` a string equal to the on-disk save dir name (`a8124d2b4dea3347…`,
itself derived from `/proc/<pid>/fd`, never typed on a command line).

| field | encoding | offset | source |
|---|---|---:|---|
| `worldTime` | `d` | 648 | class_ro_t ivar list **and** `OBJC_IVAR_$_World.worldTime` cell — same cell |
| `lastUpdateTime` | `d` | 3112 | same |
| `fastForward` | `c` | 934 | same |
| `timeOfDayFraction` | `f` | 880 | same |

Two independent clocks live in the same object:

```text
real seconds per second     0.999745   (lastUpdateTime; equals the wall clock:
                                       NSDate-reference 812849131.7 -> 2026-10-05 07:25 UTC,
                                       i.e. the capture time)
worldTime per real second  19.995      (slope on the sampling clock)
worldTime / lastUpdateTime 20.00012    (endpoint ratio)
```

A separate 20 s-cadence passive watcher over ~7 minutes saw the same, with
`fastForward == 1` on every row:

```text
worldTime per s: 19.9955 .. 20.0311      real per s: 0.999841 .. 1.001544
tod(t=0.1s cadence) steps: +2.008, +2.000, +2.036, +1.965, ... (per ~0.1 s frame)
```

So `worldTime` is **not** a wall-seconds clock in this session: it advances 20 units per
real second, in per-frame steps of `20 * frame_dt`. With the day/night divisor pinned at
900.0 in *this* build too (`getDayNightFractionForX:atWorldTime:` @ `0x00582c30`, pool
`0x582f38` = 900.0), a 900-unit day lasts **~45 real seconds** while the flag is set.

That is consistent with the one piece of save-side evidence already on record: the
assembled `worldv2` record carries `worldTime: 900.0` with only 543 s between
`creationDate` and `saveDate`. 900 units in ≤543 s of wall time is impossible at 1 unit/s,
and is exactly 45 s of unpaused simulation at 20 units/s.

## Where the ×20 comes from (code, not a timing artefact)

`-[DynamicWorld update:accurateDT:isSimulation:]` @ `0x008cbf40` in the 1.7.6 base
(`733d8210…`):

```text
0x008cdc58  blx  r2                       ; [world fastForward]  (selref slot 0x00e8300c)
0x008cdc5c  sxtb r0, r0
0x008cdc60  cmp  r0, #0
0x008cdc64  beq  #0x8cdc84                ; flag clear -> skip this block
0x008cdc68  movw r0, #0x14                ; 20
0x008cdc6c  vmov.f32 s0, #2.000000e+01    ; 20.0f
0x008cdc74  vldr s2, [r1]
0x008cdc78  vdiv.f32 s0, s2, s0           ; value / 20.0f
0x008cdc7c  vstr s0, [r1]
0x008cdc80  str  r0, [sp, #0x214]         ; the factor 20 is kept for later use
```

The 20 is an explicit constant gated on the flag, which also rules out the attractive
alternative explanation ("the frame dt is inflated, so everything runs fast"): in the same
object the real-time domain (`lastUpdateTime`, `saveCount`, `forcedCalibrationTimer`)
advances at 1.000/s while only the world-clock domain (`worldTime`, `noRainTimer`)
advances at 20/s.

## Why this matters for the replacement

`WORLD_TIME_DOMAIN.md` reads "worldTime is a seconds clock; an in-game day is 900
seconds". The divisor is right and the *unit* is `worldTime`'s own unit, but the rate is
state-dependent: the same 900 units is 900 s at 1x and ~45 s at 20x. A replacement that
drives `worldSeconds` from real elapsed time will therefore disagree with the original by
20x whenever the original is in this state — and the 1800-unit plant gate (`Plant
loadSaveDictValues:`) fires after 90 real seconds in that state, not 30 minutes.

Landed in the replacement with this batch:

- `GameWorld::kOriginalFastForwardScale = 20.0` and a `fastForward` state with
  `setFastForward(bool)` that drives `clockTimeScale` (`app/src/main/cpp/game_world.h`).
  The worker still advances `worldSeconds` by real elapsed time, now scaled by that
  state, so the clock stays a seconds domain and the day fraction stays derived.
- `game_engine.cpp` drove the acceleration from a hard-coded `100.0f` with no evidence
  behind it; it now derives it from the fastForward state, so the factor in the code is
  the measured one. **The mapping is an inference**: the state and the 20.0 are measured,
  but *which condition sets fastForward in the original* is not located, so mapping the
  replacement's sleep state onto it is a guess that a future batch must replace.
- The flag is deliberately **not** persisted (v4 `world.bin` still stores only
  `worldSeconds` + `hasWorldSeconds`), because the original's flag is not a savedict key
  either. `tools/test_world_clock.cpp` pins both directions: the scale is 20.0 with a
  discriminating upper bound (a regression to 100 fails) and a save/load round-trip must
  not resurrect the flag.

## Boundary

- No `fastForward == 0` session was observed, so the 1x rate is **inferred** from the
  constant's placement (the `beq` skips the whole block), not measured. Confirm by
  re-running the probe when the flag reads 0.
- **What sets the flag is not located.** `-setFastForward:` is referenced nowhere in the
  1.7.6 build, and no direct store to `World+934` exists in any `World` / `DynamicWorld` /
  `GameView` / `UIManager` method (the store must go through the ivar cell or from another
  class). The flag is a runtime state — it is not a savedict key.
- The flag did not clear across a 60-row / 20.0-minute passive window (`watcher_window` in the
  artifact: 07:27:47 -> 07:47:27, `fastForward` 1 on every row, mean ratio 19.9587), so a transient
  catch-up is ruled out for that period. Whether it is a menu setting, a server state, or a
  side effect of the app not being the focused window is still **not established**.
- Offsets are verified for the 1.7.5 build measured and are byte-identical in 1.7.6
  (only the `__objc_ivar` cell *addresses* shift by +0x50); the mechanism block above is
  read from the 1.7.6 base and is not claimed to be byte-verified in 1.7.5.
- `timeOfDayFraction` oscillates rather than ramping, so it is not a plain
  `fract(worldTime / 900)`: its exact derivation is not settled here.
