# Tree -[growInTimeSinceSaved:] — executed differential, STAGE 1 (batch b4g)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x004c2568
boundary: 0x004c2df0 (next method IMP — Tree loadSaveDictValues:, b3a/b4d/b4e)
words:    546 (exact coverage asserted by the listing emitter)
types:    v16@0:4d8   (one double argument: timeSinceSaved)
```

The b3n decode of this hook (the tree GROWTH STATE MACHINE) is now
**executed** — stage 1, the nil-tile path:
`tools/test_tree_grow_arm.py` runs the original ARM body under Unicorn
with synthetic world/dynamicWorld objects, the tile lookup `bl 0xa12f24`
hooked to return nil, and compares the 120-byte instance image and the
(code, arg) message trace against the recovered C++
`reconstruction/recovered/tree_grow_in_time.{h,cpp}` at -O0 and -O2.
`tools/test_tree_grow_arm_evidence.py` guards it in both host and CI
modes; CTest `recovered_tree_grow_in_time` exercises the contract without
the ELF.

## Stage boundary

The tile-record/PRNG block (0x4c27a8–0x4c2858: tile byte/+0xe/+0x10/+0x12
reads, the 0x1c3728 chain, chance ≠ 0.5) is a **stage-2 slice**. Stage 1
hooks the lookup at 0xa12f24's first instruction and returns nil, which is
the fixture boundary documented in b4e: the growth math still runs with
chance = 0.5f. The hook asserts the lookup asks for
`(pos.x, pos.y + current height)` — proving the body reads those ivars.

## What execution settled that static reading could not

* **The partial-growth formula is `gc + (1-gc)*eg`, not `gc+(1-eg)*eg`.**
  The static read of the vsub operand order was wrong; the executed
  differential caught a 0.5-ULP-scale disagreement in growthCounter
  (0x3e70a3d7 vs 0x3e77a3d7) and forced the re-read: s2 starts at 1.0f,
  `vsub s2,s2,s10` subtracts **growthCounter** (both s6 and s10 load the
  same ivar), then `vmul` by eOverG and `vadd` into gc. This is the
  second time this line's execution corrected a static formula claim
  (after b4a's [1,21] seed range).
* **timeToGrow is a loop-carried spill, not 1−gc.** First iteration uses
  1.0f−growthCounter; the increment path stores 1.0f into the body slot
  (`vstr s0,[sp,#0x44]` before `updateGrowth:`, reloaded into fp-0x3c
  after the call) and the loop re-entry at 0x4c26bc skips the
  recompute. A C++ contract that recomputes 1−gc per iteration diverges
  on the second increment (caught by the double_increment case).
* **The denom constant is 0.005, not 1/168.** 0x004c2b98 =
  0x3f747ae147ae147b = the double nearest 0.005 (1/168 rounds
  differently). Bit-exactness forced the check.
* **maxAge is checked once per call**, not per loop iteration; the loop
  re-entry jumps after the compare.
* NaN takes every `bpl`/`movgt` branch as the unordered case: NaN
  worldTime → old path (compost/death), NaN growthTime → partial.

Confirmed as decoded: isStaticTree gate (sxtb), dead checks (ldrsb),
age+elapsed ≥ maxAge → compost (`age = maxAge`) or death
(`[dynamicWorld sowTreeNearParent:self adult:1
adultMaxAge:(float)(elapsed − (double)(maxAge − age))]`, `dead = 1`,
`timeDied = t + (double)maxAge − (double)age`, `[self
removeAllOwnedTiles:0]`), increment path (`age += growthTime` f32,
`growthCounter = 0`, `maxHeightReached = max(height, mhr)` AFTER the
incrementHeight reload, `[self updateGrowth:1]`), tail
`updateGrowth:0` only when nothing grew and the tree lives.

## Case table (10 cases, all matched bit-exactly)

`static`, `dead_entry`, `partial` (growthCounter advances, tail call),
`double_increment` (2 increments then partial; spilled timeToGrow
exercised), `scripted_height_exit` (incrementHeight bumps height to
maxHeight; mhr = max(10,6) after reload), `compost` (age := maxAge),
`death` (timeDied = 115.0, adultMaxAge = 85.0f bits, dead = 1),
`nan_worldtime` (unordered → old path), `negative_elapsed`
(grow-block skipped), `boundary` (age+elapsed == maxAge → old path).

## Boundary

Stage-1 executed evidence only: the tile lookup/PRNG block is a stage-2
slice; incrementHeight mutations are scripted; not Foundation, not the
original-app runtime, not device gameplay. Next natural slices: stage 2
of this method (the tile-record chance path incl. the 0x1c3728 chain),
the Chest per-slot loop, or the b3e write-side counterpart.
