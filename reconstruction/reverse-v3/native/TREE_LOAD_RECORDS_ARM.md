# Tree fruit records — executed slice (batch b4e, stage 2)

Scope: the per-fruit record writer inside `-[Tree loadSaveDictValues:]`
(`0x004c2df0`, 748 words) of `libApplication.so`
(sha256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Evidence level: **executed** (the original ARM body runs under Unicorn and its
stores are read back), not device-accepted, not Foundation.

## Executed facts

```
treeFruit                objectForKey → array; fruitCount@128 reset to 0
NSFastEnumeration        real state buffer cleared through the actual
                         0x1c2924 memset veneer; items read from the
                         protocol's itemsPtr
per fruit dictionary     pos.x word                        (+0)
                         pos.y word                        (+4)
                         hasCreatedFreeBlockThisSeason byte (+8)
                         written with stride 0xc into the buffer pointed at by
                         treeFruits@124; fruitCount@128 is the running index
                         and advances only for WRITTEN records
gate (per fruit)         the world accessor `bl 0x00a12f24` is called, and the
                         record is written only when
                         [tile+0x28] == self[uniqueID@40] &&
                         [tile+0x2c] == self[uniqueID@44] &&
                         [self tileIsKindOfSelf:tile]
world accessor queries   `worldWidthMacro` (answered 32 → 32 macro tiles =
                         1024 tiles wide) and `macroTiles`
```

Stage 1 (already landed in b4d) covered the scalar chains, the `treeFruit`
reset/enumeration entry and the `isStaticTree` gate; `height@60`/`age@96` are
read before that gate.

## What this batch proves

* the record loop executes against the original instructions, including the
  real veneers and the world accessor (only Foundation/UIKit-level messages and
  the world's own storage are stubbed);
* the 12-byte record geometry and the `fruitCount@128` running index match the
  static decode byte for byte, across 6 fruit configurations (0/1/2/3/4 fruits,
  duplicates, world-edge coordinates) — ARM vs C++ at `-O0` and `-O2`;
* the two skip paths: identity mismatch (negative control, fitting disabled)
  and a nil lookup, both leave `fruitCount` untouched.

## Fixture boundary (stated, not hidden)

* the harness is a synthetic world/save-dictionary/fruit-array fixture — not
  Foundation, not the original-app runtime, not device gameplay;
* at the identity compare site (`0x4c3218`) the harness copies the looked-up
  tile's `+0x28`/`+0x2c` into the tree's `uniqueID@40/+44`, i.e. it puts the
  fixture into the state the original gates on; disabling exactly that fitting
  is the negative control;
* `macroTiles` points at a synthetic pointer table, so the accessor returns a
  tile for the coordinate classes exercised by the cases. Coordinates where the
  fixture lookup yields nil (`(0,0)`, `(32,32)`, `(64,64)`, `(1024,1024)`) are
  recorded as a **fixture boundary**, not as a decoded game rule.

## Artifacts

* `reconstruction/recovered/tree_load_records.{h,cpp}` — recovered contract.
* `tools/test_tree_load_records.cpp` — CTest contract (`recovered_tree_load_records`).
* `tools/tree_load_records_arm_bridge.cpp` — ARM-vs-C++ bridge.
* `tools/test_tree_loadsave_arm_stage2.py` — Unicorn differential (8 cases,
  `--sweep` prints the accessor domain).
* `tools/test_tree_load_records_arm_evidence.py` — guard (static in CI, host
  mode when the pinned ELF is present).
