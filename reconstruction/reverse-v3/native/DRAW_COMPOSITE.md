# DynamicWorld giant draw composite — E44

The world-line's top-level draw composite: `draw:projectionMatrix:modelViewMatrix:
cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:`.
**1 body, 7203 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_drawgiant.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/draw_composite.json`.

| body | imp | end | words | mode |
|---|---|---|---|---:|---|
| draw:…:hideUIType: | 0x008d4ff0 | 0x008dc07c | 7203 | structural pass |

## Structure (anchored to the listing)

- **Frame**: 0x470 + 0x2000 + 16-alignment ≈ **9.3 KB stack work area**; sl
  registers hold the area bases (sp+0x800/sp+0x1800/sp+0x2000 partitions).
- **hideUIType gate** @0x8d5258: `== 3` skips directly to the slice phases
  (0x8d6264).
- **Three collection phases** with the **ffe2353c dispatch** (3 sites,
  first @0x8d54d0):
  1. **ffffe4f4 netBlockheads** @0x8d52b0;
  2. **ffffe4f0 local-client family** @0x8d57f8;
  3. **ffffe4f8 blockheads** @0x8d5d40.
  Each marshals the camera bundle per element and exits at its tail
  (0x8d57cc / 0x8d5d14 / 0x8d625c).
- **Eighteen slice phases** from 0x8d6264: the **ffffe54c member** is walked
  slice by slice (18 member loads, first cell 0x8d71e8; `std::__1::__tree_next`
  iteration, e.g. @0x8d7c44) with the **ffe23538 dispatch** (18 sites, first
  @0x8d64e4) — the same dispatch E25/E41 use, now instantiated per family.
  Slice offsets observed in spot checks include +0x88/+0xa8/+0xcc/+0x270 (the
  free-block slice +0xa8 and painting/client +0x270 among them).
- **Tail tables**: the **0x00E4AA3C** and **0x00E4AA0C** jump tables are read
  at the epilogue cells (@0x8dc05c / 0x8dc06c) — the 10-arm plant table and
  the 4-arm family table select the final arms.
- **Enumerator scaffold**: ffe231ec at 6 sites (first @0x8d52a8) with the
  containment/mutation guards.
- **Composition**: the composite is the top of the draw call chain whose parts
  were recovered in E25 (drawInFrontOfBlocksObjects), E41
  (drawOpaqueObjects/drawFreeBlocks) and E29/E30's reload family — the
  ffe23538/ffe2353c dispatches and the ffffe54c slice family recur across all
  of them.

## Boundary (honest)

This batch is a **structural pass**: the frame layout, phase boundaries, all
dispatch sites (ffe2353c ×3, ffe23538 ×18), the member slices (ffffe54c), the
three collections (ffffe4f4/f0/f8), the enumerator scaffold and the tail
tables are anchored to listing cells; a word-by-word transcription of all 7203
instructions is deliberately deferred and NOT claimed. uncl 40/42 resolve as
PIC base anchors + 2 table bases (0xE4AA3C, 0xE4AA0C).

With this batch the DynamicWorld class reaches **210/210 rows touched**
(209 full-recovery bodies + this structural pass) and the World line
(WTL 52/52 + DynamicWorld 210/210) nominally closes at 262/262 = 100%,
with this composite and .cxx_construct flagged as the line's boundary
artifacts.
