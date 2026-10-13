# Tree base class — E89 (plants line)

The Tree engine: the base ctor with the gene clamps, the static-tree alloc,
the owned-tiles family, the f64 dead-tile reaper and the fallen-fruit
spawner.
**28 bodies, 4378 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_treebase.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/tree_base.json`.

## Load-bearing findings

- **The gene clamps**: the base ctor runs **`clampi(1, 0xff)` x2** on the
  maxHeight/growthRate gene halfwords (strh into the ffffc8f4/c8f0/c8e0/
  c8e4/c8ec cells) - the same 0..0xff gene domain as the Plant base (E88).
- **The second vigor symbol**: the base ctor calls
  **`growthVigorForTreeTypeAtPos`** AND **`baseGrowthRateForTreeType...`** -
  the vigor family has a base-rate sibling.
- **The static tree**: `initStaticTree...` runs **`__wrap_calloc`** - the
  static tree allocates its own backing block at placement.
- **The owned-tiles family**: `killAllOwnedTiles` (154w),
  `killAllOwnedTilesAboveY:` (211w), `removeAllOwnedTiles:` (225w) and
  `updateAllOwnedTilesToNewIDSize` (129w) all walk via
  `tileAtWorldPositionLoaded` + the shared local helper **0x4c0bc4** (the
  tree-frame helper reused across the class).
- **The f64 reaper**: `checkIfDeadTilesNeedRemoved` computes an
  **f64 age fraction** (`vmov.f64 d0, 1` + pool + `movw ip, 0x3c` (60) +
  `vdiv/vsub/vmul/vadd/vcvt.s32.f64`) and tests **`tileIsTreeTrunk`** - the
  dead-tile removal gate.
- **The fallen fruits**: `addFallenFruits` seasons/randomizes each drop
  (`seasonForWorldX` + `__modsi3` + `tileIsSolid`).
- **The trunk math**: `update:` carries **`__aeabi_idiv` x8** (the intensive
  fraction ratios) + the 0x1869f (99999) sentinel pool word; the soil set is
  **{0x1b, 0x1c, 0x30, 0x31, 0x32}** (same as the Plant base);
  `isStaticTree` = 0; `occupiesNormalContents` = 1.

## Boundaries (honest)

- uncl 40/41: the 0x1869f pool word is the sentinel (data).
- The giants are census-characterized (call tables) + the read windows; the
  helper 0x4c0bc4 body stays opaque; the base hooks (updateGrowth: 20w,
  makeTileDead: 6w) are near-empty by design (subclass overrides).
