# Plant base class — E88 (plants line)

The Plant engine: the ctor with the **+0xb occupancy slot**, the tileIsPlant
placement check, the randomized removal, the soil set with dead-tree
markers, the net/save pair and the flowering flag.
**29 bodies, 2168 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_plantbase.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/plant_base.json`.

## Load-bearing findings

- **The +0xb occupancy slot**: the plant ctor tests the tile byte **+0xb**
  (@0x95516c) and runs **`tileIsPlant(Tile*)`** (@0x955184); the occupancy
  write **`strb r2=0 [r1, 0xb]`** (@0x95520c) and `clearAllTileContents`'s
  `strb r1=0 [r0, 0xb]` (@0x957878) share the slot - the +0xb byte is the
  plant-occupancy marker (compare the trees' stage byte at +3).
- **The randomized removal**: `removePlantWithoutCreatingFreeblocks` runs
  objc x3 + the local helper 0x95767c x2 + **`clampi(int,int,int)` x2** +
  **`lrand48` x1** - the removal outcome is randomized (lrand48) and
  clamped.
- **The soil set**: `isRequiredSoilType` accepts **{0x1b, 0x1c, 0x30, 0x31,
  0x32}** - the tree soil codes PLUS the dead-tree markers 0x1b/0x1c
  (plants grow over dead trees).
- **The substrate test**: `worldChanged:` uses **`tileIsAirWaterOrSnow`** -
  the plant re-checks its support.
- **The flowering flag**: `setFlowering:`/`isFlowering` ride the
  **ffffcad4** cell byte.
- **The gene clamps**: maxAge/growthRate gene variations clamp to **0xff**
  via clampi.
- The net/save pair: the record builders (stret + memset) + forwarders; the
  harvest hook forwards via ffe24024.

## Boundaries (honest)

- uncl 35/35 resolve as PIC base anchors (clean).
- The helper 0x95767c and the ffe23fxx/ffe24xxx chains stay opaque; the
  non-constant accessors' per-subclass values read from the subclasses'
  batches.
