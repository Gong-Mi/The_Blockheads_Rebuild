# DynamicWorld door/boat/train accessor family C — E38

The third typed-accessor batch: the window triplet, the door family (creation
with the tile-state write, the y−1 resolver, the usage/open/set predicates and
the other-block probe), the boat placer/lookup/tap check and the train-car
lookup/tap check. **14 bodies, 1307 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_acc3.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/accessor_c.json`.

| body | imp | words | content |
|---|---|---:|---|
| addDoorAtPos:ofType:saveDict:placedByClient: | 0x008ed56c | 149 | door creation + tile write |
| checkForTrainCarUnderTap: | 0x008eef50 | 143 | train-car tap check |
| trainCarWithID: | 0x008ef18c | 143 | train-car lookup |
| doorCanBeUsedByPathUser:atPos: | 0x008ed950 | 130 | door usage predicate |
| checkForBoatUnderTap: | 0x008ee3e8 | 127 | boat tap check |
| placeBoatInWaterAtPos:saveDict:placedByClient: | 0x008ee1f0 | 126 | boat placer |
| doorAtPos: | 0x008ed7c0 | 100 | door resolver |
| posOfDoorsOtherBlockAtPos: | 0x008ef488 | 100 | other-door-block probe |
| boatWithID: | 0x008ee5e4 | 71 | boat lookup |
| doorIsOpenAtPos: | 0x008edb58 | 56 | door open predicate |
| setDoorAtPos:toOpen:direction: | 0x008ef3c8 | 48 | door state setter |
| removeWindowAtPos: | 0x008ed4b8 | 45 | window removal |
| addWindowAtPos:ofType:saveDict:placedByClient: | 0x008ed414 | 41 | window add |
| windowAtPos: | 0x008ed3a4 | 28 | window accessor |

## Load-bearing findings

- **Type codes pinned**: window = **0x1f (31)**, door = **0x14 (20)**; window
  triplet = the E36/E37 family shape (ffe235f0 / ffe23624 / ffe23600+**ffe2364c**
  remove).
- **Door family**: `addDoorAtPos:` wraps the door creation in the tile-state
  write — `tileAtWorldPositionLoaded` + byte compares against **0x34 ('4') and
  0xa4** + the **0x46 ('F') marker** written to [tile+0xc]; `doorAtPos:` probes
  the position then **y−1** via `makeIntpair`; the state family is
  ffe23650 (fetch) / ffe23658 (open check) / ffe2366c (set fetch) with the
  ffe23654 usage fetch and ffe232b0 predicate; `posOfDoorsOtherBlockAtPos:`
  probes the four directions (y+1, x+1, x−1, y−1) and returns −1 on no hit.
- **Boat family**: `placeBoatInWaterAtPos:` uses class **ffe2af8c** + the
  ffffe4e4/ffffe504 world chain + **ffe23660**; `boatWithID:` is the
  two-registry lookup on the **ffffe54c/ffffe550 +0x180 boat slices** (the same
  slice `checkForBoatUnderTap:` walks with the **ffe23664** hit test) — the
  +0x180 boat-slice identity is pinned by shared use across the pair.
- **Train-car family**: both bodies take the `arg >= 4` gate and dispatch via
  the **0x00E4AA0C table** (4 arms) into the ffffe54c 12-byte family segments
  (`trainCarWithID:` with `__count_unique`/`operator[]`, `checkForTrainCarUnderTap:`
  tree-walking with ffe23664).

## Boundaries (honest)

- All cells pinned by cell address; type codes and tile markers read from
  immediates; the ±1 door probes and tile-byte compares read from the listing;
  32 of 34 uncl cells resolve as PIC base anchors, the last 2 are the
  0xE4AA0C table bases; the miss-path tails continue in the listings.
