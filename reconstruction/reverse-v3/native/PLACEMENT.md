# DynamicWorld placement-actions cluster — E30

The placement-actions cluster: the seed sower dispatch, the workbench placer, the
dynamic-world change recorder, the background free-block factory, the
rail/standard/painting adders and the pole-taken recorder.
**8 bodies, 1808 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_place.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/placement.json`.

| body | imp | words | content |
|---|---|---:|---|
| workbenchPlacedAtPosition:… | 0x008e7608 | 278 | workbench placer |
| dynamicWorldChangedAtPos:objectType: | 0x008e1390 | 263 | change recorder |
| createBackgroundContentFreeBlockAtPosition:… | 0x008df3c4 | 248 | background free-block factory |
| addRailAtPos:ofType:ownedByStation: | 0x008ecea4 | 236 | rail adder |
| addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient: | 0x008eb0c0 | 234 | standard-object adder |
| addPaintingAtPos:ofType:saveDict:placedByClient:clientName: | 0x008eac68 | 233 | painting adder |
| poleItemTaken: | 0x0090365c | 227 | pole-taken recorder |
| sowTreeOrPlantAtPosition:itemType:maxHeight:growthRate: | 0x008e49c8 | 89 | seed sower dispatch |

## Load-bearing findings

- **Seed dispatch**: `treeTypeForSeedItemType(ItemType)` (C) non-zero -> the
  ffe23414 tree-sow call; zero -> `plantTypeForSeedItemType(ItemType)` (C) ->
  the ffe233f8 plant-sow call; the float 0x47c34f80 (= 100000.0f) rides the
  packed frame.
- **Workbench placer**: creation (class ffe2af04, dispatch ffe235c8) + the
  E26-family registration (ffffe550 uniqueID map + ffffe554 worldIndex map +
  ffe232a0 flag-1) and the **ffffe558 flag byte set to 1** when the ffe2348c
  check returns 1 — the per-world workbench-present flag.
- **Change recorder**: skips objectType 0x16/0x1d; /32 + `makeIntpair` into the
  **ffffe578 member's 12-byte 65-segment structure** (the container E21's
  saveGame sweep and E29's destructor address).
- **Background free block**: tile byte +0xc markers 0x46 ('F')/0x4b ('K') arm 1
  (ffe23578) and 0x45 ('E') arm 2 (ffe2357c); the byte [r1+6] **> 0xaa** sets
  the flag passed to the 8-arg ffe23410 create — the ore-ish threshold.
- **Adder family** (`addRail`/`addStandardObject`/`addPainting`): existence via
  `worldIndexAtWorldPos` + the ffffe554 member's per-family slice (+0x1e0 rail,
  plain 12-byte segment standard, +0x270 painting) `__count_unique` + the ffe234ac
  gate; creation with per-family class cells (ffe2af88 rail, the
  **`classForDynamicObjectType(int)`** C call for standard, ffe2af84 painting) and
  dispatches (ffe23644/ffe23620/ffe2361c); registration via the ffffe550 map.
- **Pole taken**: client gate + the two 0x40-byte world-struct checks
  (byte[0], byte[0x4c]==1); the **ffffe564 registry dict** lazily created and
  updated with the `stringWithFormat:` key from **0xfff34284** — the same format
  string E23's pole restorer uses.

## Boundaries (honest)

- The `treeTypeForSeedItemType`/`plantTypeForSeedItemType`/
  `classForDynamicObjectType` C symbols and the packet/list call bodies are
  outside the batch; the float 0x47c34f80, tile markers and the 0xaa threshold
  are read from immediates; the ffffe554 slice offsets are observed member
  arithmetic; all 30 uncl cells resolve as PIC base anchors (clean).
