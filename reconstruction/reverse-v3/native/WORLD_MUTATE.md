# DynamicWorld world-mutation & client-request cluster — E26

The mutation and client-request cluster: the worldContentsChanged queue producer,
the interaction-object placement, the standard-object/door removals with lighting
recalculation, the client free-block materialization, the client-departure
removal sweep and the train-car placer. **7 bodies, 2673 verified words**, from
the pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_mutate.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/world_mutate.json`.

| body | imp | words | content |
|---|---|---:|---|
| placeTrainCarAtPos:ofType:saveDict:placedByClient: | 0x008ee700 | 532 | train-car placer |
| removeStandardObject: | 0x008e88fc | 443 | standard-object removal |
| worldContentsChangedAtPos: | 0x008e046c | 409 | queue producer |
| removeDoorAtPos: | 0x008edc38 | 366 | door removal + relight |
| createClientFreeblocksWithData: | 0x008d0c90 | 326 | client free-block materialization |
| removeDynamicObjectsBelongingToClient: | 0x00904e18 | 316 | departure removal sweep |
| interactionObjectPlacedAtPosition:… | 0x008e7a60 | 281 | interaction placement |

## Load-bearing findings

- **Queue producer** (`worldContentsChangedAtPos:`): its own exact-position
  vector ffffe5c4 dedup + append, then /32 (`__aeabi_idiv` 0x20) + `makeIntpair`
  into the worldChangedMacroPositions queue (ffffe570) — the third producer of
  the E21/E22/E23 queue family.
- **Interaction placement**: the local helper 0x8e7ec4 resolves the type;
  `classForInteractionObjectType(unsigned short)` resolves the class; the packed
  6-arg init runs; then **registration into the ffffe550 (uniqueID) and ffffe554
  (worldIndexAtWorldPos) maps** with the ffe232a0 flag-1 closing call; type 8 and
  type 6 specials.
- **Standard removal**: 0xe/0x18/interaction objects are refused with an NSLog
  (0xfff34154); type 0x14 has its own path; the main path clears the tile type
  byte ([tile+3]=0) and the ffe235f8/ffe235fc-gated second pass clears
  [tile+0xb]=0, each with the ffe235e8 flag-1 notify.
- **Door removal**: resolver hit on 0x14; door halves 0x34/0xa4 clear
  [tile+0xc]=0 on (x,y+1) and (x,y-1) and call
  `recalculateDrawBlockLightingForTile(int, int, MacroTile*, World*)`; the retry
  path has the **0x130-objectType special** ([tile+3]=0 else [tile+0xc]=0), a
  second relight and the ffe2365c tail.
- **Client free blocks**: the shared parser 0x8b1db0 turns the blob into the
  object list; per entry the creation feeds the same **registration family**
  (ffffe54c +0xa8 uniqueID map + ffffe588 worldIndex position map) as E24's
  FreeBlock factory.
- **Departure sweep**: `for i in 0x41` with the
  `objectTypeCanBeLoadedOnlyWhenClientOwnerOnline` gate; ffffe54c and ffffe550
  segments are swept per node with the ffe233a0/ffe233a4 pair and the
  **ffe2349c flag-1 removal mark** (the needsRemoved family).
- **Train-car placer**: rail gates (tile byte [tile+0xb] == 0x62 on (x,y) and
  (x,y-1)); the four car classes (0xcc/0xcd/0xce/0xd0; class cells
  ffe2af90/94/00/98) each with the packed 5-arg creation (dispatch ffe23660);
  the ±2 search loop with `tileIsSolid` and the Vector2(x+5, y+1) candidate; the
  created car registers into the ffffe550 map.

## Boundaries (honest)

- The local helper 0x8e7ec4, `classForInteractionObjectType`, `tileIsSolid`,
  `recalculateDrawBlockLightingForTile` and the shared parser 0x8b1db0 are
  outside this batch.
- Tile byte offsets (+3, +0xb, +0xc) and the rail marker 0x62 / door codes
  0x34/0xa4 / the 0x130 special are read from the immediates.
- The car classes' identities behind the four class cells are outside this batch.
- All 27 uncl cells resolve as PIC base anchors (no tables in this batch).
