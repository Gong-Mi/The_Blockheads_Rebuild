# DynamicWorld object queries & lifecycle cluster — E24

The object query and lifecycle cluster: the full teardown, the remote-removal
receiver, the server repair pass, the occupant/position queries, the
interaction-object probe lattice, the client-disconnect cleanup and the two
free-block factories. **9 bodies, 6108 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_object_life.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/object_life.json`.

| body | imp | words | content |
|---|---|---:|---|
| dealloc | 0x008ad320 | 1116 | full graph teardown |
| interactionObjectAtPos: | 0x008f0550 | 702 | interaction probe lattice |
| clientDisconnected:simulate: | 0x008f85a0 | 651 | departing-client cleanup |
| blockheadOccupiesTileAtPos:ignoreBlockhead: | 0x008f3b80 | 649 | occupant BOOL query |
| doRepairForTileAtPos: | 0x00905dd0 | 644 | server repair pass |
| blockheadAtPos: | 0x008f45a4 | 633 | occupant object query |
| createFreeBlockAtPosition:ofType:… (9 args) | 0x008ddc78 | 630 | master FreeBlock factory |
| remoteRemove:forObjectsOfType:fromClient: | 0x008c420c | 602 | removal receiver |
| createFreeBlockAtPosition:forForegroundContents:… | 0x008de880 | 481 | foreground drop factory |

## Load-bearing findings

- **Teardown** (`dealloc`): three blockhead collections (ffffe4f8/ffffe4f4/
  ffffe4f0) swept with `blockheadWillBeUnloaded:`; a 4-arm SWITCH (table
  **0x00E4AA0C**) over the ffffe54c/ffffe550 map segments with the ffe231f4 hook;
  the collections + ffffe4ec released (ffe231f8); then **`for i in 0..0x41 (65)`**
  clearing the three per-type registries with
  `std::__1::tree<pair<u64,DynamicObject*>>::clear()` (ffffe54c/ffffe550/ffffe554).
- **Removal receiver** (`remoteRemove:…`): the client-side counterpart of E21's
  removal packet — gates (ffe23430 server flag, 0x3c special, 0xe/0x1f skip,
  `objectTypeIsNPC` skip), IDs via `getBytes:length:8`; Blockheads (0x18) match
  netBlockheads by uniqueID + clientID; other types go through the ffffe54c
  segment `__count_unique` + `operator[]` with the ffe23448/ffe2344c gates and
  the (0x14, objectType 0x130) skip.
- **Repair** (`doRepairForTileAtPos:`): server-only (ffffe51c gate); creates via
  the 8-arg ffe23410 call (flag 1); `for i in 0x41` skipping 0x14/0x15, requiring
  `objectTypeHasStaticPosition`; per node the **cylindrical wrap distance**
  ((worldWidthMacro<<5)/… with the 2/5 constants + rsb negation) decides the
  ffe237f0 repair hook; runs over ffffe54c then ffffe550.
- **Occupant queries**: `blockheadOccupiesTileAtPos:ignoreBlockhead:` (BOOL) and
  `blockheadAtPos:` (object) share ONE scan: three collections, ignore-filter,
  pos stret reads with x == arg, y == arg, and **pos.y − 1 == arg**, then the
  ffe236b8 gate.
- **Interaction probe** (`interactionObjectAtPos:`): per-location probes through
  the ffe235f0 resolver with the gate pair ffe23680/ffe23684 (and ffe23678 on the
  last arm), type codes **0x2f / 0x3c / 0x31 / 0x32**, a 2×2 sub-grid, and the
  9-arm SWITCH (table **0x00E4AA90**) skipping already-handled codes.
- **Disconnect** (`clientDisconnected:simulate:`): netBlockheads clientID match →
  9-arm SWITCH (table 0x00E4AA90) over the ffffe54c segments (per node ffe236f0 +
  uniqueID); lazy ffffe5ac dict; ffffe4f0 pass with the ffe232f4/ffe232f0 and
  ffe232fc/ffe232f8 pairs — the same pair family clientConnected sets.
- **FreeBlock factories**: the foreground factory resolves the item via
  `itemTypeFromTileIsForegorund(Tile*, intpair, signed char, World*)` + the
  classifier ladder (Painting/Column/Stairs/Torch/0xb2) + the ffe23410 create +
  the workbench path (`tileIsWorkbench`, local helper 0x8df004) + the 0x30
  tile-byte arm. The 9-arg master factory gates ofType 0xb, splits client/server
  arms around worldTime (**double → float via `vcvt.f32.f64`**), maps the
  creation flag to the sounds 0xfff34094 / 0xfff340a4 (gated by the ffffe5a4
  field < const) / 0xfff340b4, accumulates ffffe5a4, then **registers** the
  object: `map<u64,DynamicObject*>::operator[]` (ffffe54c +0xa8 slice) and
  `worldIndexAtWorldPos` → `map<u64, set<DynamicObject*>>::operator[]`
  (ffffe588) + `__tree insert_unique` — the same registries the E22 unloader
  erases and E23/E22 iterated.

## Boundaries (honest)

- The packed release/create calls (ffe231f8/ffe23410 families), the per-type
  resolver ffe235f0, the C helpers (`itemTypeFromTileIsForegorund`,
  `itemTypeIs*`, `tileIsWorkbench`, `objectTypeHasStaticPosition`) and the
  classifier sounds/strings are pinned by address; their bodies live elsewhere.
- The y − 1 relation in the occupant queries is read from the `sub r1, r1, 1`
  compare; its intent is recorded as observed.
- The wrap-distance micro-form in the repair pass is recorded from the compare
  chain (2/5 constants + rsb negation).
- The 9 packed creation arguments are read from the stack layout.
- `playerInfoForPeerID:`-style side effects are outside this batch.
