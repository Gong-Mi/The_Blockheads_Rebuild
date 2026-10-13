# DynamicWorld save/remote/simulate cluster — E40

The save/remote/simulate cluster: the dynamic-object saver, the remote
creation, the client-owned loader, the simulation finisher/simulator/updater,
the database/portal/conversion-list removals, the chest-inventory removal and
the server-slot setter. **11 bodies, 1297 verified words**, from the pinned
original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_savecluster.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/save_remote_sim.json`.

| body | imp | words | content |
|---|---|---:|---|
| saveDynamicObjects | 0x008b254c | 284 | dynamic-object saver |
| loadClientOwnedDynamicObjectsForClient:physicalBlock: | 0x008bd6bc | 191 | client-owned loader |
| finishSimulating | 0x008cbc8c | 173 | simulation finisher |
| remoteCreate:forObjectsOfType:clientID: | 0x008c3c08 | 151 | remote creation |
| removeSavedInventoryForChest: | 0x008b8dc0 | 129 | chest inventory removal |
| safeRemoveFromDynamicObjectDatabase: | 0x008b8c58 | 90 | guarded db removal |
| simulate: | 0x008c9740 | 88 | 8-family simulator |
| mainThreadRemoveDirFromConversionList: | 0x008ae490 | 74 | conversion-list removal |
| removePortalFromListAtPos: | 0x008b8b80 | 54 | portal-list removal |
| update:accurateDT: | 0x008c9810 | 36 | update wrapper |
| setServer:serverClients: | 0x008ad2b4 | 27 | two-slot setter |

## Load-bearing findings

- **saveDynamicObjects** — the 0x41 gate + the ffffe578 12-byte segments with
  the `(end-start)/8` count + the skip triple (ffffe518 client non-null,
  **objectType 0x2e (46)**, **objectType 0x18 (24)**) — the dynamic-object
  saver's own skip set.
- **remoteCreate** — the **== 0xe (14, FreeBlock) skip** (matching E21's
  type-14 handling) + the **ffffe53c 4-byte slot array** with the ffe2aeb4
  lazy bucket — the remote-creation applier.
- **loadClientOwnedDynamicObjectsForClient:** — the 0x41 gate +
  **`objectTypeCanBeLoadedOnlyWhenClientOwnerOnline(int)`** (C) + the
  ffffe508 tracker with the **0xfff33f84** string.
- **Simulation trio**: `simulate:` divides dt by **8.0** and loops the
  **ffe234e8** call over the 8 families with the paire vldr; `update:accurateDT:`
  passes both floats to the same ffe234e8; `finishSimulating` enumerates
  **ffffe4f8 blockheads** with the 8-slot inner loop and the **ffe234f8**
  per-item call.
- **Removal family**: `removeSavedInventoryForChest:` (ffe23378 + the
  **0xfff33ef4** string — the same string as E31's loadLocalInventoryDataForChest:
  loader, pair confirmed; ffe2332c uniqueID + /32); `safeRemoveFromDynamic
  ObjectDatabase:` (ffffe4e0 + ffffe508 db chain);
  `mainThreadRemoveDirFromConversionList:` (ffffe534 chain);
  `removePortalFromListAtPos:` (ffffe4e8 world chain + worldIndexAtWorldPos +
  ffe2336c — the pair with E35's portalIsBeingRemovedAtPos: query and the
  portalPositions getter).
- **setServer:serverClients:** writes the server to **ffffe51c** and
  serverClients to **ffffe514** — directly confirming the two-slot pair via
  the writes (visual confirmation of E31–E35's reads).

## Boundaries (honest)

- C symbols (`objectTypeCanBeLoadedOnlyWhenClientOwnerOnline`) and cells pinned;
  the 0x2e/0x18/0xe skips and the 8.0 divisor read from immediates; all 16 uncl
  cells resolve as PIC base anchors (clean); the continuation tails are covered
  by the listings.
