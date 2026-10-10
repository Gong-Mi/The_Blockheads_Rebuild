# DynamicWorld world-save cluster — E22

The world-persistence cluster: the world-dict builder with its five-container dirty
sweep, the blockhead save collector, the per-macro-tile dynamic-object saver with
its per-client loaded-set bookkeeping, the object unloader with its registry
erases, the world-position change marker and the client-connect handler.
**6 bodies, 7058 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_world_save.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/world_save.json`.

| body | imp | words | content |
|---|---|---:|---|
| saveGameWithWorldData:signOwnershipData: | 0x008b29bc | 2063 | world dict + five-container dirty sweep |
| saveDynamicObjectsForMacroTile:objectType:xPos:yPos: | 0x008b933c | 1394 | per-type object persistence (5000 FreeBlock cap) |
| saveBlockheads | 0x008b6f0c | 1391 | blockhead save collect / prune |
| worldChangedAtPos:sendReliably: | 0x008df7a4 | 818 | change marker (pos + macro pair queues) |
| clientConnected: | 0x008f7428 | 730 | new-client wiring + dirty-block push |
| removeDynamicObjectsForMacroTile: | 0x008b5e54 | 662 | object unload + registry erases |

## Load-bearing findings

- **World dict + sweep** (`saveGameWithWorldData:signOwnershipData:`): root
  NSMutableDictionary; the signOwnershipData branch stores the flag 8 vs 1; then
  **five 8-byte-stride containers are swept** (ivars ffffe570, ffffe574,
  ffffe578+0x120, ffffe57c, ffffe580): per entry the (x, y) pair drives
  `macroTileAtMacroPostion(int, int, MacroTile*, World*)` and a non-NULL tile runs
  `savePhysicalBlockForMacroTile:tile sendReliably:? dontSend:?
  onlySaveIfClientsNeedIt:?` (1-vs-0 flag families per container); success erases
  the entry through the libc++ erase path. This is the save-side counterpart of
  E21's flush queues.
- **Dynamic-object persistence** (`saveDynamicObjectsForMacroTile:...`): gates
  (type 0xf logs, 0x15 returns, client+non-0x2e returns, [tile+2] byte), then
  `macroIndexAtMacroPosition` + `objectTypeCanBeLoadedOnlyWhenClientOwnerOnline`
  with the per-client `map<unsigned, set<unsigned>*>::at(objectType)` loaded-macro
  bookkeeping (`__count_unique` / `__erase_unique(macroIndex)`); the tile's
  [tile+0xc] object list is walked per requested type with a **5000 cap for
  FreeBlocks (0xe)**; data serializes through the shared helper `0x8b84c8` and is
  keyed into the dynamic-object database (ivar ffffe508); failure paths log
  (0xfff33f44/0xfff33ea4/0xfff33f54).
- **Blockhead save** (`saveBlockheads`): collect (blockheads ivar ffffe4f8,
  client-gated per-item calls) -> dict -> `bl 0x8b84c8` -> client send path or the
  NSKeyedArchiver write; then prune passes over ffffe4f0 / ffffe590 with
  `removeObject:` bookkeeping.
- **Unload** (`removeDynamicObjectsForMacroTile:`): Blockhead (0x18) removal from
  netBlockheads + `blockheadWillBeUnloaded:`; per-object erases from **three ID
  registries** (trees at ffffe54c / ffffe550, hash at ffffe584); FreeBlock 0xe
  keyed by `worldIndexAtWorldPos` into the ffffe588 set-map;
  `objectTypeHasStaticPosition` (ffffe554 positional map) and
  `objectTypeRequiresPartialUpdate` (ffffe58c type segments); finally
  `std::remove` + `vector::erase` from the tile list.
- **Change marker** (`worldChangedAtPos:sendReliably:`): exact-position dedup
  vector (ffffe5b8) + macro pair via /32 and `makeIntpair`; the macro pair lands in
  the ffffe570 / ffffe574 queues around the sendReliably gate — the producers for
  E21's flush passes.
- **Client connect** (`clientConnected:`): blockhead match by
  `[item clientID]`, stale-prune pass, then the world's
  `unordered_set<PhysicalBlock*>` is copied and every block with the dirty byte
  [block+0xc] set is pushed to the new client.

## Boundaries (honest)

- The key/NSLog strings (0xfff33d64/0xd54/0xd44/0xd84, 0xfff33f04/0xf44/0xea4/
  0xf54, 0xfff33ef4/0xf84/0xf74) are pinned by address, not decoded.
- The per-container send flags and the FreeBlock cap (0x1388) are read from
  immediates; the map member slices are observed arithmetic.
- The prune/callback selector names behind cells (ffe23354/60/5c/200/23300/233d8)
  are pinned by cell; their bodies live elsewhere.
- The dual dedup micro-order around the sendReliably gate (570 vs 574) is recorded
  as observed; the queue split matches E21's two flush passes.
- `bl 0x8b84c8` (shared serializer) and the objectType capability C functions are
  outside these bodies.
