# DynamicWorld dynamic-object load chain — E19

The storage front's third line, after the WorldTileLoader block bodies (E14-E18):
**3 bodies, 11207 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_dyn_load.py` (hash-gated; every instruction word
re-verified from the pinned ELF; `--check` reproduces the artifact byte for byte).
Artifact: `reconstruction/reverse-v3/native/dyn_load.json`.

| body | imp | words | content |
|---|---|---:|---|
| loadDynamicObjectsForMacroTile:includeSurfaceBlocks: | 0x008bd9b8 | 6196 | the per-macro-tile object restore: version ladder, tree-promise pool, marker scan, surface pass |
| loadDynamicObjects:repositionBlockheadLoadFailures: | 0x008aedac | 3073 | the world-level restore: three-source fetch, one-to-two conversion thread, portal set, Blockhead construction |
| loadDynamicObjectsOfType:fromData:physicalBlock:loadedPortal:clientOwnedID: | 0x008baa54 | 1938 | the per-type constructor worker: reentrancy guard, dedup gates, class dispatch, container registration |

## Load-bearing findings

**Per-macro-tile restore** (`loadDynamicObjectsForMacroTile:`, 6196w). The macroTile
pointer's `+4` holds the PhysicalBlock; a NULL block logs and returns, and a client
world short-circuits to the surface pass. The **version ladder** reads the block's
`+0xd` byte: `< 2` runs the one-to-two file-conversion pass (versionOneToTwoConversionList
enumeration + `__wrap_rename` under worldSaveDirectory), `2..5` and `6` run marker-7
NPC fixups, `7` runs the npc-8 tree-top glow repair, and `>= 8` calls
**`[world updatePhysicalBlockToLatestVersion:]` then stamps `+0xd = 8`** — the direct
caller of the E15 migration body. The 32-column outer loop special-cases the quarter
columns (W*8 / W*16 / W*24) with lakeHeight-derived tree promises 0x8c/0x8e; other
columns walk the **64-byte tree-promise pool** at block+8 (byte3 = promise type via
`treeTypeForTreePromise`, consumed then planted via `loadTreeAtPosition:...` with a
noise-derived geometry and a f64 growth argument). The **marker scan** reads
npcPositions/plantPositions: marker 6 builds the treasure/troll record (DrawBlock
bit-packing, LOD ids 4/5/7), marker 8 repairs tree-top glow blocks, plant 9/0xa and
the generic arm dispatch `loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:`,
and npc markers reload via `loadNPCAtPosition:...`. The **surface pass** (server, when
includeSurfaceBlocks) walks the block double-nested: water below `byte4 0xff` and
water-over-water cases call `loadSnowSurfaceBlockAtPos:loadSnow:`, air-or-snow over
solid/water calls `loadSurfaceBlockAtPos:` (through the 4-argument
`tileAtWorldPosition(x, y, macroTile, world)` variant), and `byte0 == 4` tiles get the
surface reload.

**World-level restore** (`loadDynamicObjects:`, 3073w, returns a BOOL). The payload is
fetched from three sources in order — worldDatabase `dataForKey:`, the
fileExistsAtPath:/defaultManager/`dataWithContentsOfFile:` path, and
`dictionaryWithContentsOfFile:` — and parsed through the local `0x008b1db0` helper.
Scalars restored: `activeBlockheadIndex` (8-byte `{value, 0}` write),
`workbenchHasBeenCrafted`, the poleItemTakenTimes family. `count < 2` runs the
one-to-two conversion: the versionOneToTwoConversionList enumeration with the
`0x7fffffff` sentinel pair, and when entries remain it spawns
**`detachNewThreadSelector:@selector(conversionThread:)`** on self — the old-save
conversion runs on a background thread. `count >= 2` decodes an **NSKeyedUnarchiver**
set into `portalPositions` via `addIndexes:`. The client gate skips the server-side
migration; the server path re-resolves the file, renames it (`__wrap_rename`),
**`gzipInflate`s** the local-player payload (gzip, matching the E14 writer) and
metadata. The main loop enumerates object IDs (unsignedLongValue pairs), resolves each
payload (database-or-file), finds/refuses the blockhead
(`blockheadWithIDIncludingNet:` + the `blockheads removeObject:` /
`blockheadWillBeUnloaded:` path), parses the payload with
`NSPropertyListSerialization`, and constructs
**`[[Blockhead alloc] initWithWorld:dynamicWorld:saveDict:savedInventorySlots:cache:repositionOnLoadFailure:clientSaveDir:clientLocallySavedDict:]`**
(arg2 = repositionBlockheadLoadFailures). Post passes: per-blockhead
`fullyLoadIfNeededAroundPos:clientLightBlockIndex:-1:forBlockhead:`,
`activeBlockheadIndex` clamp, `hasLoadedBlockheads = 1`, the 65-entry
12-byte-stride dynamic-object map scan (`std::__tree_next`), and the final
customRules[0]/[+0x32]==4 `[bh die]` sweep.

**Per-type constructor worker** (`loadDynamicObjectsOfType:`, 1938w). Type gate
1..0x40 (excluding 0 and 0x15). **Reentrancy guard**: for server-side loads the block's
macro index is looked up in the `currentlyLoadingMacroBlocks` hash table — a hit logs
and returns — then inserted (in-flight mark). The payload dict is enumerated; type 0xf
keys map through `dynamicObjectTypeForInteractionObjectType`; **dedup gates** check the
two `std::map<u64, DynamicObject*>` maps and the `currentlyAddingObjectIDs` hash set (a
hit in the set logs and re-notifies via `dynamicWorldChangedAtPos:objectType:`).
Construction routes: the key-value==1 **Workbench** route
(`initWithWorld:dynamicWorld:saveDict:cache:`), `classForInteractionObjectType`, or
`classForDynamicObjectType`; post-fixups include the `[obj level]` jump table writing
tile byte0 ids 0x19/0x21-0x25, `addIndex:worldIndexAtWorldPos(...)`, and the
Workbench-route level==2 -> `setLevelSilently:3` repair for old blocks. Registration
stores the object into the type-strided map, runs `blockheadsLoaded` when the world
finished loading, inserts world indices for static-position objects into the
`std::map<u64, set<DynamicObject*>>`, records `objectType == 0xe` positions in the
tamed-animal index family, and for client-owned objects records the macro index under
the client id. Skips erase the ID from `currentlyAddingObjectIDs`; the exit (server)
erases the macro index from `currentlyLoadingMacroBlocks`.

## Boundaries (honest)

- The payload parser at `0x008b1db0` (immediately after the world-level body) is
  labeled from call usage; its accepted encodings are inferred from the callers' data
  sources (plist / keyed archive / gzip payload).
- The two 12-byte-stride map slots (`ffe54c`/`ffe550`) carry the names
  dynamicObjectsToAdd/dynamicObjects across the two spec tables; the offsets are the
  stable identity (the third table prints them swapped).
- The DrawBlock packing fields, the `[obj level]` tile ids 0x19/0x21-0x25, the marker
  taxonomy (6/8/9/0xa) and the customRules byte names are read from the gates and
  writes; the consumers live outside this batch.
- The std::map/set/hash layouts are the demangled route names; the container types are
  not re-derived here.
