# DynamicWorld load-chain leaves — E20

The ten constructor workers the E19 load chain calls into: the per-type object
factories, the cave-treasure generator, the blockhead spawner and the background
conversion thread. **10 bodies, 5479 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_dyn_leaf.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/dyn_leaf.json`.

| body | imp | words | content |
|---|---|---:|---|
| loadTreeAtPosition:type:maxHeight:growthRate:adultTree:adultMaxAge: | 0x008e4e44 | 1283 | 11 tree classes; occupancy scan; GemTree variant |
| loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult: | 0x008e69e8 | 776 | 10 plant classes |
| loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient: | 0x008e66d4 | 197 | NPC type map, 512 cap, sparsity gate |
| loadSurfaceBlockAtPos: | 0x008e6594 | 29 | forwarder to type 0x16 |
| loadSnowSurfaceBlockAtPos:loadSnow: | 0x008e6608 | 51 | forwarder to type 0x1d + updateInTimeSinceSaved |
| loadGlowBlockIfNeededAtPos:tile: | 0x008f4f88 | 362 | macro gate, triple dedup, GlowBlock |
| addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient: | 0x008e8320 | 229 | needsRemoved gate, Torch |
| createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure: | 0x008e909c | 1447 | troll cave + chest loot generator |
| loadNewBlockheadAtPos:craftableItemObject:uniqueID: | 0x008f5b70 | 596 | Blockhead spawn + broadcasts |
| conversionThread: | 0x008ae5b8 | 509 | background one-to-two file conversion |

## Load-bearing findings

- **Tree factory**: type→class pinned by arm resolution — 1 AppleTree, 2 MangoTree,
  3 MapleTree, 4 PineTree, 5 CactusTree, 6 CoconutTree, 7 OrangeTree, 8 CherryTree,
  9 CoffeeTree, 0xa LimeTree, 0xf GemTree (GemTree uses the `...gemTreeType:` init).
  An **occupancy scan** walks both 12-byte-stride maps with `std::__1::__tree_next`
  and rejects near-duplicates (x differs, y within ±1, exact-y when the adult gate is
  clear) with a log. This is the sibling of the E17 tree candidate types — the
  world-gen ids now have concrete class names.
- **Plant factory**: type→class pinned — 1 FlaxPlant, 2 SunflowerPlant, 3 CornPlant,
  4 CarrotPlant, 5 ChilliPlant, 6 KelpPlant, 7 VinePlant, 8 TulipPlant, 9 WheatPlant,
  0xa TomatoPlant.
- **NPC factory**: `dynamicObjectTypeForNPCType` + `loadedCountOfObjectsOfType:`
  **512 cap** + `tooManyNPCsToSpawnMoreNearPos:` gate + `classForNPCType` init.
- **Surface/snow forwarders**: `loadStandardDynamicObjectOfType:0x16/0x1d` — the type
  ids the E19 surface pass plants; snow adds `updateInTimeSinceSaved`.
- **GlowBlock**: macro-record gate (+2 nonzero, +4 == marker) then **three dedup
  gates** (map slice +0xd8, `currentlyAddingGlowBlocks` hash, `currentlyLoadingMacroBlocks`
  +0x168) with an insert/erase in-flight bracket around the init.
- **Torch**: existing object at the +0xcc map slice is queried with `needsRemoved` —
  nonzero short-circuits, zero replaces.
- **Treasure/troll**: position jitter (±2 via mod-32), cave geometry gates (solid
  below/right, air opening with byte1==1/byte3==0), **troll NPC type 6 with isAdult 1**,
  MJSoundManager roar anchored by a Vector2, two corner torches type 0xb7; the chest
  arm stamps tile byte3=0x30, builds the key item (type 0x430), and rolls loot on an
  **8-tier rarity ladder (0x149/0x41/0x48/0x57/0x56/0x4c/0x4b/0x58)** plus the
  **0xa6/0xa7** second variant, then `moveInventoryItemsFromArray:toIndex:count:`.
- **Blockhead spawner**: full init chain, first-blockhead activation (count==1 clears
  activeBlockheadIndex), `std::vector<intpair>` push_back broadcast via `worldChanged:`,
  `uiManager blockheadCountChanged`, sound, ParticleEmitter spawn, net send.
- **conversionThread:**: NSAutoreleasePool, `setThreadPriority:` 5, per-item
  `sleepForTimeInterval:` pacing, NSFileManager directory creation under
  worldSaveDirectory, per-file `__wrap_rename`, and
  `performSelectorOnMainThread:@selector(mainThreadRemoveDirFromConversionList:)` —
  the background half of the E19 conversion story.

## Boundaries (honest)

- Item/marker/tile id names (0x430, 0x149 tier ids, 0xa6/0xa7, 0xb7, tile byte3 0x30)
  are read from immediates; the registries that name them live outside this batch.
- The C++ container member layouts behind the slice offsets (+0xcc/+0xd8/+0x168) are
  observed; the header-level types are the demangled route names.
- Gameplay thresholds (512 cap, sparsity, jitter) are read from the compares; their
  tuning intent lives in the game rules, not this evidence.
- The conversion thread's concrete file layout per item is read at the call sites;
  the pacing constant is the call's operand.
