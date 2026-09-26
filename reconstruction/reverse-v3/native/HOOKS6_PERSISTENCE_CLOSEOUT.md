# The six persistence hooks — PERSISTENCE CORE CLOSED (batch b3n)

Scope: the six referenced-but-undecoded persistence hooks of
`libApplication.so` (sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`),
1,965 words total. **With this batch every member of every save/load
selector family in the binary carries static level-A evidence** — the
persistence core is closed.

```text
Tree          growInTimeSinceSaved:               0x004c2568  546w
TradingPost   initSlotsWithSaveDict:              0x005e4914  243w
NPC           loadValuesFromSaveDict:             0x00643b20  603w
DynamicObject initDerivedStuff:loadPhysicalBlockIfNeeded:
                                                 0x00839508  242w
FreightCar    initWithWorld:…:chestSaveDict:cache: 0x00a403e8 134w
TradePortal   loadPriceOffsets:                   0x00d37a78  197w
```

## Decoded

**Tree `growInTimeSinceSaved:` (546w)** — the tree GROWTH STATE MACHINE,
read-side counterpart of the b4d/b4e loader gate family: `[world
worldTime]` time math against the loaded saveTime (completing the b3k
Tree-loader picture), `[self isStaticTree]` gate, `isGrowingInCompost`,
then `updateGrowth:` / `incrementHeight` / `sowTreeNearParent:adult:
adultMaxAge:` / `removeAllOwnedTiles:` — over the same gene/growth ivar
family the loader gates protect. No own key, no classref, no super call.

**TradingPost `initSlotsWithSaveDict:` (243w)** — the sell-slot loader:
key `sellSlot` → InventoryItem children (alloc + `initWithSaveData:`, the
Chest family) into a NSMutableArray, one NSFastEnumeration, flags
`needsToUpdateBitmapString`.

**NPC `loadValuesFromSaveDict:` (603w)** — **THE NPC STATE LOAD**: 15 own
keys `{age, breed, currentBlockheadIndex, damage, fullness,
hasBeenFedByBlockheadOrChest, hasBred, layCooldownTimer, layTimer,
mateBreed, mateCooldownTimer, name, tameCooldownTimer,
tameCountsByClientID, tamedClientID}` → the complete NPC
survival/breeding/taming state machine; `tameCountsByClientID` loaded as
an NSMutableDictionary `dictionaryWithDictionary:` copy.

**DynamicObject `initDerivedStuff:loadPhysicalBlockIfNeeded:` (242w)** —
the ROOT loader's tail hook: wires the loaded object into the world via
`[dynamicWorld
loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:]`,
`[world loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:
createIfNotCreated:]`, `[world macroTiles]`, `shouldAddToMacroBlock` +
`addObject:` (macro-block registration), with `macroTileOwner` as the
ownership handoff point.

**FreightCar `initWithWorld:…:chestSaveDict:cache:` (134w)** — the FOURTH
selector variant front member: super=TrainCar (via objc_msgSendSuper2
with the own-class superref), then constructs a **Chest child** from the
`chestSaveDict` argument (`alloc` + the exact 4-arg loader),
`setProxyObjectOwner:` + `setFloatPosAndUpdatePosition:` wiring into
`FreightCar.chest`. No own key — the variant's extra argument feeds a
child loader.

**TradePortal `loadPriceOffsets:` (197w)** — the on-load price-offset
normalization: enumerates the source, `doubleValue` →
`numberWithDouble:` (NSNumber classref), rebuilds the dict with
`setObject:forKey:` into `TradePortal.localPriceOffsets`.

## Census

```text
persistence core: 149 methods with static level-A evidence (143 + 6)
remaining: 0 — every save/load selector family member is covered
  save side getSaveDict:        66/66
  initWithWorld front:          60/60 (b3f..b3m-3)
  loadSaveDictValues:            5/5
  initWithSaveDict: family       4/4
  Action inventoryItems          1/1
  CrystalManager loadFromSave    1/1
  hooks (this batch)             6/6
  FreightCar 4th variant        1/1  (inside this batch)
  TradingPost slots / TradePortal prices counted in the hook six
```

## Negative controls

8/8 mutations at the correct site (prologue word 0 and word 1 per method;
the classref-cell resolution — R_ARM_RELATIVE raw word = class object
address — is itself exercised by the FreightCar super gate).

## Artifacts

- `tools/recover_hooks6_persistence.py` (`--check`/`--self-test`).
- `reconstruction/reverse-v3/native/hooks6_persistence_closeout.json`.
- `tools/test_hooks6_persistence_evidence.py` — dual-mode guard.
- This document.
