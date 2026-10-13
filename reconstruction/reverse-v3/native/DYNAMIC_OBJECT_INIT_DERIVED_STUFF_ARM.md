# DynamicObject -[initDerivedStuff:loadPhysicalBlockIfNeeded:] — executed differential (batch b4k)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x00839508
boundary: 0x008398D0 (next method IMP)
words:    242 (exact coverage asserted by the b3n listing)
types:    c16@0:4c8c12 (BOOL return, two BOOL arguments: initDerivedStuff, loadPhysicalBlockIfNeeded)
```

The b3n decode of this method (root dynamic object macro-block registration tail hook, static level-A) is now **executed**:
`tools/test_dynamic_object_init_derived_stuff_arm.py` runs the original ARM body under Unicorn
with synthetic world/macroTile fixtures and compares the resulting 48-byte
instance image, boolean return value, and the full message trace against the recovered C++
contract `reconstruction/recovered/dynamic_object_init_derived_stuff.{h,cpp}` at -O0 and -O2.
`tools/test_dynamic_object_init_derived_stuff_arm_evidence.py` guards it in both host and CI modes;
CTest `recovered_dynamic_object_init_derived` exercises the contract without the ELF.

## Harness topology (stated limits)

* `0x00A16594` (coordinate converter) is hooked to compute `(x >> 5, y >> 5)`.
* `0x00A16CCC` (macro tile lookup) is hooked to return `macroTile` pointer.
* `objc_msgSend` (GOT slots `0x0105B7A0` and `0x0105FB18`) is stubbed:
  - `[self->world macroTiles]`
  - `[self->world loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:]`
  - `[self shouldAddToMacroBlock]`
  - `[self->dynamicWorld loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:]`
  - `[macroTile->dynamicObjects addObject:self]`
  - `[self objectType]`
  - `[self->dynamicWorld dynamicWorldChangedAtPos:objectType:]`
* The ivar-offset resolution executes for real:
  - `OBJC_IVAR_$_DynamicObject.world` = 4 (self + 4)
  - `OBJC_IVAR_$_DynamicObject.dynamicWorld` = 8 (self + 8)
  - `OBJC_IVAR_$_DynamicObject.macroTileOwner` = 12 (self + 12)
  - `OBJC_IVAR_$_DynamicObject.pos` = 16 (self + 16)

## What execution confirmed

* **Macro tile coordinate conversion & lookup**: converts `self->pos` to macro tile coordinates and assigns `self->macroTileOwner = macroTile` at ivar offset 12.
* **Early nil exit**: if `macroTile == nil`, returns `false` (0) immediately without dispatching any further calls.
* **Physical block presence gate**:
  - Checks if `macroTile->physicalBlock` (offset 4) is loaded.
  - If unloaded: checks `loadPhysicalBlockIfNeeded` (argument 2). If false, returns `false` (0) immediately.
  - If true, invokes `[world loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:false createIfNotCreated:true]`.
* **Macro block addition gate**:
  - Invokes `[self shouldAddToMacroBlock]`.
  - If false, returns `true` (1) early without loading dynamic objects or adding self.
* **Dynamic world registration & addition**:
  - Invokes `[dynamicWorld loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:macroTile includeSurfaceBlocks:true]`.
  - Adds self to macro block's dynamic objects collection (`[macroTile->dynamicObjects addObject:self]`).
* **Post-init notification**:
  - If `!initDerivedStuff` (argument 1 is false), queries `[self objectType]` and notifies `[dynamicWorld dynamicWorldChangedAtPos:self->pos objectType:type]`.
  - Unconditionally returns `true` (1) on completion.

## Case table (6 cases, all matched bit-exactly)

* `happy_path_with_init`: normal initialization, physical block present, adds to macro block, initDerivedStuff=true (no change notification).
* `happy_path_without_init`: normal initialization with initDerivedStuff=false (queries objectType and dispatches dynamicWorldChanged).
* `nil_macro_tile`: macro tile lookup fails; returns false early.
* `physical_block_unloaded_do_load`: physical block missing, loadPhysicalBlockIfNeeded=true (triggers loadPhysicalBlockForMacroTile:).
* `physical_block_unloaded_dont_load`: physical block missing, loadPhysicalBlockIfNeeded=false (returns false early).
* `dont_add_to_macro_block`: shouldAddToMacroBlock=false; returns true early.

## Ledger state

- Persistence core: 149/149 closed at static level-A.
- Executed Level-B differentials: b4a (NPC loader) + b4b (Plant) + b4c (Forwarders) + b4d (Tree stage 1) + b4e (Tree fruit records) + b4f (NPC loadValues) + b4g (Tree growth stage 1) + b4h (FreightCar 4th variant) + b4i (TradePortal price offsets) + b4j (TradingPost slot init) + **b4k (DynamicObject derived stuff)**.
- **ALL SIX PERSISTENCE HOOKS DECODED IN B3N ARE NOW EXECUTED AGAINST ORIGINAL ARM AT LEVEL-B.**
