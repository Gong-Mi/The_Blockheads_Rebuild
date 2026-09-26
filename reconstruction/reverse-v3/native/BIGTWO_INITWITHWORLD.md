# FreeBlock / Workbench — FINAL closeout of the initWithWorld front (batch b3m-3)

Scope: the two biggest loaders — FreeBlock `0x00626a68` (1,347w) and
Workbench `0x00ae4ed8` (1,390w), both exact variant, 2,737 words. With
this batch **the entire `initWithWorld:` front — 60 methods / 13,820
words across all three selector variants — carries static level-A
evidence**. `libApplication.so` sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## FreeBlock (super=DynamicObject) — the falling/loose-item entity

- 12 own keys: `bounceTimer, creationTime, dataA, dataB,
  dynamicObjectSaveDict, fallSpeed, floatPos[VX], floatPos[VY], hovers,
  itemType, priorityBlockheadUinqueID` (the original's own typo, preserved
  verbatim), `subItems`
- InventoryItem child construction (alloc + `initWithSaveData:` — same
  family as Chest) into `FreeBlock.subItems` (NSMutableArray)
- `[world blockheadWithIDIncludingNet:]` resolves `priorityBlockhead` from
  the loaded ID; `[blockhead updatePosition:]` re-syncs it;
  `[dynamicWorld dynamicWorldChangedAtPos:objectType:]`
- `creationTime` + `[world worldTime]` — the **6th site** of the b3a
  worldTime-relative gate family
- `hovers` → boolValue; `floatPos[VX]/[VY]` → floatValue (velocity axes)
- hook: **`initSubDerivedObjects`** — a NEW 4th hook name of the line
  (loadDerivedStuff / initSubDerivedItems / initSubDerivedStuffStuff /
  initSubDerivedObjects)

## Workbench (super=InteractionObject) — the crafting centerpiece

- **25 own keys** — the richest method of the entire front:
  - fuel/hurry crafting family: `fuelFraction, hasFuel, isInUseFuel,
    currentBlockheadIndexFuel, hurryCost, hurrySeconds, hurryTimer,
    hurrying`
  - craft counters: `count, countCreated, countLeft, craftProgressCount,
    selectedIndex, level, workbenchType, xScroll`
  - **`craftingItemData` + `craftingItemDatav2` — a v1→v2 MIGRATION
    pair** (both keys read; v2 parsed via bytes/length)
  - `fireSpreadTimer, lastWorldTime, availableElectricity, lightDict`
  - formatted per-slot family: `sourceItems_%d`
- child construction of **THREE craftable families** (classrefs):
  `CraftableItemObject` (alloc + `initWithSaveDict:` — the b3c-covered
  family), `BlockheadCraftableItemObject` +
  `PaintingCraftableItemObject` (`initWithCraftableItem:`), `InventoryItem`
  (`initWithSaveData:`), plus `ArtificialLight` via the 5-arg
  `parentObject:` variant (`lightDict`)
- `setInteractionWorkbench:` wires the crafting item to self;
  `[self craftableItem]` / `[self itemType]`
- **`__android_log_print` in the GOT — the ONLY front method that calls
  Android logging** (a diagnostic path in the crafting restore)

## Census — front CLOSED

```text
front total:        60 methods / 13,820 words (43 exact + 17 long; the
                    parentObject 5-arg variant appears as a child-
                    construction selector inside 6 pools)
covered b3f..b3m3:  60 methods / 13,820 words  ← ALL
remaining:           0
```

Batch series on this front: b3f (5), b3g (1), b3h (5), b3i (9), b3j (5),
b3k (15), b3l (15), b3m-1 (2), b3m-2 (1), b3m-3 (2).

## Negative controls

4/4 mutations at the correct site (prologue word 0 / word 1 per class).

## Artifacts

- `tools/recover_bigtwo_initwithworld.py` (`--check`/`--self-test`).
- `reconstruction/reverse-v3/native/bigtwo_initwithworld.json`.
- `tools/test_bigtwo_initwithworld_evidence.py` — dual-mode guard.
- This document.
