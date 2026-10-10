# The Chest loader (batch b3m-2)

Scope: `-[Chest initWithWorld:dynamicWorld:saveDict:cache:]`
`0x00cb627c` (760 words, exact variant) — the save-system centerpiece —
closeout series part 2 of 3. `libApplication.so` sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.
Evidence level: **static (level-A)**, pool-exact + helper-word gates.

## Decoded structure

```text
super-forward    → InteractionObject (nil guard → nil)
own keys         chestType           → intValue → Chest.chestType
                 safeClientID       → retain   → DynamicObject.ownerID
                 saveItemSlots      → NSNumber array, count → enumeration
                 shelfItemDataBs_%d   (formatted, stringWithFormat:)
                 shelfRenderItems_%d  (formatted)
SLOT CAPACITY RULE (private helper 0x00cb623c, called 4x before the loops):
                 numberOfSlots = (chestType == 2 || chestType == 5) ? 4 : 16
per-slot loop    reads the two formatted key families per slot index;
                 constructs InventoryItem children via alloc +
                 [InventoryItem initWithSaveData:]; addObject: into
                 Chest.inventoryItems / shelfItemDataBs / shelfRenderItems
                 (initWithCapacity: driven by the capacity rule)
hooks            initSubDerivedItems, then
                 [dynamicWorld dynamicWorldChangedAtPos:objectType:],
                 [world customRules], [self itemType]/[self objectType]
canary           the ONLY front method with __stack_chk_guard (stack
                 canary) — its loops write through local buffers
enumeration      one NSFastEnumeration over saveItemSlots with the
                 0x1c2e28 mutation veneer
```

The capacity rule is the batch's semantic payload: chest types 2 and 5
are 4-slot chests, everything else 16 slots — decoded from the helper's
own `cmp r0,#2` / `cmp r0,#5` / `movw r0,#4` / `movw r0,#0x10` words, all
pinned as gates.

## Census

```text
front total:        60 methods / 13,820 words
covered b3f..b3m2:  58 methods / 11,086 words
remaining:           2 methods / 2,734 words
  FreeBlock  1,347w (exact)
  Workbench  1,390w (exact)
```

## Negative controls

6/6 mutations at the correct site: body gates (push/super/nil-guard) and
three helper-gate mutations (small-capacity movw, big-capacity movw, the
chestType-2 compare) — the capacity rule itself is mutation-covered in
both directions.

## Artifacts

- `tools/recover_chest_big_initwithworld.py` (`--check`/`--self-test`).
- `reconstruction/reverse-v3/native/chest_big_initwithworld.json`.
- `tools/test_chest_big_initwithworld_evidence.py` — dual-mode guard.
- This document.
