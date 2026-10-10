# Action `-[initWithSaveDict:inventoryItems:]` read-back evidence — batch b3d

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_action_initsavedict_inventoryitems.py` →
`action_initsavedict_inventoryitems.json`. Listing:
`disasm_action_initsavedict_inventoryitems.txt` (815w).

```text
Action -[initWithSaveDict:inventoryItems:] 0x00735198 (815w)
  self = [super init] (super2, own superref 0x00e8bd04 → OBJC_CLASS_$_Action)
  if (!self) return nil
  inProgress@4                objectForKey → boolValue        → strb
  isAI@6                      objectForKey → boolValue        → strb
  goalTilePos.x@8 / .y@12     objectForKey → intValue         → str / str [r1,#4]
  interactionItemIndex@20     objectForKey → intValue         → strh
  interactionItemSubIndex@22  objectForKey → intValue         → strh
  interactionItemType         objectForKey → intValue         → local (compare only)
  animationTimer@68           CONSTANT 1.0f (vmov.f32/vstr) — not a key
  interactionItem@16          explicit nil reset

  INVENTORY WALK (only when interactionItemIndex@20 > 0):
    item      = [inventoryItems objectAtIndex:interactionItemIndex]   (arg 3)
    element   = [item objectAtIndex:([item count] - 1)]      → interactionItem@16
    sub       = [element subItems]
    subElem   = [sub objectAtIndex:interactionItemSubIndex@22]
    last      = [subElem objectAtIndex:([subElem count] - 1)] → interactionItem@16
    if ([last itemType] != interactionItemType-from-dict):
        interactionItem@16 = nil; interactionItemIndex@20 = -1;
        interactionItemSubIndex@22 = -1                     (type-mismatch reset)

  [self->interactionItem retain] (0x7358ec)
  goalInteraction@24       objectForKey → intValue          → str
  pathType@28              objectForKey → intValue          → str
  interactionObjectID@32   objectForKey → unsignedLongValue → 64-bit store
                           (str r0,[r1,r2]! + str #0,[r1,#4] zeroes the high word)
  craftableItemObject      objectForKey (nested dictionary)
    craftableObjectType = [[saveDict objectForKey:@"craftableObjectType"] intValue]
      1 → [[BlockheadCraftableItemObject  alloc] initWithSaveDict:dict] → @40
      2 → [[PaintingCraftableItemObject  alloc] initWithSaveDict:dict] → @40
      else → [[CraftableItemObject       alloc] initWithSaveDict:dict] → @40
  craftCountOrExtraData@44 objectForKey → intValue          → strh
  inventoryChange@64       objectForKey → retain            → str
  interactionTestResult@52 objectForKey → getBytes:length: 12 (0xc) inline record
```

Facts:

- **The inventory walk has an explicit type gate with a reset side effect**:
  the object finally stored into `interactionItem@16` must report an
  `itemType` equal to the dictionary's `interactionItemType`, otherwise the
  loader scrubs `interactionItem@16 → nil`,
  `interactionItemIndex@20 → -1`, `interactionItemSubIndex@22 → -1`
  (cmp/beq at 0x735820/0x735824, `movw r0,#0xffff` at 0x735828). Each level
  of the walk stores the **last** element (`count - 1`) of the array it
  inspects, not element 0.
- **The craftable dispatch links straight into batch b3c**: the nested
  `craftableItemObject` dictionary is handed to
  `alloc + initWithSaveDict:` of `BlockheadCraftableItemObject` (type 1),
  `PaintingCraftableItemObject` (type 2) or `CraftableItemObject` (default);
  the class-object cross-check (classref slots 0x00e8a544/0x00e8a548/0x00e8a54c)
  resolves to the same three classes whose initialisers b3c gated, and their
  `class_ro_t` instance sizes come out 152 / 136 / 128 — matching b3c's
  restored-record fits exactly.
- **Read/write asymmetry is now inverted for one key**:
  `Action getSaveDict` (b2o) writes 14 keys and the loader reads all of them
  (`write_only` empty), but the loader additionally consumes
  `craftableObjectType`, which the saver never writes — `read_only =
  ['craftableObjectType']`, i.e. the type tag that selects the nested
  craftable class only ever lives in dictionaries produced by other means.
- **Two fields are not dictionary scalars**: `animationTimer@68` is reset to
  the constant 1.0f, and `interactionObjectID@32` is stored as a 64-bit value
  whose high word is explicitly zeroed (`str r0,[r1,r2]!` + `str #0,[r1,#4]`)
  while `interactionTestResult@52` is a 12-byte inline record written through
  `getBytes:length:` — the same blob idiom as b3c's `craftableItem` (124 B)
  and `skinOptions` (20 B).
- **The tail of the method calls `objc_msgSend` through a local PIC veneer**
  (`0x001c281c`: `add ip, pc, #imm` / `add ip, ip, #imm` /
  `ldr pc, [ip, #imm]!` → slot 0x0105fb18 = imported `objc_msgSend`), so those
  call sites are gated on `bl #0x1c281c` words rather than `blx rN`.
- **Negative controls 12/12**: store offsets (goalTilePos.y +4, halfword
  stores, the high-word zero), the itemType compare, the mismatch `movw`,
  a dispatch classref target, the `== 2` compare, the 12-byte length
  immediate, the veneer immediate, an ivar offset, a key cell payload and the
  superref target — each mutation must fail the run.
- Static level-A evidence only; the runtime walk (array contents, itemType
  values) and the roundtrip remain unexecuted. Next natural boundaries:
  CrystalManager `loadFromSave` 0x009f3d44 (506w), the remaining
  `initWithSaveDict:` variants (Painting 0x00741e18-adjacent classes,
  BlockheadCraftableItemObject already covered) and the 43 subclasses that
  read their own keys inside `initWithWorld:dynamicWorld:saveDict:cache:`
  overrides.
