# Workbench loader — executed differential (batch b4q)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

```text
IMP:      0x00AE4ED8
boundary: 0x00AE6490 (next method IMP from the pinned ObjC method map)
words:    1,390 (exact coverage asserted by this listing; the FINAL
          executed initWithWorld front member)
selector: initWithWorld:dynamicWorld:saveDict:cache:
super:    InteractionObject   instance_size: 0x144 = 324 (class_ro_t+8;
          instanceStart 100, name verified 'Workbench')
```

`tools/test_workbench_init_arm.py` runs the original ARM body under Unicorn
and compares the 324-byte instance image, the return value and the full
(code, arg) trace with `reconstruction/recovered/workbench_init.{h,cpp}` at
-O0 and -O2 across **11 cases, bit-exact**. CTest `recovered_workbench_init`
+ guard `tools/test_workbench_init_arm_evidence.py` cover CI.

## Executed facts (frozen by the run)

1. **The 16-key scalar walk order**: workbenchType(intValue), selectedIndex,
   xScroll(floatValue), level, craftProgressCount(floatValue), hurryTimer,
   hurrySeconds(floatValue), **hurrying(BOOLVALUE — the static decode said
   intValue)**, hurryCost, fireSpreadTimer(floatValue), fuelFraction,
   **hasFuel(BOOLVALUE)**, lastWorldTime(doubleValue), isInUseFuel(boolValue),
   **availableElectricity(UNSIGNEDINTVALUE)**, currentBlockheadIndexFuel.
2. **currentBlockheadIndexFuel is read TWICE via objectForKey, then intValue
   once** — regardless of the value (the -1 sentinel and a real 7 both show
   the same OFK/OFK/intValue triple; savedBlockheadIndexFuel@116 stores the
   intValue).
3. **The craft wiring is gated by isInUse ALONE**: it fires even when
   craftingItemObject is nil (msgSend on a nil receiver; receiver =
   self->currentBlockhead@56), immediately after the crafting-restore block.
   The fuel wiring is a separate isInUseFuel gate on currentFuelBlockhead@108.
4. **The craftableItem STRET returns a 124-byte struct** (bounds pinned by
   the 0x7c memset at 0xAE5B7C): +0x00 the craftable type, +8.. the per-slot
   types (the 0xb SLOT gate at 0xAE5D4C reads them — a type-11 SLOT is
   skipped wholesale, not per-item), +0x48 the source-slot count that bounds
   the sourceItems_%d loop. objc_msgSend_stret via veneer 0x1C2918 ->
   GOT 0x105FB6C; ARM32 convention: r0 = result buffer, r1 = receiver.
5. **The v1 -> v2 migration**: craftingItemDatav2 absent -> craftingItemData
   present -> `[v1 bytes]` + TWO 124-byte memcpys (GOT memcpy 0x105FB40 via
   veneer 0x1C2894; the second copy stages the blob as the
   initWithCraftableItem: argument — the trace arg is the blob head
   0x03020100 in the fixture) -> `[CraftableItemObject alloc]
   initWithCraftableItem:` -> craftableItem stret. __android_log_print
   (GOT 0x105FB68) is loaded but NOT called on the success path.
6. **The sourceItems_%d loop**: per slot (bounded by the stret slot count):
   `release` the old sourceItems[i], nil it, `stringWithFormat:` the
   `sourceItems_%d` key, `objectForKey:` it, gate on `count`; non-empty ->
   `[NSMutableArray alloc] init]` stored into sourceItems[i] (140+i*4),
   inner NSFastEnumeration over the payloads building InventoryItem children
   (alloc + initWithSaveData: + autorelease + addObject:). Slot type 11 is
   gated BEFORE the count read.
7. **lightDict restore**: `[ArtificialLight alloc]` ->
   `initWithWorld:dynamicWorld:saveDict:cache:parentObject:` (the 5-arg
   variant, saveDict = the lightDict itself) -> stored into light@100 ->
   `[world macroTiles]` + `worldWidthMacro` asked TWICE by the 0xA197B4
   tile-light helper (which reaches `__aeabi_idiv` via veneer 0x1C3728 ->
   GOT 0x0106001C).
8. **initSubDerivedItems** is the hook (NOT initSubDerivedObjects) and the
   final call before return.

## Case table (11 cases, all matched bit-exactly)

```text
super_nil            trace 1    (nil super -> nil)
plain_keys           trace 36   (16-key walk, -1 sentinel, no isInUse tail)
index_fuel_reread    trace 36   (index 7: same OFK/OFK/intValue triple)
v2_type1            trace 49   (BlockheadCraftableItemObject path + wiring)
v2_type2            trace 49   (PaintingCraftableItemObject path)
v2_type_other       trace 49   (CraftableItemObject path, type 9)
v1_migration        trace 51   (bytes + two 124B memcpys + initWithCraftableItem:)
in_use_no_data      trace 39   (nil craftable: wiring STILL fires)
source_items_walk   trace 73   (2 slots: 3 payloads + empty; type-11 slot gate)
fuel_blockhead_wire  trace 37   (isInUseFuel -> fuel wiring)
light_dict_restore   trace 42   (ArtificialLight 5-arg + macroTiles + 2x width)
```

## Boundary

Executed differential evidence for this method only: synthetic fixtures,
not Foundation, not the original-app runtime, no APK/device acceptance.
WITH THIS BATCH **the entire initWithWorld front (60 methods / 13,820 words)
carries EXECUTED differential evidence** — every front member now has both
the static level-A decode and the level-B Unicorn differential.
