# Chest -[initWithWorld:dynamicWorld:saveDict:cache:] — executed differential (batch b4m)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x00CB627C
boundary: 0x00CB6E5C (next method IMP)
words:    760 (exact coverage asserted by the b3m-2 listing)
types:    @28@0:4@8@12@16   (self, _cmd, world, dynamicWorld, saveDict, cache)
runtime superclass: InteractionObject
class_ro_t instance_size: 0x8C = 140
```

The b3m-2 decode of this method (the save-system centerpiece, static level-A at
760 words, the only initWithWorld front member carrying a `__stack_chk_guard`
canary) is now **executed**: `tools/test_chest_init_with_world_arm.py` runs the
original ARM body under Unicorn against synthetic saveDict/world/dynamicWorld
fixtures and compares the full 140-byte instance image, the return value and the
complete (code, arg) message trace with the recovered C++ contract
`reconstruction/recovered/chest_init_with_world.{h,cpp}` compiled at -O0 and -O2.
`tools/test_chest_init_with_world_arm_evidence.py` guards it in host and CI mode;
CTest `recovered_chest_init_with_world` exercises the contract without the ELF.

## Harness topology (stated limits)

* ONE selector-string `objc_msgSend` stub serves both message paths: the GOT
  cell `0x0105B7A0`, the veneer slot `0x0105FB18` (`0x001C281C`) and the
  `objc_msgSendSuper2` GOT cell `0x0105B79C`. The super handler asserts the
  `objc_super` struct (`receiver == self`, class word `0x00E92240` = the OWN
  class), all four forwarded arguments and the stacked `saveDict`/`cache`.
* `objc_msgSend_stret` (veneer `0x001C2918`, slot `0x0105FB6C`) writes the
  64-byte `customRules` result (byte 0 = case gate, bytes 1..63 = 0xAB) and
  asserts the receiver is the `self->world` ivar (offset 4) — the ivar read is
  what the game gates on, not the method argument (the fixture keeps them
  distinct on purpose).
* `memset` (veneer `0x001C2924`, slot `0x0105FB70`) executes real fills and is
  traced at BOTH call sites: the 0x40 `customRules` fallback and the 0x20
  per-slot fast-enumeration state zeroing.
* `objc_enumerationMutation` (veneer `0x001C2E28`, slot `0x0105FD1C`) is traced.
* `__stack_chk_guard` (JUMP_SLOT `0x0105B7E0`, file word 0) is pointed at a
  mapped canary word; `0x001C28B8` (`__stack_chk_fail`) never runs.
* Classref cells: `0x00E8B618` (NSMutableArray) and `0x00E8B620` (NSString) have
  zero file words and are patched to synthetic class tokens; `0x00E8B61C`
  already holds the real `InventoryItem` class object `0x00E91CA0` (asserted).
* `__objc_superrefs` slot `0x00E8BEF0` points at the OWN class `0x00E92240`;
  the runtime superclass is reached through `class+16 -> class_ro_t` (name
  `Chest`, instance_size 0x8C) with the superclass word resolving to
  `InteractionObject` (`0x00E90710`).
* The body passes the REAL ELF CFString objects for `chestType` /
  `safeClientID` / `saveItemSlots` / both format strings; the dispatcher
  resolves keys through the object's +8 data pointer (b4a lesson 7) and
  `stringWithFormat:` synthesizes CFString-shaped keys with the same layout.

## What execution confirmed

* **Super forwarding**: `objc_msgSendSuper2(&(struct objc_super){self, Chest},
  @selector(initWithWorld:dynamicWorld:saveDict:cache:), world, dynamicWorld,
  saveDict, cache)`; a nil result returns nil and touches no ivar.
* **chestType**: `[[saveDict objectForKey:@"chestType"] intValue]` stored as a
  word at offset 108; a missing key (`[nil intValue]`) stores 0.
* **The customRules gate and the RE-READ**: for `chestType == 4` the body takes
  the 64-byte struct by value when `self->world != nil` (0x40 memset fallback
  otherwise) and, if byte 0 of that struct is non-zero, stores 0 into
  `chestType` — then **re-reads the field** at 0x00CB6524, so the zeroed value
  selects the 16-slot path instead of the 4-slot one. Case
  `chest_type_4_rules_gate` proves this with `InitWithCapacity(16)` in the
  trace and `chestType == 0` in the image; the static note that called this a
  dead store would have been wrong.
* **ownerID default**: only when `self->ownerID` (offset 36) is nil does the
  body read `safeClientID` and `retain` it; a pre-set ownerID skips both calls.
* **Capacity rule**: the private helper `0x00CB623C` executes natively four
  times per call site pattern — `numberOfSlots = (chestType == 2 ||
  chestType == 5) ? 4 : 16`; the harness recomputes the expected capacity from
  the emulated ivar and asserts every `initWithCapacity:` argument against it.
* **Count gate**: `[slots count] >= numberOfSlots` selects the restore loop;
  fewer saved slots than the chest capacity pads `inventoryItems` with
  `numberOfSlots` empty `[NSMutableArray array]` objects instead (no
  `objectAtIndex:`/enumeration at all).
* **Per-slot restore loop**: `[NSMutableArray array]` per slot added to
  `inventoryItems` (offset 100), `[slotsArray objectAtIndex:i]`, a 0x20 memset
  of the enumeration state, then `[slotData
  countByEnumeratingWithState:objects:count:16]` in 16-wide batches with the
  per-batch mutation-counter capture, `[[InventoryItem alloc]
  initWithSaveData:itemData]` → `autorelease` → `[item itemType]` → `!= 11`
  filter → `[slotArray addObject:item]`; a terminal 0-call closes each slot.
* **Shelf restore loop**: runs whenever `inventoryItems` is nil (missing
  `saveItemSlots` key or `chestType == 4`), reading
  `shelfRenderItems_%d` / `shelfItemDataBs_%d` through
  `[NSString stringWithFormat:]` for m = 0..3, storing words at 116 (4 × 4B)
  and `strh`-truncated halfwords at 132 (4 × 2B) — 132 + 8 == 140 ==
  `instance_size`, so the compared image covers the whole instance.
* **Epilogue**: `[self initSubDerivedItems]` runs on every non-nil path and the
  body returns self; the stack canary is compared against the mangled guard.

## Case table (13 cases, all matched bit-exactly)

| case | return | trace | items | slots |
|---|---|---|---|---|
| super_nil | 0x0 | 1 | 0 | 0 |
| chest_type_2_full | self | 55 | 4 | 4 |
| chest_type_0_sixteen | self | 92 | 0 | 16 |
| count_less_than_capacity | self | 20 | 2 | 2 |
| slots_key_missing | self | 31 | 0 | 0 |
| chest_type_4_rules_zero | self | 31 | 0 | 16 |
| chest_type_4_rules_gate | self | 99 | 1 | 16 |
| chest_type_4_world_nil | self | 31 | 0 | 16 |
| owner_id_present | self | 30 | 0 | 4 |
| mixed_item_types | self | 58 | 5 | 4 |
| chest_type_key_missing | self | 92 | 0 | 16 |
| chunked_slot_items | self | 123 | 18 | 4 |
| mutation_during_enumeration | self | 61 | 5 | 4 |

Notable coverage: nil super, the itemType == 11 filter on both sides of the
capacity gate, 18 items (batches 16 → 2 → 0), the 0x12345 → 0x2345 `strh`
truncation, missing shelf keys (`[nil intValue]` → 0), and an enumeration
mutation driven by the fixture so `objc_enumerationMutation` executes for the
two elements that observe the bump (the per-batch capture suppresses it again in
the following batch).

## Harness lessons (paid for in this batch)

* `MsgDispatcher` records into its OWN `trace` list; harness code that writes to
  a separate state list silently produces ARM traces of length 0 while the C++
  side has content — append everything to `dispatcher.trace`.
* `StubContext.word(addr)` READS a word; writing state (`itemsPtr`,
  `mutationsPtr`) must go through `uc.mem_write(...)`.
* Batch bookkeeping needs two cursors (`batch_begin` for the current batch,
  `batch_next` for the next one); incrementing the same cursor the element index
  is computed from double-counts and runs off the fixture list.
* Pad-path slot arrays are NOT the saved slots: an addObject: identity assertion
  must range over the arrays the stub created, not over the save-dict slots.
* Patch both the GOT cell and the veneer slot for `objc_msgSend` before blaming
  the decode (b4e lesson, here applied from the start).

## Boundary

Executed differential evidence for this method only: synthetic fixtures, not
Foundation, not the original-app runtime, no device/APK acceptance, and the
`customRules` struct layout beyond byte 0 is still outside the body. The
remaining decode-only loaders of the front are FreeBlock (1,347w) and Workbench
(1,390w); the other natural next slice is the b4-style execution of
KelpPlant/VinePlant (606w/681w).
