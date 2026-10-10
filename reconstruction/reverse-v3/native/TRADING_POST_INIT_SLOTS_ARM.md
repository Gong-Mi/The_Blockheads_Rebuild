# TradingPost -[initSlotsWithSaveDict:] — executed differential (batch b4j)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x005E4914
boundary: 0x005E4CE0 (next method IMP)
words:    243 (exact coverage asserted by the b3n listing)
types:    v8@0:4 (void return, one dictionary argument: saveDict)
```

The b3n decode of this method (sellSlot restoration and slot initialization, static level-A) is now **executed**:
`tools/test_trading_post_init_slots_arm.py` runs the original ARM body under Unicorn
with synthetic dictionary fixtures and compares the resulting 160-byte
instance image and the full message trace against the recovered C++
contract `reconstruction/recovered/trading_post_init_slots.{h,cpp}` at -O0 and -O2.
`tools/test_trading_post_init_slots_arm_evidence.py` guards it in both host and CI modes;
CTest `recovered_trading_post_init_slots` exercises the contract without the ELF.

## Harness topology (stated limits)

* `objc_msgSend` (GOT slot 0x0105B7A0) is stubbed:
  - `[[NSMutableArray alloc] init]` (receiver `OBJC_CLASS_$_NSMutableArray` 0x00E8A0EC)
  - `[saveDict objectForKey:@"sellSlot"]`
  - `countByEnumeratingWithState:objects:count:` on sellSlotArray
  - `[[InventoryItem alloc] initWithSaveData:itemData]` (receiver `OBJC_CLASS_$_InventoryItem` 0x00E8A0F0)
  - `[item autorelease]`
  - `[item itemType]`
  - `[self->sellSlot addObject:item]`
* `memset` (0x001C2924 via slot 0x0105FB70) executes natively.
* `objc_enumerationMutation` (0x001C2E28 via slot 0x0105FD1C) is stubbed as a no-op.
* The two-level ivar-offset resolution executes for real:
  - `OBJC_IVAR_$_TradingPost.sellSlot` = 100 (self + 100)
  - `OBJC_IVAR_$_TradingPost.needsToUpdateBitmapString` = 124 (self + 124)

## What execution confirmed

* **Slot array allocation**: unconditionally initializes `self->sellSlot` via `[[NSMutableArray alloc] init]` at ivar offset 100.
* **Fast-enumeration loop & chunking**: chunks up to 16 items onto stack buffer; terminal enumeration call returns 0.
* **Item type filtering rule**:
  - `[item itemType]` is extracted for each item.
  - If `itemType == 11` (0x0b), the item is **filtered out** (`cmp r0, #0xb; beq #0x5e4bf8`) and `addObject:` is bypassed.
  - If `itemType != 11`, `[self->sellSlot addObject:item]` is executed.
* **Epilogue flag update**: `self->needsToUpdateBitmapString` is unconditionally set to 1 (`strb r0, [self + 124]`) on method exit.

## Case table (6 cases, all matched bit-exactly)

* `missing_sell_slot`: saveDict lacks "sellSlot" key; loop skipped; exits cleanly setting flag to 1.
* `empty_sell_slot`: "sellSlot" is an empty array; loop skipped; flag set to 1.
* `single_item`: 1 valid item (itemType != 11); added to sellSlot.
* `item_filtered_11`: 1 item with itemType 11; filtered out; sellSlot remains empty.
* `mixed_items`: 4 items with mixed itemTypes (including two 11s); only valid items added.
* `chunked_items_cross_16`: 18 items crossing the 16-element fast-enumeration boundary; multiple batches verified.

## Ledger state

- Persistence core: 149/149 closed at static level-A.
- Executed Level-B differentials: b4a (NPC loader) + b4b (Plant) + b4c (Forwarders) + b4d (Tree stage 1) + b4e (Tree fruit records) + b4f (NPC loadValues) + b4g (Tree growth stage 1) + b4h (FreightCar 4th variant) + b4i (TradePortal price offsets) + **b4j (TradingPost slot init)**.
