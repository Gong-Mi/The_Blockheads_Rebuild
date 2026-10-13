# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 42091 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| hc_00 | Blockhead -[canFish] | 0x00c80fec | 125 | 4 | 1 | 3 | 0 | 4 | 5 |
| hc_01 | Blockhead -[clothingItemAtIndex:] | 0x00b9b86c | 131 | 3 | 1 | 1 | 0 | 8 | 6 |
| hc_02 | Blockhead -[creationNetDataForClient:] | 0x00b9d894 | 402 | 6 | 5 | 16 | 3 | 10 | 5 |
| hc_03 | Blockhead -[currentItem] | 0x00c73804 | 205 | 5 | 1 | 2 | 0 | 14 | 8 |
| hc_04 | Blockhead -[currentItemSlot] | 0x00c73288 | 164 | 5 | 1 | 2 | 0 | 11 | 6 |
| hc_05 | Blockhead -[currentItemSubIndex] | 0x00c73b38 | 141 | 5 | 1 | 2 | 0 | 9 | 7 |
| hc_06 | Blockhead -[currentTradeMission] | 0x00c8a688 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| hc_07 | Blockhead -[drawTransparentInventoryItem:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00c49968 | 11170 | 30 | 5 | 39 | 0 | 273 | 41 |
| hc_08 | Blockhead -[dropInventoryItemsAtIndex:subIndex:count:ignoreFreeblocks:] | 0x00c71800 | 488 | 13 | 7 | 7 | 1 | 27 | 26 |
| hc_09 | Blockhead -[fishingRod] | 0x00c80fb0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hc_10 | Blockhead -[fishingRodCast:] | 0x00c7bb4c | 121 | 1 | 1 | 5 | 0 | 9 | 2 |
| hc_11 | Blockhead -[freeBlockBonusCreationCount] | 0x00bb3468 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| hc_12 | Blockhead -[freeBlockPickupRadius] | 0x00c86434 | 69 | 2 | 1 | 2 | 0 | 2 | 5 |
| hc_13 | Blockhead -[hasJetPackEquipped] | 0x00c863e0 | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| hc_14 | Blockhead -[heldItemType] | 0x00c867d8 | 87 | 2 | 1 | 4 | 0 | 2 | 5 |
| hc_15 | Blockhead -[incrementPassiveItemUsage] | 0x00c6cb00 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| hc_16 | Blockhead -[incrementUsageOfClothing] | 0x00c6cd08 | 580 | 16 | 3 | 6 | 1 | 33 | 33 |
| hc_17 | Blockhead -[incrementUsageOfIceClothing] | 0x00c6d618 | 454 | 14 | 2 | 7 | 1 | 25 | 23 |
| hc_18 | Blockhead -[initWithWorld:dynamicWorld:saveDict:savedInventorySlots:cache:repositionOnLoadFailure:clientSaveDir:clientLocallySavedDict:] | 0x00b95fe4 | 4618 | 68 | 27 | 61 | 8 | 246 | 130 |
| hc_19 | Blockhead -[inventoryItems] | 0x00c638a0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hc_20 | Blockhead -[inventoryLocationOfFirstInstanceOfItemType:] | 0x00c64ca4 | 344 | 5 | 1 | 1 | 0 | 23 | 22 |
| hc_21 | Blockhead -[inventoryNeedsSaving] | 0x00c7156c | 48 | 1 | 1 | 2 | 0 | 1 | 1 |
| hc_22 | Blockhead -[inventoryWasChanged:subIndex:wasUsage:] | 0x00c6ebc0 | 2667 | 27 | 13 | 37 | 3 | 133 | 109 |
| hc_23 | Blockhead -[isCorrectToolForBackWallOfType:forItem:] | 0x00bac9e4 | 202 | 0 | 0 | 0 | 0 | 1 | 72 |
| hc_24 | Blockhead -[itemWillBeRemovedFromInventory:] | 0x00c6a070 | 290 | 4 | 1 | 3 | 0 | 11 | 12 |
| hc_25 | Blockhead -[moveInventoryItemsFromArray:fromIndex:fromSubIndex:toIndex:toSubIndex:count:movedItems:] | 0x00c72628 | 682 | 7 | 1 | 3 | 0 | 40 | 50 |
| hc_26 | Blockhead -[moveInventoryItemsFromIndex:fromSubIndex:toIndex:toSubIndex:count:] | 0x00c71fa0 | 210 | 4 | 1 | 1 | 0 | 11 | 10 |
| hc_27 | Blockhead -[onTradeMission] | 0x00bb8fa4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hc_28 | Blockhead -[pickUpItemIfPossibleInTile:atPos:] | 0x00be91fc | 3452 | 56 | 18 | 16 | 5 | 183 | 169 |
| hc_29 | Blockhead -[pickupDynamicObject:] | 0x00bb0a1c | 277 | 11 | 1 | 3 | 1 | 15 | 8 |
| hc_30 | Blockhead -[pickupItemForTile:astPos:] | 0x00be5d40 | 3375 | 35 | 3 | 3 | 3 | 185 | 164 |
| hc_31 | Blockhead -[placableLightForAIItemIndex] | 0x00c69424 | 319 | 5 | 1 | 1 | 0 | 17 | 28 |
| hc_32 | Blockhead -[placableLightForAIItemType] | 0x00c68f4c | 310 | 5 | 1 | 1 | 0 | 14 | 28 |
| hc_33 | Blockhead -[prepareInventoryForSaving] | 0x00be5854 | 315 | 1 | 1 | 4 | 0 | 4 | 21 |
| hc_34 | Blockhead -[remoteCreationDataUpdate:] | 0x00bb8d6c | 58 | 2 | 2 | 1 | 1 | 2 | 2 |
| hc_35 | Blockhead -[remotePickupRequestResponse:uniqueIDs:count:] | 0x00c7ca5c | 227 | 8 | 1 | 1 | 2 | 11 | 8 |
| hc_36 | Blockhead -[removeCurrentItem] | 0x00c746d0 | 360 | 7 | 1 | 4 | 0 | 18 | 17 |
| hc_37 | Blockhead -[removeInventoryItemIdenticalTo:] | 0x00c7c5f0 | 283 | 4 | 1 | 3 | 0 | 12 | 19 |
| hc_38 | Blockhead -[removeInventoryItemsFromIndex:fromSubIndex:count:] | 0x00c722e8 | 208 | 6 | 1 | 3 | 0 | 10 | 15 |
| hc_39 | Blockhead -[removeItem:index:wasUsedUp:] | 0x00c73d6c | 601 | 0 | 0 | 0 | 0 | 26 | 31 |
| hc_40 | Blockhead -[saveItemSlotsArray] | 0x00c8a1b4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hc_41 | Blockhead -[selectedToolIndex] | 0x00c753d4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hc_42 | Blockhead -[setCurrentItemToItemAtIndex:] | 0x00c73518 | 187 | 7 | 1 | 3 | 0 | 11 | 8 |
| hc_43 | Blockhead -[setInventoryNeedsSaving:] | 0x00c7162c | 117 | 4 | 1 | 3 | 1 | 4 | 5 |
| hc_44 | Blockhead -[setSelectedToolIndex:] | 0x00c75364 | 28 | 0 | 0 | 1 | 0 | 0 | 1 |
| hc_45 | Blockhead -[setupFromNetCreationData:] | 0x00b9be40 | 1056 | 11 | 4 | 23 | 1 | 51 | 19 |
| hc_46 | Blockhead -[sowableItemForAIItemIndex] | 0x00c68964 | 378 | 5 | 1 | 1 | 0 | 25 | 22 |
| hc_47 | Blockhead -[sowableItemForAIItemType] | 0x00c683c0 | 361 | 5 | 1 | 1 | 0 | 22 | 22 |
| hc_48 | Blockhead -[startTradeMission:tradePortal:] | 0x00c87060 | 640 | 11 | 2 | 14 | 2 | 28 | 4 |
| hc_49 | Blockhead -[stopFishing] | 0x00c80e34 | 95 | 2 | 1 | 5 | 0 | 2 | 1 |
| hc_50 | Blockhead -[subtractCash:] | 0x00c6595c | 2111 | 17 | 2 | 8 | 0 | 106 | 136 |
| hc_51 | Blockhead -[subtractItemsFromInventoryOfType:count:] | 0x00c6a4f8 | 25 | 1 | 1 | 0 | 0 | 1 | 0 |
| hc_52 | Blockhead -[subtractItemsFromInventoryOfType:count:dataB:] | 0x00c6a55c | 1595 | 25 | 4 | 5 | 2 | 87 | 89 |
| hc_53 | Blockhead -[totalCash] | 0x00c65204 | 470 | 0 | 0 | 0 | 0 | 28 | 29 |
| hc_54 | Blockhead -[usageMultiplierForFirstItemOfType:] | 0x00c6455c | 466 | 0 | 0 | 0 | 0 | 24 | 31 |
| hc_55 | Blockhead -[useCurrentItemIfPossible] | 0x00c79598 | 1428 | 22 | 6 | 16 | 2 | 52 | 80 |

## Findings (E126)

- **Blockhead's inventory / items / economy slice lands**: 56 bodies / 42,091 words
  from the pinned original libApplication.so (1.7.6, armeabi-v7a). Listings
  hc_00..hc_55 regenerate from the pinned r2 recipe; specs carry 1,833 call rows /
  75 routes. This is the third Blockhead slice (E124 life/state/tick, E125
  crafting/actions, E126 inventory/economy).
- **The inventory model** (from the whole family): 8 slots (loop bound `i < 8`;
  slot 0 is the clothing slot worked by `clothingItemAtIndex:`, item scans start
  at slot 1); each slot holds a stack ("elements") whose members can carry
  sub-stacks (`subItems`, tracked up to 4 sub-slots); per-frame dirty maps are
  byte arrays `inventoryChangedThisFrameSlots[8]` [0x750] and
  `subInventoryChangedThisFrameSlots[8*4]` [0x758], mirrored by usage maps
  [0x778]/[0x780].
- **The current-item trio** resolves through `selectedToolIndex` [0x294]:
  `currentItem` = top of the sub-stack of the selected slot's top element (only
  when `itemTypeSubItemsCanBeModifiedWhileCarried`), `currentItemSlot` = that
  sub-stack, `currentItemSubIndex` = `selectedSubItemIndex & 0xff` (-1 default).
- **Removal / move engine**: `itemWillBeRemovedFromInventory:` is a recursive
  tree walk (items are fast-enumerable containers; when the walked item equals
  `interactionItem` [0x240] it is autoreleased and interactionItem/Index/SubIndex
  reset to -1/-1/-1); `removeInventoryItemsFromIndex:fromSubIndex:count:` removes
  min(count, available) top-down (lastObject -> notify -> removeLastObject) and
  marks the slot dirty; `removeInventoryItemIdenticalTo:` searches by pointer
  identity (== only, no isEqual); `moveInventoryItemsFromArray:...` is the core
  mover (destination itemType merge check via helper 0xc5eaa8, optional
  `movedItems` addObject:, returns the count moved).
- **The economy**: `totalCash` sums coin stacks as int: itemType 0xa6 x1 +
  0xa7 x100 + 0x104 x10000 of the stack count; `subtractCash:` spends the same
  denominations top-down (change/refunds spawned as free blocks); pickup
  rollbacks (`remotePickupRequestResponse:`) subtract cash back for previously
  granted coin pickups; `startTradeMission:tradePortal:` fills the 32-byte
  `currentTradeMission` [0x870] (objc_copyStruct) and sets the onTradeMission
  state byte.
- **The state block (offset convention)**: Blockhead's first own ivar is `state`
  @0x38 (spans 0x38..0xa4); field accesses are emitted as
  `[self + 0x38 + imm]`, so the EFFECTIVE addresses are e.g. interaction enum
  [self+0x3c] (state+4), action enum [self+0x88] (state+0x50), health
  [self+0x58], happiness [self+0x5c], fullness [self+0x60], energy [self+0x64],
  drownFraction [self+0x6c], coffeeEnergy [self+0x8c], hungerPause [self+0x90],
  death [self+0x94], onTradeMission byte [self+0xa0] (state+0x68), plus a
  canFish gate word [self+0x84] (state+0x4c). (E124's published map lists the
  raw immediates without the +0x38 base; effective = listed + 0x38.)
- **Fishing**: `fishingRod` [0x278] getter; `fishingRodCast:(Vector2)` clamps
  each component to [-8000.0f, 8000.0f] (0xc5fa0000/0x45fa0000), writes s16
  fishingRodCastX/Y [0x7f6/0x7f8], sets updateNeedsToBeSent and bumps
  incrementUsageOfInteractionItem:; `stopFishing` sets rod.valid=NO,
  autoreleases it and clears; `canFish` = idle gates + (state+0x4c == 0 OR the
  ridden rideObject's objectType == 0x20).
- **Clothing / jetpack**: `hasJetPackEquipped` = shirtItemType [0x13a] ==
  **0x116** (the same constant E124 found in canFly); `incrementUsageOfClothing`
  ages worn clothing via `clothingItemPasivelyUsedRate(ItemType,int,int,char)`
  + setDataA:, removing used-up pieces with an inventory flash and sound
  (ice variant gated on currentTemperature [0x27c]); `usageMultiplierForFirstItemOfType:`
  = 1.0 - usage/16384.0f.
- **The giants (census)**: drawTransparentInventoryItem... 11,170w (273 calls;
  glUniformMatrix4fv x16, glBindTexture x10, drawShaderQuad x10, sinf x7);
  init...saveDict... 4,618w/246 calls/68 selectors (save-game constructor);
  pickUpItemIfPossibleInTile: 3,452w (tile-pickup router); pickupItemForTile:
  3,375w (per-object pickup incl. door/ladder/elevator/torch/window/wire
  probes); inventoryWasChanged:subIndex:wasUsage: 2,667w; subtractCash: 2,111w;
  subtractItemsFromInventoryOfType:count:dataB: 1,595w; useCurrentItemIfPossible
  1,428w; setupFromNetCreationData: 1,056w (census-lite).

## Boundaries

- Census-grade (not instruction-by-instruction): hc_07, hc_18, hc_22, hc_28,
  hc_30, hc_50, hc_52, hc_55 + hc_45 (census-lite); hc_16/hc_17/hc_25 read to
  structural completeness only.
- Unresolved names/values: the canFish state+0x4c word and the state+0x38[0]
  byte are characterized structurally only (no consumer proves a name); coin
  item types 0xa6/0xa7/0x104 and the 1/100/10000 denomination mapping are the
  machine constants (item names not proven here); the hc_50 "refund/change as
  free blocks" phrasing is census-level; hc_54's usage getter callee and the
  hc_25 merge helper (0xc5eaa8) remain unnamed C targets; hc_39/hc_54 have
  build_specs "skipped cells" (pool-region cells whose slot classification did
  not resolve - the listing annotations still show their raw words).
- Tool id sets reported from cmp ladders only: light items {0x11,0xb7,0x2f,
  0x96,0xfe} (placableLightForAI*), wall/tool table of
  isCorrectToolForBackWallOfType:forItem: (wood set {6,7,8,0x1b,0x1c,0x30-0x32,
  0x3a,0x46}, rock via tileTypeIsRock+{0x18,0x3b,4}, tool mask 0x1f9 covering
  0x5a,0x5d..0x62, specials 6/0x21/0x46).
- Listings/specs only; no runtime verification in this batch. semantics_blockhead3.json
  holds one entry per body (56/56, none empty).

_Artifacts: hc_00..hc_55 .txt/_gl.txt listings, roster.json,
specs_blockhead3.json, semantics_blockhead3.json (this batch dir)._
