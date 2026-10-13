# TradingPost (E151)

The TradingPost lands: the consignment economy - sell slot stacking, the price table and the coin settlement. 46 bodies, 10576 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| tp_00 | TradingPost -[actionTitle] | 0x005edb38 | 45 | 2 | 2 | 0 | 1 | 2 | 0 |
| tp_01 | TradingPost -[addDodoEggDrawQuadData:fromIndex:] | 0x005f2224 | 241 | 4 | 1 | 3 | 0 | 9 | 4 |
| tp_02 | TradingPost -[addDrawCubeData:fromIndex:] | 0x005eeb18 | 1291 | 9 | 3 | 8 | 2 | 32 | 7 |
| tp_03 | TradingPost -[addDrawItemQuadData:fromIndex:] | 0x005f0f9c | 514 | 6 | 1 | 6 | 0 | 19 | 11 |
| tp_04 | TradingPost -[addDrawQuadData:fromIndex:forMacroPos:] | 0x005f0908 | 245 | 0 | 0 | 3 | 0 | 8 | 1 |
| tp_05 | TradingPost -[blockheadIsSeller:] | 0x005edc08 | 144 | 4 | 2 | 2 | 0 | 5 | 10 |
| tp_06 | TradingPost -[buyButtonTappedWithQuantity:] | 0x005ee238 | 414 | 15 | 8 | 9 | 1 | 21 | 8 |
| tp_07 | TradingPost -[coinCount] | 0x005f2a10 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| tp_08 | TradingPost -[contentsDidChange] | 0x005ebbe4 | 173 | 3 | 0 | 6 | 0 | 10 | 0 |
| tp_09 | TradingPost -[creationNetDataForClient:] | 0x005e6938 | 29 | 1 | 1 | 1 | 0 | 1 | 0 |
| tp_10 | TradingPost -[currentBlockheadCash] | 0x005ee188 | 44 | 1 | 1 | 1 | 0 | 1 | 2 |
| tp_11 | TradingPost -[dealloc] | 0x005e69ac | 87 | 2 | 2 | 3 | 1 | 4 | 0 |
| tp_12 | TradingPost -[destroyItemType] | 0x005edaec | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_13 | TradingPost -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x005e7748 | 2111 | 16 | 2 | 8 | 0 | 90 | 34 |
| tp_14 | TradingPost -[freeBlockCreationDataA] | 0x005ed76c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_15 | TradingPost -[freeBlockCreationDataB] | 0x005ed788 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_16 | TradingPost -[freeBlockCreationSaveDict] | 0x005ed720 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| tp_17 | TradingPost -[freeblockCreationItemType] | 0x005ed704 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_18 | TradingPost -[initSubDerivedItems] | 0x005e4ce0 | 375 | 8 | 10 | 7 | 1 | 19 | 1 |
| tp_19 | TradingPost -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] | 0x005e52bc | 279 | 6 | 5 | 4 | 1 | 12 | 5 |
| tp_20 | TradingPost -[initWithWorld:dynamicWorld:cache:netData:] | 0x005e5a94 | 388 | 12 | 5 | 6 | 1 | 20 | 7 |
| tp_21 | TradingPost -[interactionObjectType] | 0x005e7024 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_22 | TradingPost -[interactionRenderItemType] | 0x005f2834 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_23 | TradingPost -[isPaintable] | 0x005f2994 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_24 | TradingPost -[moveInventoryItemsToSellSlotFromArray:count:] | 0x005ea85c | 1250 | 21 | 4 | 5 | 1 | 75 | 52 |
| tp_25 | TradingPost -[occupiesNormalContents] | 0x005f29b0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_26 | TradingPost -[paint:] | 0x005f2850 | 81 | 3 | 1 | 5 | 0 | 3 | 1 |
| tp_27 | TradingPost -[price] | 0x005ede48 | 27 | 0 | 0 | 1 | 0 | 0 | 0 |
| tp_28 | TradingPost -[priceTier] | 0x005edeb4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| tp_29 | TradingPost -[remoteUpdate:] | 0x005e7040 | 450 | 11 | 6 | 12 | 1 | 27 | 5 |
| tp_30 | TradingPost -[remove:] | 0x005ed7a4 | 210 | 6 | 1 | 9 | 0 | 6 | 9 |
| tp_31 | TradingPost -[removeFromMacroBlock] | 0x005f25e8 | 147 | 2 | 1 | 2 | 1 | 9 | 0 |
| tp_32 | TradingPost -[requiresHumanInteraction] | 0x005edbec | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_33 | TradingPost -[sellSlot] | 0x005f29cc | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| tp_34 | TradingPost -[sellTitle] | 0x005ee8b0 | 83 | 2 | 2 | 1 | 1 | 3 | 2 |
| tp_35 | TradingPost -[setCoinCount:] | 0x005f2a4c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| tp_36 | TradingPost -[setPriceTier:] | 0x005edef0 | 166 | 3 | 0 | 5 | 0 | 10 | 0 |
| tp_37 | TradingPost -[staticGeometryDodoEggCount] | 0x005f20e0 | 81 | 4 | 1 | 1 | 0 | 4 | 4 |
| tp_38 | TradingPost -[staticGeometryDrawCubeCount] | 0x005ee9fc | 71 | 3 | 1 | 1 | 0 | 4 | 3 |
| tp_39 | TradingPost -[staticGeometryDrawItemQuadCount] | 0x005f0cdc | 156 | 6 | 1 | 4 | 0 | 9 | 7 |
| tp_40 | TradingPost -[staticGeometryDrawQuadCountForMacroPos:] | 0x005f08e4 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| tp_41 | TradingPost -[title] | 0x005edb08 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| tp_42 | TradingPost -[updateBitmapString] | 0x005ebf70 | 302 | 7 | 2 | 6 | 2 | 15 | 7 |
| tp_43 | TradingPost -[updateNetDataForClient:] | 0x005e60c8 | 449 | 11 | 5 | 7 | 3 | 20 | 14 |
| tp_44 | TradingPost -[worldChanged:] | 0x005ece18 | 550 | 2 | 1 | 3 | 0 | 25 | 34 |
| tp_45 | TradingPost -[worldContentsChanged:] | 0x005ed6ec | 6 | 0 | 0 | 0 | 0 | 0 | 0 |

## Findings (E151)

- **The TradingPost batch lands**: 46 bodies / 10576 words / 228 in-body branch rows / 464 call rows / 58 routes of `TradingPost` (**super = InteractionObject** — chain TradingPost(127) -> InteractionObject(97) -> DynamicObject(53), Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). The tsv holds exactly 46 instance methods for this class, so the batch is the **complete class**. Roster names tp_00..tp_45 (targets ordered by selector name, not address), 0 name collisions. Mechanical layer regenerated this run: `gen_listings.py` ("bodies 46 words 10576", entrypoint warnings only) + `build_specs.py` (46 bodies, 464 call rows, 58 routes). Listing rows == roster word count for every body (verified programmatically: 0 mismatches). Grades: **3 census** (>1000w): tp_13 (2111w draw:), tp_02 (1291w addDrawCubeData:), tp_24 (1250w moveInventoryItemsToSellSlotFromArray:); **8 census-lite**: tp_44 (550w), tp_03 (514w), tp_29 (450w), tp_43 (449w), tp_06 (414w), tp_20 (388w), tp_18 (375w), tp_42 (302w); the remaining **35 are <=283w and were fully read**. 4 bodies are TRIMMED at the next IMP (tp_12, tp_14, tp_23, tp_36 -- see Boundaries).

- **What the class is**: the player-consigned shop interaction object. Identity/economy ivars (all offset-cell accessed): `sellSlot@100` NSMutableArray of InventoryItem entries, `coinCount@104` int (coins accrued for the consignor), `priceTier@108` int (index into the static price table), `sellerClientName@112` NSString (peerID of the consignor), `usageShader@116` Shader (the 'ColoredNoTexture' overlay for the in-use bar), `bitmapString@120` BitmapString (the 'SHOP' / 'CLOSED' / price sign), `needsToUpdateBitmapString@124`, `inventoryNeedsToBeSentWithUpdate@125`, `blackText@126` (sign text color latch). Base-class fields used: DynamicObject pos/floatPos/macroTileOwner/ownerID/ownerName/cache/world/dynamicWorld/updateNeedsToBeSent/isNet/needsRemoved, InteractionObject currentBlockhead/isInUse/remoteBlockheadInUseUniqueID/needsToBeRemovedWhenInteractionEnds/shader/paintColor.

- **Price line (tp_27/tp_42)**: `-[price]` = `staticPriceTable[priceTier@108]` from a plain int table at **0xe13a90** (PIC base 0x0105faf4 + signed word at cell 0x5edea4): 1,2,3,4,5,6,7,8,9,10,15,20,25,30,35,40,45,50,60,70,80,90,100,125,150,175,200,250,300,350,400,450,... The sign string is `-[updateBitmapString]` (tp_42): "CLOSED" when sellSlot is empty, else a price string from the local helper 0x5ec428 which formats the coin count with three currency glyphs - "<100 -> %d¥"; 100..9999 -> "%d€ %d¥" (units=price/100, rem=price%100, rem==0 -> "%d€"); >=10000 -> "%d₽ %d€" (the yen remainder is dropped in that branch). BitmapString is built 128x48, alignment 1, blackText ? blackFont : embossedFont, white color, and blackText = (green > 0.75 - 0.25*(red+blue)) exactly like Sign sg_33 (VFP-truth constants 0.75/0.25 from the _gl listing; r2's pool disassembly mislabels those immediates).

- **Consignment / economics flow**: `-[buyButtonTappedWithQuantity:]` (tp_06, census-lite) charges the buyer: guard currentBlockhead; q <= [sellSlot count]; total = q*[self price]; total <= [currentBlockhead totalCash]; then `self.coinCount += total` + `[currentBlockhead subtractCash:total]`, and per sold item pops `[sellSlot lastObject]`, strips the 6 ownership keys (ownerName/ownerID/sellerClientName/sellerClientID/safeClientID/ironPlaceClientID) from a copy of its dynamicObjectSaveDict, and (itemType != 0xb) hands the item to `[dynamicWorld createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:0 playSound:4 priorityBlockhead:currentBlockhead]` before `removeLastObject`. It finishes by setting updateNeedsToBeSent/needsToUpdateBitmapString/inventoryNeedsToBeSentWithUpdate and firing Game Center `reportAchievementWithIdentifier:@"grp.tycoon"`. `-[moveInventoryItemsToSellSlotFromArray:count:]` (tp_24, census) is the stock-in side (merge stacks of the same itemType+dataA+dataB gated by itemTypeIsStackable with a 99 cap, create `[[InventoryItem alloc] initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:]` entries, `removeObjectAtIndex:` the source, spill leftovers as free blocks with playSound:2, end with `[self contentsDidChange]`, return moved count). `-[blockheadIsSeller:]` (tp_05) gates who may sell: netID == ownerID, or server-side with ownerID nil-or-"server" and the blockhead not being server-controlled.

- **Net protocol (tp_43 / tp_20 / tp_29)**: the wire record is a fixed **0x30-byte** prefix `{super interactionObjectCreationNetData (0x28) | coinCount int @+0x28 | priceTier short @+0x2c}` (tp_43) followed by `gzipDeflate(plistFromObject(metaDict))`; the dict carries ownerID/sellerClientName/ownerName and "sellSlot" = array of `[item saveData]` for itemType != 0xb (flag cleared after). `-[initWithWorld:dynamicWorld:cache:netData:]` (tp_20) and `-[remoteUpdate:]` (tp_29) are the exact inverses (getBytes 0x30, subdataWithRange {0x30,len-0x30} gzipInflate + plistFromData 0x5e60a4), reassigning ownerID/ownerName/sellerClientName; tp_29 additionally rebuilds the sellSlot when the dict has one and, on both paths, refreshes the sign if paintColor changed. tp_20 ends by telling every blockhead `-[netInteractionObjectWasLoaded:]`. Shared family helpers 0x5e67cc (plistFromObject) and 0x5e60a4 (plistFromData) sit between this class's IMPs.

- **Rendering quartet**: the static-geometry counters/servers are consistent and cross-checked - `staticGeometryDodoEggCount` = 1 iff last sell-slot item is itemType 0x5b with dataB != 0 (tp_37 -> tp_01 renders it with fillQuadBufferDodoEgg, center (floatPos.x-5, floatPos.y, -0.9)); `staticGeometryDrawCubeCount` = 3 + isBlock(last) (tp_38 -> tp_02 emits the 3 post-body cubes + optional last-item cube; fill via DrawCube class `fillBuffer:...` 19/20-arg variants, image ids 196/305/304 for the body, `[world expertMode]` consulted); `staticGeometryDrawItemQuadCount` = itemQuadCount(last) (1, or 2 for itemType 103 / colorable - helper 0x5f0f4c) + coin pile (tp_39 -> tp_03 emits the item quad box 0.9/0.1 and, when coinCount>0 and ownerID == the local client's netID, the coin-pile quad image 166/167/260 at (floatPos.x, floatPos.y+5, -0.8)); `staticGeometryDrawQuadCountForMacroPos:` = 1 (tp_40 -> tp_04 paints one image-184 quad at (floatPos.x, floatPos.y+1, -0.99)). All four go through the Apportable image library (texCoordsForImageIndex/paintedIndexForImageIndex, packed-16 paint -> RGB via 0x5ec7e0) and the shared matrix builder 0x5eff44 (= 64-byte constant matrix + translation floats at +0x30/+0x34/+0x38).

- **-[draw:...] (tp_13, census)**: camera->macro clamp math (worldWidthMacro + 6x __aeabi_idiv + tileAtWorldPositionLoaded probe), then the WorldObject shader pass ([shader program]->glUseProgram, uniformLocations/intValue->glUniform1i, [world dayColor]->glUniform4f x3, glEnableVertexAttribArray x2, [shader setColor:], local 16-arg transform helper 0x5e9844 x3), a depth-masked pass that draws bitmapString via `[bitmapString renderWithProjectionMatrix:modelViewMatrix:]`, and finally the **usage overlay** through usageShader@116: gated by sellSlot's last item (itemType != 0xb, [last dataA] > 0) and rate = usageIncrementPerUse(ItemType,0,2,0) (real ELF symbol 0x5e9c30) falling back to clothingItemPasivelyUsedRate (0x5e9fa4) - i.e. the post shows the remaining-use bar of the item currently being used (the reason this class owns a 'ColoredNoTexture' shader).

- **Base-contract one-liners**: interactionObjectType=5, interactionRenderItemType=167, destroyItemType / freeblockCreationItemType = 168 (0xa8 - the free block the post converts into), freeBlockCreationDataA/B = 0, freeBlockCreationSaveDict = [self getSaveDict], requiresHumanInteraction/isPaintable/occupiesNormalContents = YES, worldContentsChanged: is empty, actionTitle = "USE %@", title = "SHOP", sellTitle = "SHOP" or "SHOP (seller)". dealloc releases exactly sellerClientName/sellSlot/bitmapString (usageShader not released); contentsDidChange mirrors Chest ce_07 minus the proxyObjectOwner branch (updateNeedsToBeSent + inventoryNeedsToBeSentWithUpdate + dynamicWorldChangedAtPos + needsToUpdateBitmapString + the 4 reloads).

| body | method | words | branches | calls | grade |
|---|---|---|---|---|---|
| tp_00 | `-[actionTitle]` | 45 | 0 | 2 | read |
| tp_01 | `-[addDodoEggDrawQuadData:fromIndex:]` | 241 | 4 | 9 | read |
| tp_02 | `-[addDrawCubeData:fromIndex:]` | 1291 | 7 | 32 | census |
| tp_03 | `-[addDrawItemQuadData:fromIndex:]` | 514 | 11 | 19 | census-lite |
| tp_04 | `-[addDrawQuadData:fromIndex:forMacroPos:]` | 245 | 1 | 8 | read |
| tp_05 | `-[blockheadIsSeller:]` | 144 | 10 | 5 | read |
| tp_06 | `-[buyButtonTappedWithQuantity:]` | 414 | 8 | 21 | census-lite |
| tp_07 | `-[coinCount]` | 15 | 0 | 0 | read |
| tp_08 | `-[contentsDidChange]` | 173 | 0 | 10 | read |
| tp_09 | `-[creationNetDataForClient:]` | 29 | 0 | 1 | read |
| tp_10 | `-[currentBlockheadCash]` | 44 | 2 | 1 | read |
| tp_11 | `-[dealloc]` | 87 | 0 | 4 | read |
| tp_12 | `-[destroyItemType]` | 7 | 0 | 0 | read (TRIMMED) |
| tp_13 | `-[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 2111 | 34 | 90 | census |
| tp_14 | `-[freeBlockCreationDataA]` | 7 | 0 | 0 | read (TRIMMED) |
| tp_15 | `-[freeBlockCreationDataB]` | 7 | 0 | 0 | read |
| tp_16 | `-[freeBlockCreationSaveDict]` | 19 | 0 | 1 | read |
| tp_17 | `-[freeblockCreationItemType]` | 7 | 0 | 0 | read |
| tp_18 | `-[initSubDerivedItems]` | 375 | 1 | 19 | census-lite |
| tp_19 | `-[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]` | 279 | 5 | 12 | read |
| tp_20 | `-[initWithWorld:dynamicWorld:cache:netData:]` | 388 | 7 | 20 | census-lite |
| tp_21 | `-[interactionObjectType]` | 7 | 0 | 0 | read |
| tp_22 | `-[interactionRenderItemType]` | 7 | 0 | 0 | read |
| tp_23 | `-[isPaintable]` | 7 | 0 | 0 | read (TRIMMED) |
| tp_24 | `-[moveInventoryItemsToSellSlotFromArray:count:]` | 1250 | 52 | 75 | census |
| tp_25 | `-[occupiesNormalContents]` | 7 | 0 | 0 | read |
| tp_26 | `-[paint:]` | 81 | 1 | 3 | read |
| tp_27 | `-[price]` | 27 | 0 | 0 | read |
| tp_28 | `-[priceTier]` | 15 | 0 | 0 | read |
| tp_29 | `-[remoteUpdate:]` | 450 | 5 | 27 | census-lite |
| tp_30 | `-[remove:]` | 210 | 9 | 6 | read |
| tp_31 | `-[removeFromMacroBlock]` | 147 | 0 | 9 | read |
| tp_32 | `-[requiresHumanInteraction]` | 7 | 0 | 0 | read |
| tp_33 | `-[sellSlot]` | 17 | 0 | 0 | read |
| tp_34 | `-[sellTitle]` | 83 | 2 | 3 | read |
| tp_35 | `-[setCoinCount:]` | 17 | 0 | 0 | read |
| tp_36 | `-[setPriceTier:]` | 166 | 0 | 10 | read (TRIMMED) |
| tp_37 | `-[staticGeometryDodoEggCount]` | 81 | 4 | 4 | read |
| tp_38 | `-[staticGeometryDrawCubeCount]` | 71 | 3 | 4 | read |
| tp_39 | `-[staticGeometryDrawItemQuadCount]` | 156 | 7 | 9 | read |
| tp_40 | `-[staticGeometryDrawQuadCountForMacroPos:]` | 9 | 0 | 0 | read |
| tp_41 | `-[title]` | 12 | 0 | 0 | read |
| tp_42 | `-[updateBitmapString]` | 302 | 7 | 15 | census-lite |
| tp_43 | `-[updateNetDataForClient:]` | 449 | 14 | 20 | census-lite |
| tp_44 | `-[worldChanged:]` | 550 | 34 | 25 | census-lite |
| tp_45 | `-[worldContentsChanged:]` | 6 | 0 | 0 | read |

## Boundaries

- **Scope**: 46/46 selectors of `TradingPost` as listed in the pinned ELF (sha256 733d8210...30b94c7); the tsv holds no other instance methods for this class, so no TradingPost method is outside this batch. C methods the class calls (usageIncrementPerUse 0x5e9c30, clothingItemPasivelyUsedRate 0x5e9fa4, tileTexCoordsForItemType 0x5f0450, tileTexCoordsForWorkbenchTypeAndLevel 0x5effb8) are outer-scope dependencies decoded only as far as the call sites/roles here.
- **TRIMMED bodies** (listing bound = next ObjC IMP, header keeps the ARM.exidx end): tp_12 `-[destroyItemType]` (exidx 0x5edb38, trimmed at IMP 0x5edb08 -[title]), tp_14 `-[freeBlockCreationDataA]` (0x5ed7a4 / 0x5ed788 -[freeBlockCreationDataB]), tp_23 `-[isPaintable]` (0x5f29cc / 0x5f29b0 -[occupiesNormalContents]), tp_36 `-[setPriceTier:]` (0x5ee238 / 0x5ee188 -[currentBlockheadCash]). tp_12/tp_14/tp_23 are 7-word constant stubs; tp_36's 166-word setter is fully listed together with its pool. In all four cases the trim re-bounds the listing's pool region rather than removing identified instructions.
- **Census-grade bodies** (structure + histograms + anchor windows, not per-instruction full reads): tp_13 (2111w), tp_02 (1291w), tp_24 (1250w). For these three the census pass pins phases, call/send histograms, branch skeleton, constants and key windows (documented above), but individual straight-line stretches (most of tp_13's 0x5e8b44-0x5e9490 quad assembly; tp_02's 0x5eec90-0x5ef3cc static-face block; tp_24's per-type filter middle 0x5eae50-0x5eb030) are summarized rather than decoded instruction-by-instruction. tp_24's exact interleaving of the "drop leftover as free block" and "add InventoryItem" paths between 0x5eaf08 and 0x5eb480 was not fully pinned (both paths and their selectors are verified; the branch order between them is inferred). tp_13's anonymous local helpers 0x5e9844 / 0x5e9a78 (16-arg) and 0x5ea29c (23-arg) are labeled by arg shape + call site only.
- **r2 pool-comment caveat (recurring)**: r2's `; [0x...]=...` pool annotations misclassify bare literal-pool words as PIC-base cells; in this batch the affected constants were re-read from the raw ELF (struct at file offset == vaddr) - e.g. tp_42's blackText thresholds are 0.75/0.25 (`vmov.f64 d1,#104 / d2,#80` in the _gl listing, not 7/2 as the r2 row suggests), and the tp_27 price table / tp_42 currency strings were read from ELF bytes. All VFP immediates quoted in the semantics were taken from the `_gl.txt` GNU listings.
- **Helper ownership**: out-of-body local statics (0x5eff44 matrix builder, 0x5ec7e0 packed16->RGBA, 0x5ec428 priceString, 0x5ecdec Vec2 store, 0x5e9a2c/0x5f17a4 Vec4 stores, 0x5f0f4c itemQuadCount, 0x5f00c4 type->index switch, 0x5ed6b0 abs, 0x5f0524/0x5f17f0 quad bridges, 0x5e67cc/0x5e60a4 plist pair) were disassembled directly from the ELF because they lie between IMPs; the ELF's symbol table names only usageIncrementPerUse/clothingItemPasivelyUsedRate/tileTexCoordsForItemType/tileTexCoordsForWorkbenchTypeAndLevel in this region, so the role labels for the rest are functional (byte-verified), not symbol-derived.
- **Wire-format caveat**: the 0x28-byte prefix of `interactionObjectCreationNetData` belongs to the InteractionObject/DynamicObject contract (E146/E139 evidence, out of this batch); this batch pins its length and the +0x28/+0x2c tail (verified identically from tp_43 build vs tp_20/tp_29 parse). The currency glyphs stored in the string pool are raw UTF-8 U+00A5 / U+20AC / U+20BD; whether the game font renders them as distinct coin icons was not probed.
- **Item-type literals**: 0x5b (91, live dodo egg), 0xb (11, excluded from sellSlot net data + free-block handoff), 0xa8 (168, post free block), 0xa7 (167), 196/304/305 (body images), 166/167/260 (coin-pile images), 103 / colorable (2-quad items), 1043/1065 (non-merge item types in tp_24) are quoted as compiled; their display names were not resolved in this batch (ItemType table lives in the dwarf line).
