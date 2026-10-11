# Chest (E139)

The Chest dynamic object lands: inventory storage, the net/save round-trip and the cube/quad geometry emitters. 48 bodies, 12879 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| ce_00 | Chest -[actionTitle] | 0x00cbd834 | 45 | 2 | 2 | 0 | 1 | 2 | 0 |
| ce_01 | Chest -[addDodoEggDrawQuadData:fromIndex:] | 0x00cc3430 | 360 | 5 | 1 | 6 | 0 | 9 | 17 |
| ce_02 | Chest -[addDrawCubeData:fromIndex:] | 0x00cbe5c0 | 2373 | 11 | 2 | 12 | 2 | 39 | 28 |
| ce_03 | Chest -[addDrawItemQuadData:fromIndex:] | 0x00cc21d4 | 396 | 5 | 1 | 6 | 0 | 11 | 18 |
| ce_04 | Chest -[addDrawQuadData:fromIndex:forMacroPos:] | 0x00cc1a64 | 261 | 0 | 0 | 4 | 0 | 8 | 3 |
| ce_05 | Chest -[canBeUsedByBlockhead:] | 0x00cbd940 | 148 | 5 | 2 | 3 | 1 | 5 | 8 |
| ce_06 | Chest -[chestType] | 0x00cbd904 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| ce_07 | Chest -[contentsDidChange] | 0x00cbc1d0 | 200 | 4 | 1 | 7 | 0 | 9 | 4 |
| ce_08 | Chest -[dealloc] | 0x00cb94ec | 49 | 2 | 2 | 1 | 1 | 2 | 0 |
| ce_09 | Chest -[destroyItemType] | 0x00cbd634 | 18 | 0 | 0 | 1 | 0 | 1 | 0 |
| ce_10 | Chest -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00cbb1d0 | 138 | 0 | 0 | 0 | 0 | 0 | 0 |
| ce_11 | Chest -[freeBlockCreationDataA] | 0x00cbd274 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ce_12 | Chest -[freeBlockCreationDataB] | 0x00cbd290 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ce_13 | Chest -[freeBlockCreationSaveDict] | 0x00cbd228 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| ce_14 | Chest -[freeblockCreationItemType] | 0x00cbd140 | 18 | 0 | 0 | 1 | 0 | 1 | 0 |
| ce_15 | Chest -[getSaveDictIncludingInventory:] | 0x00cb9638 | 886 | 17 | 7 | 4 | 4 | 44 | 33 |
| ce_16 | Chest -[initSubDerivedItems] | 0x00cb4ee0 | 167 | 1 | 0 | 3 | 0 | 8 | 4 |
| ce_17 | Chest -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] | 0x00cb517c | 1072 | 18 | 4 | 4 | 3 | 54 | 59 |
| ce_18 | Chest -[initWithWorld:dynamicWorld:cache:netData:] | 0x00cb6e5c | 786 | 20 | 7 | 8 | 3 | 39 | 30 |
| ce_19 | Chest -[interactionObjectType] | 0x00cba410 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ce_20 | Chest -[interactionRenderItemType] | 0x00cc39d0 | 18 | 0 | 0 | 1 | 0 | 1 | 0 |
| ce_21 | Chest -[inventoryChanged] | 0x00cc41bc | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| ce_22 | Chest -[inventoryDataAllowingEmpty:] | 0x00cb7ac8 | 323 | 0 | 0 | 0 | 0 | 15 | 16 |
| ce_23 | Chest -[inventoryItems] | 0x00cc3d04 | 72 | 3 | 1 | 3 | 0 | 3 | 2 |
| ce_24 | Chest -[isPaintable] | 0x00cc3bbc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ce_25 | Chest -[loadInventoryItemsFromDiskIfNeeded] | 0x00cc3bd8 | 75 | 2 | 1 | 4 | 0 | 2 | 3 |
| ce_26 | Chest -[moveInventoryItemsFromArray:toIndex:count:] | 0x00cbc100 | 52 | 1 | 0 | 0 | 0 | 5 | 1 |
| ce_27 | Chest -[moveInventoryItemsFromArray:toIndex:count:assignedIndexes:] | 0x00cbb3f8 | 834 | 10 | 3 | 3 | 0 | 46 | 46 |
| ce_28 | Chest -[occupiesNormalContents] | 0x00cc3e24 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ce_29 | Chest -[paint:] | 0x00cc3a18 | 105 | 3 | 0 | 6 | 0 | 4 | 1 |
| ce_30 | Chest -[remoteInventoryDataRecieved:] | 0x00cb88b4 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| ce_31 | Chest -[remoteUpdate:] | 0x00cba42c | 873 | 20 | 5 | 14 | 3 | 39 | 37 |
| ce_32 | Chest -[remove:] | 0x00cbd2ac | 158 | 4 | 1 | 8 | 0 | 4 | 9 |
| ce_33 | Chest -[removeFromMacroBlock] | 0x00cbdce4 | 211 | 3 | 2 | 4 | 1 | 10 | 4 |
| ce_34 | Chest -[removeItemIfAvailable:] | 0x00cc3e40 | 223 | 7 | 1 | 1 | 0 | 11 | 10 |
| ce_35 | Chest -[requiresHumanInteraction] | 0x00cbd8e8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ce_36 | Chest -[setNeedsRemoved:] | 0x00cbd524 | 68 | 2 | 2 | 2 | 1 | 2 | 2 |
| ce_37 | Chest -[startInteractionWithBlockhead:] | 0x00cbe330 | 164 | 5 | 2 | 5 | 1 | 6 | 7 |
| ce_38 | Chest -[staticGeometryDodoEggCount] | 0x00cc3140 | 188 | 5 | 1 | 4 | 0 | 5 | 16 |
| ce_39 | Chest -[staticGeometryDrawCubeCount] | 0x00cbe030 | 192 | 4 | 1 | 3 | 0 | 5 | 18 |
| ce_40 | Chest -[staticGeometryDrawItemQuadCount] | 0x00cc1e78 | 195 | 5 | 1 | 4 | 0 | 7 | 17 |
| ce_41 | Chest -[staticGeometryDrawQuadCountForMacroPos:] | 0x00cc19fc | 26 | 0 | 0 | 1 | 0 | 0 | 2 |
| ce_42 | Chest -[title] | 0x00cbd67c | 110 | 0 | 7 | 1 | 0 | 0 | 17 |
| ce_43 | Chest -[updateInventoryWithData:] | 0x00cb8140 | 477 | 13 | 1 | 5 | 2 | 24 | 22 |
| ce_44 | Chest -[updateNetDataForClient:] | 0x00cb8908 | 761 | 18 | 5 | 8 | 3 | 35 | 37 |
| ce_45 | Chest -[updatePosition:] | 0x00cbdb90 | 85 | 2 | 1 | 3 | 1 | 2 | 3 |
| ce_46 | Chest -[worldChanged:] | 0x00cbc704 | 619 | 2 | 1 | 4 | 0 | 27 | 41 |
| ce_47 | Chest -[worldContentsChanged:] | 0x00cbd0ec | 21 | 1 | 1 | 0 | 0 | 1 | 0 |

## Findings (E139)

- **The Chest batch lands**: 48 bodies / 12,879 words / 515 branches / 488 call rows of `Chest` (InteractionObject subclass; Apportable offset-cell binary). Implementation span 0xcb4ee0..0xcc41f8, body order = ObjC method-table order. 2 bodies >1000w [census], 10 bodies 300-1000w [census-lite], 36 bodies <=300w fully read. Roster names ce_00..ce_47 are collision-free.

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | ce_00 | `Chest -[actionTitle]` | 45 | 0 | 2 | read |
  | ce_01 | `Chest -[addDodoEggDrawQuadData:fromIndex:]` | 360 | 17 | 9 | census-lite |
  | ce_02 | `Chest -[addDrawCubeData:fromIndex:]` | 2373 | 28 | 39 | census |
  | ce_03 | `Chest -[addDrawItemQuadData:fromIndex:]` | 396 | 18 | 11 | census-lite |
  | ce_04 | `Chest -[addDrawQuadData:fromIndex:forMacroPos:]` | 261 | 3 | 8 | read |
  | ce_05 | `Chest -[canBeUsedByBlockhead:]` | 148 | 8 | 5 | read |
  | ce_06 | `Chest -[chestType]` | 15 | 0 | 0 | read |
  | ce_07 | `Chest -[contentsDidChange]` | 200 | 4 | 9 | read |
  | ce_08 | `Chest -[dealloc]` | 49 | 0 | 2 | read |
  | ce_09 | `Chest -[destroyItemType]` | 18 | 0 | 1 | read |
  | ce_10 | `Chest -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 138 | 0 | 0 | read |
  | ce_11 | `Chest -[freeBlockCreationDataA]` | 7 | 0 | 0 | read |
  | ce_12 | `Chest -[freeBlockCreationDataB]` | 7 | 0 | 0 | read |
  | ce_13 | `Chest -[freeBlockCreationSaveDict]` | 19 | 0 | 1 | read |
  | ce_14 | `Chest -[freeblockCreationItemType]` | 18 | 0 | 1 | read |
  | ce_15 | `Chest -[getSaveDictIncludingInventory:]` | 886 | 33 | 44 | census-lite |
  | ce_16 | `Chest -[initSubDerivedItems]` | 167 | 4 | 8 | read |
  | ce_17 | `Chest -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]` | 1072 | 59 | 54 | census |
  | ce_18 | `Chest -[initWithWorld:dynamicWorld:cache:netData:]` | 786 | 30 | 39 | census-lite |
  | ce_19 | `Chest -[interactionObjectType]` | 7 | 0 | 0 | read |
  | ce_20 | `Chest -[interactionRenderItemType]` | 18 | 0 | 1 | read |
  | ce_21 | `Chest -[inventoryChanged]` | 15 | 0 | 0 | read |
  | ce_22 | `Chest -[inventoryDataAllowingEmpty:]` | 323 | 16 | 15 | census-lite |
  | ce_23 | `Chest -[inventoryItems]` | 72 | 2 | 3 | read |
  | ce_24 | `Chest -[isPaintable]` | 7 | 0 | 0 | read |
  | ce_25 | `Chest -[loadInventoryItemsFromDiskIfNeeded]` | 75 | 3 | 2 | read |
  | ce_26 | `Chest -[moveInventoryItemsFromArray:toIndex:count:]` | 52 | 1 | 5 | read |
  | ce_27 | `Chest -[moveInventoryItemsFromArray:toIndex:count:assignedIndexes:]` | 834 | 46 | 46 | census-lite |
  | ce_28 | `Chest -[occupiesNormalContents]` | 7 | 0 | 0 | read |
  | ce_29 | `Chest -[paint:]` | 105 | 1 | 4 | read |
  | ce_30 | `Chest -[remoteInventoryDataRecieved:]` | 21 | 0 | 1 | read |
  | ce_31 | `Chest -[remoteUpdate:]` | 873 | 37 | 39 | census-lite |
  | ce_32 | `Chest -[remove:]` | 158 | 9 | 4 | read |
  | ce_33 | `Chest -[removeFromMacroBlock]` | 211 | 4 | 10 | read |
  | ce_34 | `Chest -[removeItemIfAvailable:]` | 223 | 10 | 11 | read |
  | ce_35 | `Chest -[requiresHumanInteraction]` | 7 | 0 | 0 | read |
  | ce_36 | `Chest -[setNeedsRemoved:]` | 68 | 2 | 2 | read |
  | ce_37 | `Chest -[startInteractionWithBlockhead:]` | 164 | 7 | 6 | read |
  | ce_38 | `Chest -[staticGeometryDodoEggCount]` | 188 | 16 | 5 | read |
  | ce_39 | `Chest -[staticGeometryDrawCubeCount]` | 192 | 18 | 5 | read |
  | ce_40 | `Chest -[staticGeometryDrawItemQuadCount]` | 195 | 17 | 7 | read |
  | ce_41 | `Chest -[staticGeometryDrawQuadCountForMacroPos:]` | 26 | 2 | 0 | read |
  | ce_42 | `Chest -[title]` | 110 | 17 | 0 | read |
  | ce_43 | `Chest -[updateInventoryWithData:]` | 477 | 22 | 24 | census-lite |
  | ce_44 | `Chest -[updateNetDataForClient:]` | 761 | 37 | 35 | census-lite |
  | ce_45 | `Chest -[updatePosition:]` | 85 | 3 | 2 | read |
  | ce_46 | `Chest -[worldChanged:]` | 619 | 41 | 27 | census-lite |
  | ce_47 | `Chest -[worldContentsChanged:]` | 21 | 0 | 1 | read |

- **The heavy bodies** (>300w), heaviest first:

  | body | method | words | branches | calls |
  |---|---|---|---|---|
  | ce_02 | `Chest -[addDrawCubeData:fromIndex:]` | 2373 | 28 | 39 |
  | ce_17 | `Chest -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]` | 1072 | 59 | 54 |
  | ce_15 | `Chest -[getSaveDictIncludingInventory:]` | 886 | 33 | 44 |
  | ce_31 | `Chest -[remoteUpdate:]` | 873 | 37 | 39 |
  | ce_27 | `Chest -[moveInventoryItemsFromArray:toIndex:count:assignedIndexes:]` | 834 | 46 | 46 |
  | ce_18 | `Chest -[initWithWorld:dynamicWorld:cache:netData:]` | 786 | 30 | 39 |
  | ce_44 | `Chest -[updateNetDataForClient:]` | 761 | 37 | 35 |
  | ce_46 | `Chest -[worldChanged:]` | 619 | 41 | 27 |
  | ce_43 | `Chest -[updateInventoryWithData:]` | 477 | 22 | 24 |
  | ce_03 | `Chest -[addDrawItemQuadData:fromIndex:]` | 396 | 18 | 11 |
  | ce_01 | `Chest -[addDodoEggDrawQuadData:fromIndex:]` | 360 | 17 | 9 |
  | ce_22 | `Chest -[inventoryDataAllowingEmpty:]` | 323 | 16 | 15 |
- **What the class is**: `Chest` is the player-storage dynamic object. `chestType` keys everything: 1=SAFE, 2=SHELF, 3=GOLDEN CHEST, 4=PORTAL CHEST, 5=CABINET, 6=FEEDER CHEST, else plain CHEST (ce_42 title dispatch). The static chestType->ItemType table at 0xcbd188 (1->1065, 2->161, 3->1072, 4->1074, 5->207, 6->1104, else 1043) is shared by ce_09 destroyItemType, ce_14 freeblockCreationItemType and ce_20 interactionRenderItemType; ce_19 interactionObjectType returns the constant 2.

- **Inventory model** (ce_22/43/18/44/31/26/27/34/37/23/25/15): `inventoryItems@100` is an NSMutableArray of slot arrays; slot count is 0xcb623c(chestType) = 4 for types 2/5, else 16. Wire/storage form: nested [item saveData] arrays -> binary plist (NSPropertyListSerialization dataWithPropertyList:format:100 via nil-safe helper 0xcb7fd4, with a @catch NSLog 'Failed to load plist due to exception in dataFromPropertyList. ...') -> gzipDeflate (ce_22 inventoryDataAllowingEmpty:; returns nil when no items and !allowingEmpty). Decode is gzipInflate -> 0xcb7aa4 -> nil-safe propertyListWithData: (0xcc5494) then [[InventoryItem alloc] initWithSaveData:] per item (itemType 0xb items are skipped everywhere: ce_15/31/43/18/44). ce_44 updateNetDataForClient: = 0x40-byte header (0x28 creation net data from interactionObjectCreationNetData via objc_msgSend_stret, hdr+0x28 = 4xu16 shelfRenderItems, hdr+0x30 = 4xu16 shelfItemDataBs, hdr+0x38 = chestType byte) + gzip binary plist {ownerID, ownerName, saveItemSlots}; it clears inventoryNeedsToBeSentWithUpdate@112. ce_31 remoteUpdate: parses exactly that packet (getBytes 0x40; subdataWithRange(0x40,len-0x40) -> gzipInflate -> plist), and asks the world to sendChestInventoryForChest:toClientOwningBlockheadWithID: when the blockhead-in-use ID changed. ce_18 initWithWorld:...:netData: is the decode twin (also handles legacy 'safeClientID' -> ownerID and notifies each blockhead netInteractionObjectWasLoaded:).

- **Shelf mechanics** (types 2/5): 2x2 grid over inventoryItems[0..3]; cached mirror arrays shelfRenderItems@116 (int[4]) / shelfItemDataBs@132 (short[4]) are used when a slot is empty (ce_03/01/38/39/40 rebuild the same resolution). Rendering constants: grid step 5.0 world units, item quad center floatPos + (5*col-6, 4-5*row, -1.5), quad rect 0.6 x 0.075, dodo eggs are itemType 0x5b with dataB != 0 (ce_01 emitter, ce_38 counter); workbench items store their 'level' (dynamicObjectSaveDict[level]) as the shelf dataB (ce_02/15/44).

- **Static geometry counts**: ce_39 cube count (type2: blocks+2; type5: blocks+6; others: 1), ce_40 item-quad count (per item: 2 if itemTypeCanBeColored || itemType==103 else 1, via 0xcc2184), ce_41 macro-pos quads = 1 only for type 5, ce_38 dodo-egg count (0x5b+dataB). ce_02 addDrawCubeData:fromIndex: is the big emitter (DrawCube quads for the body/lid, image ids 115 (0x73, cabinet) / 196 (0xc4, shelf body), paintedIndexForImageIndex remapping, pi/2 rotations, fillBuffer/ fillBufferForBlockOfType bridges; returns emitted cube count). ce_04 emits the single painted type-5 quad; ce_10 -draw:... is a call-free by-value ABI re-layout/no-op.

- **Interaction & lifecycle**: ce_05 canBeUsedByBlockhead: (admins bypass; owned chests type 1/4/5 require [ownerID isEqualToString:[bh localNetID]]); ce_36/32 remove paths (stopInteracting / needsToBeRemovedWhenInteractionEnds); ce_37 startInteractionWithBlockhead: adds contents to the world found list; ce_33 removeFromMacroBlock drops the saved inventory; ce_07 contentsDidChange notifies proxyObjectOwner childNeedsSaving: else world dynamicWorldChangedAtPos:objectType: and sets update flags; ce_45 updatePosition: stops the interaction when the position moved; ce_46/47 worldChanged: neighbor-support check that remove:0's the chest; ce_29 paint: stores paintColor@88 + geometry refresh; ce_25/23 handle local-disk inventory load (portal chests route through [world portalChestManager portalChestInventoryItems]); ce_26/27 the slot-merge move with std::set<int> assignedIndexes (99 = per-slot stack cap, reportAchievementWithIdentifier:@"grp.shelf" for type 2).

- **Shared helpers pinned down**: 0xcb623c = slotCountForChestType; 0xcbd188 = chestType->ItemType jump table; 0xcb7fd4 = plist encode (format 100) wrapper; 0xcb7aa4 -> 0xcc5494 = plist decode wrapper; 0xcbd0b0 = abs(int); 0xcc2184 = item quad count (2 colourable else 1); 0xcc10e0 = 3-float vector builder; 0xcc0ad4 = paintColor->RGBA converter. (All confirmed by disassembly + lister cellinfo, not guessed.)

## Boundaries

- Mechanical layer was inherited as-is and re-verified, not re-run: 48/48 listings carry `# implementation: 0x...` headers; trace line counts == word counts for all 48 bodies; all 869 annotated `ldr rX,[cell]` lines in the traces match the authoritative spec resolution (selectors/imports/ivars/classes; quoting-normalized compare).
- Grades: ce_02 and ce_17 are census (structural summary: send table + constants + sampled phase windows, not line-by-line). ce_10 (138w) is genuinely call-free - treated as a no-op -draw: override; if it is instead an ABI artifact the 'no-op' reading is the only behaviour present in the code.
- ce_46 worldChanged: argument is a 16-byte blob visited twice (loop tail advances a pointer by 8 and jumps back to 0xcbc7a0); the exact C++ shape (pair/range of changed positions) is inferred from that back-edge, not from a type encoding. Its neighbor-support chain (tile byte[1]==2 / byte[3]==0x60 gates) is described structurally.
- ce_02 phases 2-4 are sampled windows; helper addresses 0xcc1154 / 0xcc14ec called inside it are located but not named; r2 sp-offset label noise ([sp, section..dynsym] etc.) was resolved against the GNU objdump gl listings wherever semantics depended on it (e.g. ce_27 [sp,0x16c], ce_44 fp-0x30 = hdr+0x38).
- The 0xcbd188 table values are read as itemType ids (1065/161/1072/1074/207/1104/1043); they are not mapped back to item names here. paintColor semantics for itemType 103 / itemTypeCanBeColored came from the C++ symbol (_Z20itemTypeCanBeColored8ItemType) next to the helper.
