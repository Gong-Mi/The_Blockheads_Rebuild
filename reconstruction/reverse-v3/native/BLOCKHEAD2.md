# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 32709 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| hb_00 | Blockhead -[abortCraft] | 0x00c87be8 | 388 | 10 | 2 | 5 | 3 | 24 | 2 |
| hb_01 | Blockhead -[actionCount] | 0x00c803b8 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| hb_02 | Blockhead -[actionQueue] | 0x00c8a644 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hb_03 | Blockhead -[addExpectedCraftItem:] | 0x00c81f74 | 93 | 0 | 0 | 1 | 0 | 1 | 3 |
| hb_04 | Blockhead -[addToJetFuel] | 0x00c833bc | 255 | 9 | 2 | 3 | 1 | 16 | 11 |
| hb_05 | Blockhead -[canDigBackWallforTile:atPos:withItem:includeActions:] | 0x00ba9d8c | 276 | 3 | 1 | 1 | 0 | 9 | 38 |
| hb_06 | Blockhead -[cancelAnyActionAtGoalPos:orWithInteractionObjectID:goalInteraction:craftCountOrExtraData:] | 0x00c7cde8 | 308 | 10 | 1 | 5 | 0 | 13 | 18 |
| hb_07 | Blockhead -[checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB:] | 0x00c5ec34 | 547 | 18 | 4 | 1 | 3 | 29 | 38 |
| hb_08 | Blockhead -[countOfInventoryItemsOfType:includeActions:] | 0x00c644e4 | 30 | 1 | 1 | 0 | 0 | 1 | 0 |
| hb_09 | Blockhead -[countOfInventoryItemsWithSpecificDataBOfType:dataB:includeActions:] | 0x00c638dc | 723 | 15 | 2 | 5 | 1 | 39 | 46 |
| hb_10 | Blockhead -[craftItemFinished:atWorkbench:] | 0x00c73100 | 49 | 2 | 1 | 1 | 0 | 2 | 0 |
| hb_11 | Blockhead -[craftProgressUICompleteButtonTapped] | 0x00c88c08 | 1033 | 27 | 4 | 6 | 5 | 66 | 34 |
| hb_12 | Blockhead -[craftProgressUIRequiresCollectButtonWhenCompleted] | 0x00c89c2c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| hb_13 | Blockhead -[currentCraftIsOutOfFuel] | 0x00bac27c | 171 | 4 | 1 | 2 | 0 | 8 | 6 |
| hb_14 | Blockhead -[currentInteractionIsGoodOrBad] | 0x00baa1dc | 98 | 3 | 1 | 2 | 0 | 4 | 7 |
| hb_15 | Blockhead -[currentInteractionRequiresHumanInput] | 0x00c8015c | 151 | 3 | 1 | 4 | 0 | 3 | 8 |
| hb_16 | Blockhead -[currentInteractionType] | 0x00baa364 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hb_17 | Blockhead -[currentInteractionTypeForTile:atPos:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:] | 0x00baa3a0 | 58 | 2 | 0 | 0 | 0 | 2 | 0 |
| hb_18 | Blockhead -[freeBlockCreationCountForTile:withItem:] | 0x00bb3488 | 1220 | 4 | 2 | 2 | 0 | 60 | 91 |
| hb_19 | Blockhead -[getCurrentCraftProgress] | 0x00bac194 | 58 | 1 | 1 | 2 | 0 | 1 | 3 |
| hb_20 | Blockhead -[getSaveDictIncludingWorkbenchOrInterationObject:] | 0x00b9ea28 | 1391 | 20 | 26 | 25 | 7 | 63 | 34 |
| hb_21 | Blockhead -[goalInteractionForNPCChaseForNPC:withItemType:] | 0x00ba097c | 343 | 9 | 1 | 0 | 1 | 17 | 27 |
| hb_22 | Blockhead -[goodOrBadInteractionForAction:] | 0x00bacd0c | 1433 | 17 | 2 | 3 | 1 | 75 | 226 |
| hb_23 | Blockhead -[hasActions] | 0x00c800e4 | 30 | 1 | 1 | 1 | 0 | 1 | 0 |
| hb_24 | Blockhead -[hasCancelableActionAtGoalPos:orWithInteractionObjectID:goalInteraction:craftCountOrExtraData:] | 0x00c7d2b8 | 182 | 5 | 1 | 1 | 0 | 8 | 18 |
| hb_25 | Blockhead -[hasInteractionInventoryItemAvailable] | 0x00c74e24 | 336 | 6 | 1 | 2 | 0 | 15 | 22 |
| hb_26 | Blockhead -[hitWithForce:blockhead:] | 0x00c82628 | 167 | 5 | 1 | 3 | 1 | 6 | 5 |
| hb_27 | Blockhead -[hurryCompletion:] | 0x00c881f8 | 644 | 16 | 4 | 4 | 4 | 39 | 9 |
| hb_28 | Blockhead -[hurryCostForCraftTimeRemaining:totalCraftTime:] | 0x00c89c48 | 106 | 0 | 0 | 0 | 0 | 1 | 8 |
| hb_29 | Blockhead -[incrementDamageOfArmorClothing:] | 0x00c6dd30 | 519 | 15 | 3 | 6 | 1 | 28 | 28 |
| hb_30 | Blockhead -[incrementFuelUsage] | 0x00c6e6b0 | 324 | 7 | 1 | 3 | 0 | 16 | 17 |
| hb_31 | Blockhead -[incrementUsageOfInteractionItem:] | 0x00c6cb54 | 109 | 5 | 1 | 3 | 0 | 5 | 1 |
| hb_32 | Blockhead -[incrementUsageOfItem:indexToUse:wasAttack:] | 0x00c6be48 | 33 | 1 | 1 | 0 | 0 | 1 | 0 |
| hb_33 | Blockhead -[incrementUsageOfItem:indexToUse:wasAttack:multiplier:] | 0x00c6becc | 781 | 20 | 3 | 9 | 1 | 47 | 33 |
| hb_34 | Blockhead -[initWithWorld:dynamicWorld:atPosition:cache:blockheadNumber:craftableItemObject:uniqueID:] | 0x00b91e08 | 4047 | 33 | 5 | 23 | 6 | 200 | 182 |
| hb_35 | Blockhead -[interacting] | 0x00c82a4c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hb_36 | Blockhead -[interactionObject] | 0x00bac728 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hb_37 | Blockhead -[interactionTypeForTile:atPos:item:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:] | 0x00ba0fe0 | 8735 | 90 | 17 | 16 | 0 | 472 | 976 |
| hb_38 | Blockhead -[interactionWorkbench] | 0x00bac158 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hb_39 | Blockhead -[itemIndexWithGoodInteractionTypeForTile:] | 0x00c67a58 | 602 | 5 | 1 | 1 | 0 | 27 | 92 |
| hb_40 | Blockhead -[jetPackIsLowOnFuel] | 0x00c837b8 | 43 | 1 | 1 | 1 | 0 | 1 | 4 |
| hb_41 | Blockhead -[jetpackFuelCount] | 0x00c82fc4 | 254 | 5 | 1 | 2 | 0 | 11 | 16 |
| hb_42 | Blockhead -[netInteractionObjectWasLoaded:] | 0x00b9b6a0 | 115 | 5 | 2 | 2 | 0 | 5 | 3 |
| hb_43 | Blockhead -[queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:disableCancelCheck:isAI:] | 0x00c7d680 | 2669 | 51 | 12 | 14 | 6 | 127 | 170 |
| hb_44 | Blockhead -[queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:isAI:] | 0x00c7d590 | 60 | 1 | 0 | 0 | 0 | 1 | 0 |
| hb_45 | Blockhead -[removeInteractionItem:] | 0x00c74c70 | 109 | 5 | 1 | 3 | 0 | 5 | 1 |
| hb_46 | Blockhead -[setInteractionObject:] | 0x00bac674 | 45 | 2 | 1 | 1 | 0 | 2 | 0 |
| hb_47 | Blockhead -[setInteractionWorkbench:] | 0x00bac0a4 | 45 | 2 | 1 | 1 | 0 | 2 | 0 |
| hb_48 | Blockhead -[setPath:type:goalInteraction:extraData:] | 0x00c5c9f0 | 854 | 21 | 7 | 21 | 1 | 37 | 41 |
| hb_49 | Blockhead -[startInteractingWithTileAtIndex:tile:interactionType:] | 0x00bb0e70 | 1919 | 46 | 10 | 22 | 2 | 84 | 71 |
| hb_50 | Blockhead -[stopAllActions] | 0x00c80940 | 145 | 7 | 1 | 4 | 0 | 7 | 2 |
| hb_51 | Blockhead -[stopInteracting] | 0x00bb2c6c | 511 | 14 | 3 | 18 | 2 | 22 | 8 |
| hb_52 | Blockhead -[stopInteractingWithInteractionObjectsIfNoInteractionObject] | 0x00c7c320 | 98 | 1 | 1 | 4 | 0 | 2 | 8 |
| hb_53 | Blockhead -[willBeAddingFuelAtWorkbench:] | 0x00babab0 | 112 | 2 | 1 | 1 | 0 | 3 | 6 |
| hb_54 | Blockhead -[willBeCraftingAtWorkbench:] | 0x00bab850 | 152 | 3 | 1 | 1 | 0 | 5 | 9 |
| hb_55 | Blockhead -[willBeInteractingWithInteractionObject:] | 0x00babc70 | 229 | 5 | 1 | 1 | 0 | 8 | 14 |

## Findings (E125)

- **The interaction-code machine closes its loop**: the goal-interaction code space is
  1..0x1c (28 values). `goodOrBadInteractionForAction:` (hb_22, 1433w) dispatches on
  `[action goalInteraction]` through a **28-arm jump table at 0x00bacd88** and fills the
  12-byte `interactionTestResult` struct that `currentInteractionIsGoodOrBad` (hb_14)
  returns; `goalInteractionForNPCChaseForNPC:withItemType:` (hb_21) maps the chase codes
  feeding it: feeding 0x19(25), capture 0x13(19), milk 0x1b(27), ride 0xc(12), owned
  0x1a(26), special items {0x2a,0x101}->0x14(20), default 0xa(10). The Blockhead's own
  interaction enum [self+4] uses 4=craft, 5=use, 0xd=fuel (hb_13/15/hb_53-55); the
  action enum [state+0x50] uses 5/6 = sleep states (hb_51 yawns).
- **The jetpack fuel economy is fully decoded**: item **0x116** in the shirt slot
  ([self+0x13a]); the fuel cell is inventoryItems[0][0].subItems[2][0]; burning adds
  **+100 (0x64) to dataB per call** (hb_30, cap 0x4000=16384); refuel `addToJetFuel`
  (hb_04) subtracts **0x666 (1638)** per charge and plays 'fireShort.wav'; the gauge
  (hb_41) is `clamp(int((1.0-dataB/16384.0)*10.0 + 0.99), 0, 10)` (net blockheads
  report 10); `jetPackIsLowOnFuel` (hb_40) is gauge <= 1.
- **The item wear/breakage pipeline**: `incrementUsageOfItem:...multiplier:`
  (hb_33, 781w) adds `usageIncrementPerUse(itemType, mode=(world.customRules byte 0x31
  or 2), world.expertMode, wasAttack) * multiplier` to `item.dataA` (u16); dataA >=
  **0x4000** means used up -> `removeItem:index:wasUsedUp:1` + 'toolBreak.wav'
  (armor breaks instead via hb_29 `armourItemDamageUsageRate * 100.0 * dmg` -> 'tear.wav');
  itemTypes 0x67/0x68 spawn a free block **0x66** at the goal; fishing rods (0x9c)
  only wear while `fishingRod` [0x278] is set; dirty-slot tables
  [0x750/0x758/0x778/0x780] track changed slots (bounds <4 or <8 per table).
- **The action-queue contract**: enqueue normalizes through hb_44/hb_43 (goal coords
  land in [state+0xc]/[state+0x10]; the queued action carries the ownership/trade
  payload keys ownerID/safeClientID/sellerClientID/ironPlaceClientID/server + '%d');
  matching (hb_06 cancel / hb_24 test) is **goalTilePos OR nonzero interactionObjectID
  equality**, with an int16 craftCountOrExtraData equality extra for goalInteraction in
  {0xf,0x10}; cancellation kills the in-progress path via
  `[world abortInProgressPathIfForBlockhead:]` + `setPath:nil type:2 ...`;
  `stopAllActions` clears waitingForFillResponse [0x93d] and waitingForPath [0x730].
- **Workbench interaction matching**: hb_53/54/55 compare the stored goal coords
  [state+0xc]/[state+0x10] against the object's pos: y admits pos.y, pos.y+1 when
  isDoubleHeight, pos.y-1 for workbench types {1,0xd} or objectType 0x32; two-block-wide
  objects admit x-1/x+1 gated by `flipped`. `currentCraftIsOutOfFuel` (hb_13) knows the
  **fuel workbench types {3,8,9,0xe,0xf,0x1f}** (fuelCount==0) and the **electric set
  {0x10,0x11,0x12,0x13,0x1a,0x1b,0x1d,0x1e}** (availableElectricity u16==0).
- **The save/restore surface**: hb_20 emits the Blockhead save dictionary (keys: name,
  skinOptions, state (dataWithBytes:length:), doubleTimeUnlocked, clothingIncrementTimer
  [0x7dc], interactionItemSubIndex/Index, selectedToolIndex, crystal discrepancy pair,
  actions, finalGoalSquare.x/.y, loadRequiresRecalculation, chasingBoat +
  lastKnownBoatPosition, attackingNPC + lastKnownNPCPosition, interactionObjectDict,
  tradeMissionData) and forwards to the workbench/interaction object's getSaveDict;
  hb_42 restores via the [self+0x814] dict keyed 'uniqueID' and
  blockheadWouldLikeToTakeOwnership:withSaveDict:; hb_07's warp gate keys
  'hasDisplayedBlockheadPromt_%d_%@' and the obfuscated
  '7acfe93afc08%dc65ae2c54ecaf07f' (stringFromMD5 check).
- **The second-blockhead warp cost table** (hb_07): expertMode off; count <
  min(customRules byte 0x33, 5); target food type [world distanceOrderedFoodTypes][count]
  == warp class 0x20 (item 0xb exempt); >=5 matching inventory; crystal cost 50 default,
  100 at count==2, 200 at count 3-4.
- **The sound table**: tradeJobAbort.wav (abortCraft), fireShort.wav (addToJetFuel),
  toolBreak.wav (usage breakage), tear.wav (armor breakage), fanfare.wav
  (craft-complete button), noPath.wav + elevatorBell.wav (setPath
  no-path/elevator branches), yawnMale/yawnFemale.wav (stopInteracting from sleep).
- **The interaction resolver inventory** (hb_37, 8735w / 976 branches / 472 call sites):
  free-block pickup (canPickUpItemOfType:subItems:dataA:dataB: + priorityBlockhead +
  sortedArrayUsingComparator), interaction objects (interactionObjectAtPos: +
  canBeUsedByBlockhead: + canBeUsedInExpertModeWhenNotOwned + the ownership/trade dict
  keys), and the whole per-type probe fleet (eggAtPos:/breed, checkForTrainCarUnderTap:,
  wire/window/blockhead/torch/column/painting/ladder AtPos:, elevatorShaft/elevatorMotor,
  stairsAtPos:, doorAtPos:, canDigBackWallforTile:...) with [tile+0xb] x66 / [tile+0xc]
  x19 occupancy probes.
- **VFP immediate decoding hazard (tooling finding)**: r2 mis-decodes `vmov.f32/f64`
  immediate encodings across this batch - **50 sites**. GNU cross-check (_gl.txt) is the
  truth: imm8 #36=10.0, #96=0.5, #120=1.5, #80=0.25, #8=3.0, #16=4.0, #112=1.0,
  #240=-1.0, #224=-0.5, f64 #0=2.0. Decoding the fuel gauge (hb_41) or the hurry-cost
  exponent (hb_28: powf(2*total, **0.5**)) from the r2 text alone gives wrong constants.
- **Scale**: 56 bodies / 32,709 verified words (gen_listings prints: bodies 56 words 32709); the big eight: hb_37 8735w / 976 br,
  hb_34 4047w (master ctor, super2 + 3x InventoryItem init + first-spawn grant),
  hb_43 2669w (queue writer), hb_49 1919w (interaction starter, 'grp.donkey'/'grp.boat'
  ride groups), hb_22 1433w, hb_20 1391w, hb_18 1220w, hb_11 1033w.

## Boundaries

- Census-grade bodies (call/const/offset histograms + head/tail windows; the branch
  trees are in the listings): hb_11, hb_18, hb_20, hb_22, hb_33, hb_34, hb_37, hb_43, hb_49.
- Census-lite (key constants and call inventories recorded): hb_07, hb_09, hb_13,
  hb_27, hb_29, hb_39, hb_48.
- Not expanded line-by-line: hb_34's member-by-member init order; hb_33's front-action
  rewire inner loop and hb_22's per-code arm bodies; hb_07's helpers 0xb95d44
  (food-type -> item map) and 0xc5f4c0 (warp classifier) are characterized by call site
  only; hb_37's per-branch interaction codes are recorded as constants, not decoded
  branch by branch.
- Offset convention: ivar offsets are absolute (from OBJC_IVAR symbols); shorthand
  [self+4]/[self+0]/[state+N] denote fields of the `state` ivar block ([self+0x38]),
  following the E124 BLOCKHEAD.md convention.
- The listings carry literal-pool words after each body (r2 prints them as junk
  mnemonics); counts in this file are body-instruction counts within the exidx bounds.
