# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 28977 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wv_00 | WorldUI -[.cxx_construct] | 0x00cffd68 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| wv_01 | WorldUI -[aBasketIsOpen] | 0x00cff838 | 176 | 3 | 1 | 3 | 0 | 6 | 12 |
| wv_02 | WorldUI -[acceptDragItems:assignSlot:] | 0x00cf9258 | 863 | 20 | 1 | 16 | 1 | 32 | 28 |
| wv_03 | WorldUI -[activeBlockheadInventoryChanged:inventoryIndex:] | 0x00cebc7c | 191 | 8 | 1 | 1 | 0 | 10 | 7 |
| wv_04 | WorldUI -[blockheadButton:] | 0x00cfcf34 | 217 | 3 | 1 | 4 | 0 | 7 | 8 |
| wv_05 | WorldUI -[blockheadCountChanged] | 0x00ce1930 | 409 | 7 | 1 | 3 | 0 | 12 | 11 |
| wv_06 | WorldUI -[blockheadMapButton:] | 0x00cff074 | 166 | 4 | 1 | 1 | 0 | 7 | 8 |
| wv_07 | WorldUI -[button:] | 0x00cfb644 | 1398 | 26 | 2 | 15 | 1 | 60 | 68 |
| wv_08 | WorldUI -[canDragCurrentItemsToButtonAtIndex:subIndex:] | 0x00cf2e2c | 632 | 7 | 1 | 3 | 0 | 47 | 40 |
| wv_09 | WorldUI -[canZoomCameraToOtherPlayer] | 0x00cfec68 | 52 | 3 | 1 | 1 | 0 | 3 | 0 |
| wv_10 | WorldUI -[cancelChestDrag] | 0x00cf9fd4 | 285 | 5 | 1 | 11 | 0 | 8 | 8 |
| wv_11 | WorldUI -[chatButton:] | 0x00cfb310 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| wv_12 | WorldUI -[chatNotificationsShouldBeSupressed] | 0x00cffaf8 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| wv_13 | WorldUI -[chestUI] | 0x00cffb60 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_14 | WorldUI -[closeAllButtons] | 0x00cf5594 | 184 | 3 | 1 | 3 | 0 | 6 | 6 |
| wv_15 | WorldUI -[crystalCountChanged:] | 0x00cfd938 | 883 | 9 | 3 | 6 | 2 | 28 | 25 |
| wv_16 | WorldUI -[dealloc] | 0x00ce1584 | 235 | 2 | 2 | 15 | 1 | 16 | 0 |
| wv_17 | WorldUI -[displayCameraFlash] | 0x00cfec20 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_18 | WorldUI -[dragActive] | 0x00cffc70 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_19 | WorldUI -[dragTextShowsHoldInfo] | 0x00cffcac | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_20 | WorldUI -[endInventoryDragWasCancelled:] | 0x00cf3998 | 1270 | 24 | 2 | 23 | 1 | 42 | 42 |
| wv_21 | WorldUI -[endTouch:paused:wasCancelled:index:] | 0x00cfa448 | 946 | 9 | 1 | 17 | 0 | 41 | 36 |
| wv_22 | WorldUI -[endTouch:wasCancelled:index:] | 0x00cf61d8 | 38 | 1 | 0 | 0 | 0 | 1 | 0 |
| wv_23 | WorldUI -[flashInventoryAtIndex:subIndex:color:] | 0x00cfe9d0 | 148 | 4 | 1 | 4 | 0 | 7 | 7 |
| wv_24 | WorldUI -[initWithWorld:uiManager:windowInfo:cache:client:server:] | 0x00cddc10 | 3467 | 54 | 27 | 35 | 13 | 127 | 51 |
| wv_25 | WorldUI -[inventoryButtonsAreOnBottom] | 0x00ce1f94 | 85 | 0 | 0 | 1 | 0 | 0 | 3 |
| wv_26 | WorldUI -[moveTouch:index:] | 0x00cf6154 | 33 | 1 | 0 | 0 | 0 | 1 | 0 |
| wv_27 | WorldUI -[moveTouch:paused:index:] | 0x00cf6de8 | 1426 | 22 | 3 | 34 | 1 | 59 | 50 |
| wv_28 | WorldUI -[multiplayerButton:] | 0x00cff700 | 35 | 1 | 1 | 1 | 0 | 1 | 0 |
| wv_29 | WorldUI -[netBlockheadMapButton:] | 0x00cff30c | 227 | 6 | 1 | 2 | 0 | 13 | 8 |
| wv_30 | WorldUI -[netPlayerButton:] | 0x00cfd298 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| wv_31 | WorldUI -[pauseButton:] | 0x00cfcc84 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| wv_32 | WorldUI -[playersChanged] | 0x00cffce8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_33 | WorldUI -[portalButton:] | 0x00cfed38 | 207 | 5 | 1 | 2 | 0 | 12 | 8 |
| wv_34 | WorldUI -[render:translation:pinchScale:paused:] | 0x00ce3e68 | 4431 | 72 | 11 | 42 | 7 | 155 | 113 |
| wv_35 | WorldUI -[renderBackgroundItems:paused:] | 0x00ce90f8 | 1994 | 27 | 2 | 19 | 2 | 80 | 47 |
| wv_36 | WorldUI -[renderCameraInstrcutionalView:] | 0x00ceb020 | 352 | 7 | 2 | 4 | 2 | 15 | 7 |
| wv_37 | WorldUI -[renderFrontItems:] | 0x00ceb5a0 | 345 | 5 | 1 | 5 | 0 | 24 | 2 |
| wv_38 | WorldUI -[resetAutoDissapearNetPlayerButtonsTimer] | 0x00cff78c | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_39 | WorldUI -[selectBlockheadButtonAtIndex:] | 0x00cfccec | 146 | 4 | 1 | 4 | 0 | 5 | 3 |
| wv_40 | WorldUI -[selectInventoryButtonAtIndex:] | 0x00cfb378 | 168 | 5 | 1 | 1 | 0 | 9 | 7 |
| wv_41 | WorldUI -[selectToolAtIndex:] | 0x00cebb04 | 94 | 2 | 1 | 3 | 0 | 3 | 1 |
| wv_42 | WorldUI -[selectedBlockheadNameWasChanged] | 0x00cff7d4 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| wv_43 | WorldUI -[setActiveBlockhead:dontFollow:] | 0x00cfd3f8 | 336 | 9 | 1 | 5 | 0 | 14 | 12 |
| wv_44 | WorldUI -[setAlwaysDisplayAllSubItems:] | 0x00cfe704 | 179 | 2 | 1 | 3 | 0 | 5 | 8 |
| wv_45 | WorldUI -[setChestFromDragItems:dragPos:holdState:] | 0x00cf1468 | 59 | 3 | 0 | 1 | 0 | 3 | 0 |
| wv_46 | WorldUI -[setChestUI:] | 0x00cffba4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_47 | WorldUI -[setPlayersChanged:] | 0x00cffd24 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_48 | WorldUI -[setServer:] | 0x00ce1458 | 75 | 1 | 1 | 3 | 0 | 2 | 1 |
| wv_49 | WorldUI -[setTradingPostSellUI:] | 0x00cffc2c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_50 | WorldUI -[startInventoryDragAtPos:] | 0x00cf2114 | 838 | 21 | 2 | 15 | 2 | 37 | 27 |
| wv_51 | WorldUI -[startTouch:tapCount:index:] | 0x00cf60bc | 38 | 1 | 0 | 0 | 0 | 1 | 0 |
| wv_52 | WorldUI -[startTouch:tapCount:paused:index:] | 0x00cf6270 | 734 | 7 | 1 | 18 | 0 | 22 | 41 |
| wv_53 | WorldUI -[tap:] | 0x00cf5874 | 530 | 6 | 1 | 5 | 0 | 23 | 26 |
| wv_54 | WorldUI -[textToggleButtonTappedForButton:] | 0x00cfd2b0 | 24 | 1 | 1 | 0 | 0 | 1 | 2 |
| wv_55 | WorldUI -[timeCrystalButton:] | 0x00cfcc1c | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| wv_56 | WorldUI -[touchIsInUI:] | 0x00cf4d70 | 521 | 6 | 1 | 10 | 0 | 21 | 35 |
| wv_57 | WorldUI -[tradingPostSellUI] | 0x00cffbe8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wv_58 | WorldUI -[uiShouldBeDisplayedForCurrentBlockhead] | 0x00ce3cd4 | 101 | 3 | 1 | 2 | 0 | 3 | 3 |
| wv_59 | WorldUI -[updateActiveDragRectAtPos:] | 0x00cebf78 | 180 | 2 | 0 | 2 | 0 | 4 | 7 |
| wv_60 | WorldUI -[updateActiveDragTextAtPos:holdState:] | 0x00cec248 | 423 | 11 | 5 | 5 | 3 | 21 | 14 |
| wv_61 | WorldUI -[updateButtonAtIndex:subIndex:withItem:] | 0x00cf1d98 | 63 | 3 | 1 | 1 | 0 | 3 | 2 |
| wv_62 | WorldUI -[updateButtonAtIndex:withItem:] | 0x00cf1c38 | 88 | 4 | 1 | 1 | 0 | 4 | 4 |
| wv_63 | WorldUI -[updateDragFromButtonAndCount] | 0x00cf1e94 | 160 | 5 | 1 | 4 | 0 | 7 | 4 |
| wv_64 | WorldUI -[updateJetPackButtonIfNeeded] | 0x00cf1554 | 441 | 14 | 3 | 5 | 1 | 21 | 13 |
| wv_65 | WorldUI -[updatePotentialDrag:fromDragSlot:dragItems:] | 0x00cf8430 | 906 | 15 | 2 | 12 | 1 | 40 | 29 |
| wv_66 | WorldUI -[useButton:] | 0x00cff698 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| wv_67 | WorldUI -[windowInfoChanged:] | 0x00ce20e8 | 1787 | 16 | 2 | 14 | 0 | 53 | 47 |
| wv_68 | WorldUI -[zoomButtonTappedForButton:] | 0x00cfd310 | 58 | 3 | 1 | 1 | 0 | 3 | 1 |

## Findings (E135)

**Batch: WorldUI, 69 bodies / 28,977 words** (listings wv_00..wv_68, all class WorldUI,
plus the inline helpers it calls: 0xce1394/0xce13e0/0xce142c). WorldUI is the in-world HUD
controller: the inventory tray and drag layer, the button rows (blockheads, map/portal,
net-player strip), the time-crystal counter, the instructional/tip views and the three
render passes. This is the class's first evidence batch - none of the 69 bodies was
previously covered. Seven bodies are census-tier (>1000w, 15,773w = 54.4% of the batch):
wv_34 render:translation:pinchScale:paused: (4,431w), wv_24 initWithWorld:... (3,467w),
wv_35 renderBackgroundItems:paused: (1,994w), wv_67 windowInfoChanged: (1,787w),
wv_27 moveTouch:paused:index: (1,426w), wv_07 button: (1,398w), wv_20
endInventoryDragWasCancelled: (1,270w); 15 more are 300-1,000w (census-lite where
noted) and 47 are <=300w and were read in full.

- **The WorldUI ivar map is pinned (ELF, OBJC_IVAR_$_WorldUI.*, 61 named slots).**
  Layout: world@4, uiManager@8, itemsTexture@12, currentBlockhead@16, client@20, server@24,
  touchIndex@28, multiplayerButton@32, netPlayerButtons@36, netPlayerButtonsActiveTimer@40,
  netPlayerButtonsAnimationTimer@44, orthoMatrix@48 (64B), windowInfo@112, cache@116,
  timeCrystalButton@120, timeCrystalImage@124, timeCrystalText@128, flashShader@132,
  tcFlashAlpha@136, pauseButton@140, inventoryButtons@144, selectedInventoryButton@148,
  selectedInventoryIndex@152, jetPackButton@156, blockheadButtons@160,
  selectedBlockheadButton@164, selectedBlockheadIndex@168, preDragItemCount@172,
  dragToButton@176, dragToIndex@180, dragToSubIndex@184, dragFromIndex@188,
  dragFromSubIndex@192, dragItems@196, fromDragSlot@200, activeDragText@204,
  dragTextShowsHoldInfo@208, dragActive@209, dragIsInsideInitialButton@210,
  timeSinceMovement@212, dragLocation@216, incrementTimer@224, speedTimer@228,
  alwaysDisplayAllSubItems@232, alwaysDisplayAllSubItemsDueToHandTapped@233, tapCount@236,
  chestUI@240, tradingPostSellUI@244, vignetteShader@248, fastForwardArrowTexture@252,
  fastForwardShader@256, fastFowardTimer@260 [sic], instructionalTextView@264,
  cameraFlashAlpha@268, cameraFlashShader@272, savedToAlbumTextTimer@276 (the only named
  slot not touched by this batch), playersChanged@280, portalMapButtons@284,
  blockheadMapButtons@288, netBlockheadMapButtons@292, useButton@296. All accesses go
  through the dynamic ivar-offset GOT cells (`ldr rX,[cell]; ldr rX,[rX,base]; ldr rY,[rX]`
  = offset; add to self), so the map is symbol-backed, not pattern-guessed.

- **Touch pipeline (three entry points + three forwarders).** startTouch:tapCount:paused:index:
  (wv_52) gates on touchIndex@28 == -1 and !paused, resets dragFromIndex/SubIndex to -1,
  stores tapCount@236 and dispatches in order: useButton, timeCrystalButton, pauseButton ->
  (if uiShouldBeDisplayedForCurrentBlockhead) inventoryButtons@144 -> jetPackButton@156 ->
  netPlayerButtons@36 -> timeCrystalButton (while netPlayerButtonsAnimationTimer@44 < 0.01f)
  -> blockheadButtons@160; every hit stores touchIndex = index and returns YES.
  moveTouch:paused:index: (wv_27) and endTouch:paused:wasCancelled:index: (wv_21) mirror the
  same index gate, clear touchIndex on the end, and forward to the same widget list plus the
  three overlay dictionaries (portal/blockhead/netBlockhead, values via objectForKey:).
  The no-pause variants wv_51 / wv_26 / wv_22 are pure forwarders that pass paused=0. All
  positions are adjusted as pos - windowInfo(+8/+0xc) first.

- **Drag & drop engine.** startInventoryDragAtPos: (wv_50) hit-tests buttons (index >= 1
  only; slot 0 excluded), fills dragItems@196 + preDragItemCount@172 + fromDragSlot@200 and
  flips dragActive@209; the hover tracker wv_65 (updatePotentialDrag:fromDragSlot:dragItems:)
  fast-enumerates inventoryButtons twice to retarget dragToButton@176 / dragToIndex@180 /
  dragToSubIndex@184 and plays the tick sound; wv_02 acceptDragItems:assignSlot: is the drop
  router ([currentBlockhead moveInventoryItemsFromArray:...count:-1...], itemType 0xb(11)
  items excluded from the addItemToInventory: pass); wv_20 endInventoryDragWasCancelled: is
  the drag-end handler (drop via moveInventoryItems.../dropInventoryItemsAtIndex:subIndex:
  count:ignoreFreeblocks: when fromDragSlot == -1, then full drag-state reset); wv_08
  canDragCurrentItemsToButtonAtIndex:subIndex: is the legality test (slot 0 subIndex 0..3 =
  worn-on-feet/legs/torso/head via itemTypeCanBeWornOn*; elsewhere empty-type or
  itemTypeIsStackable + <99 + same-type merge, itemTypeSubItemsCanBeModifiedWhileCarried
  gated). State helpers: wv_10 cancelChestDrag, wv_14/wv_44 (byte232/233 sub-item display
  flags + dismissSubButtonUI), wv_45 setChestFromDragItems:dragPos:holdState: (autorelease
  old / retain new / updateActiveDragTextAtPos:holdState:), wv_23 flashInventoryAtIndex:
  subIndex:color:, wv_59 updateActiveDragRectAtPos: (256x32 label rect at pos.y+48, clamped
  against windowInfo fields), wv_60 updateActiveDragTextAtPos:holdState: (label rebuild;
  itemType 0x5b(91) dodo-egg uses dataB + prefixNameForDodoBreed).

- **Button rows and slots.** 8 inventory slots (wv_61/wv_62/wv_63 update chains;
  index == 0 special-cases updateJetPackButtonIfNeeded; subIndex == 2 == jetpack slot in
  wv_61); wv_07 button: is the tap router (jetpack button, chest/trading-post routing,
  tool select via uiManager selectedToolChanged:/toolWasTapped:, sub-button assignment via
  acceptDragItems:assignSlot:YES); up to 8 blockheadButtons (wv_04 blockheadButton:, wv_39
  selectBlockheadButtonAtIndex:, wv_43 setActiveBlockhead:dontFollow: - all three end with
  the uiManager selectedBlockheadChanged:forceUpdate:dontFollow: announcement; wv_43 also
  sends blockheadInventoryChanged:inventoryIndex:-1 itemWasAddedOrRemoved:1); wv_40
  synthesizes startTouch:/endTouch: on the selected inventory button (5x frame trick);
  wv_41 selectToolAtIndex: = highlight/selection keeper.

- **Map buttons and zoom.** The three dictionary rows (portalMapButtons@284,
  blockheadMapButtons@288, netBlockheadMapButtons@292) are index -> button maps:
  wv_06/wv_29/wv_33 scan them (objectForKey: + intValue) and reconstruct a world position as
  x = v % (worldWidthMacro<<5), y = v / (worldWidthMacro<<5), then call
  [world zoomToPos:makeIntpair(x,y) pinchZoom:1] / [world zoomToPortalAtPosition:pair] /
  [world zoomToActiveNetBlockheadForPlayer:[button playerID]] (wv_68, gated by
  [button local]); wv_53 tap: synthesizes startTouch:+endTouch: on whichever map button
  answers (and closes all buttons when [world mapVisible]).

- **Layout system.** orientation/layout booleans come from windowInfo byte flags (+0xde/+0xdf)
  and the float pair vs 415.0f (wv_25 inventoryButtonsAreOnBottom; wv_05/wv_24/wv_67 reuse
  them); rects are built everywhere through the local 4-float store helper 0xce1394
  (60 calls batch-wide; 0xce13e0 x4 and 0xce142c x3 are its 4-float/2-float siblings); the
  drag label is 256x32 at pos.y+48; button sizes/offsets are the 0x28/0x24/0x2c/0x50/0x16/
  0x12/0xc/0x78 family with __aeabi_idiv centering.

- **Render passes.** wv_34 render:translation:pinchScale:paused: (4,431w, census) = the HUD
  frame: layout/update + drag continuation + the child-widget render calls
  (renderFrame:projectionMatrix: x2, renderFrame:projectionMatrix:animationTimer:,
  renderFrame:projectionMatrix:translationOffset:scale:) under GL state setup (attrib
  arrays 0/1, GL_BLEND=0xbe2, glUniformMatrix4fv/glUniform4f/glUniform1i, drawShaderQuad/
  drawShaderQuadNoTexture, blend (1, 0x303=GL_ONE_MINUS_SRC_ALPHA), GL_TEXTURE_2D=0xde1);
  wv_35 renderBackgroundItems:paused: (1,994w, census) = vignette + button rows + the
  currentTipText bar + the fast-forward arrow (fastForwardShader/fastFowardTimer); wv_37
  renderFrontItems: = the drag label pass + the camera-flash quad whose alpha decays per
  frame; wv_36 renderCameraInstrcutionalView: = the instructional text view (rebuild on
  string change). wv_16 dealloc releases 15 ivars by hand in fixed order then
  objc_msgSendSuper2(dealloc); wv_24 is the single constructor building every widget.

- **Class-level helpers referenced by this batch** (all verified in prior batches):
  itemTypeIsStackable, itemTypeCanBeWornOn{Feet,Legs,Torso,Head},
  itemTypeSubItemsCanBeModifiedWhileCarried, texCoordsForItemType, prefixNameForDodoBreed,
  tileAtWorldPositionLoaded, worldIndexAtWorldPos, makeIntpair, plus delegation to
  World (dynamicWorld/blockheads/mapVisible/zoomTo*/pauseButtonTapped/chatButton/
  playerUIIsDisplayed/timeCrystalButtonTapped), DynamicWorld (activeBlockhead/blockheads),
  Blockhead (inventoryItems/selectedToolIndex/updateName/requiresMotionEvents/onTradeMission/
  regenerating/moveInventoryItemsFromArray:...), the uiManager announcement quartet
  (selectedBlockheadChanged:forceUpdate:dontFollow:, blockheadInventoryChanged:...,
  selectedToolChanged:, toolWasTapped:, useButtonTapped, showJetPackUIForActiveBlockhead).

## Boundaries

- **Census tier (not instruction-by-instruction)**: wv_34 (4,431w), wv_24 (3,467w),
  wv_35 (1,994w) and wv_67 (1,787w) were decoded from full call/selector/ivar/constant
  censuses plus targeted windows - the branch trees and per-widget call ordering inside the
  merged layout/render regions were not all traced to the instruction; the full listings
  remain the ground truth. wv_27 (1,426w), wv_07 (1,398w) and wv_20 (1,270w) are
  census-lite (structure + key seams verified).
- **Census-lite list** (structure + key seams verified, argument shuffles not exhaustively
  traced): wv_02, wv_05, wv_07, wv_15, wv_20, wv_21, wv_27, wv_36, wv_50, wv_60, wv_64,
  wv_65.
- **Positional windowInfo fields**: the float fields at +0/+4/+8/+0xc and the byte flags at
  +0xde/+0xdf are described positionally (the WindowInfo struct field names are not recovered
  in this batch); the 415.0f constant (0x43cf8000, pool at 0xce1cac) and the 0.01f timer
  thresholds (0x3c23d70a at 0xcf6dcc / 0xcf5568) were read straight from the ELF.
- **wv_40 double frame read**: both objc_msgSend_stret calls use the selector ``frame`` on
  the same button; the 5.0 scale multiplies the second read's floats - recorded literally,
  the identity of the two reads (frame vs sub-frame) is not further resolved.
- **wv_02 argument packing**: the moveInventoryItemsFromArray:... call is read with the -1
  sentinel for count and the movedItems array; individual stack-arg slots are observed but
  not byte-traced across the two branches.
- **wv_15 CrystalManager identity**: the class used by crystalCountChanged: resolves through the
  constants/class cell route (ffe2bb7c); the amount/amountString/instance selectors are verified, the exact
  class name was not printed from a symbol.
- **Unresolved literals**: itemType 0x5b(91) = the dataB-carrying dodo egg (prefixNameForDodoBreed
  path) and itemType 0xb(11) (excluded from the inventory add pass in wv_02) are observed
  constants; their game meanings are not independently confirmed here. wv_54 returns
  [button local] through converging comparison arms.
- **Static evidence only**: no runtime execution was performed for this batch; GL/UI
  contracts are asserted at the selector level. IVar offsets come from the ELF dynsym
  (61 named slots); unnamed gaps between them (e.g. @52-108 beyond orthoMatrix@48+64,
  @220, @273-275) are not enumerated.
- Listings regenerate byte-identically from the pinned r2 recipe against the pinned
  libApplication.so (sha256 733d8210...); per-body words = (end - imp)/4 from the
  ARM.exidx-bounded ranges, census-tier boundaries reported in each semantics entry.
