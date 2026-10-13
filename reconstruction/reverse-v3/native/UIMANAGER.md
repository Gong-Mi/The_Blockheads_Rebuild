# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 21484 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| um_00 | UIManager -[addBlockheadUI] | 0x00ade688 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_01 | UIManager -[addFuelUI] | 0x00ade7dc | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_02 | UIManager -[blockhead:tookOwnershipOfInteractionObject:] | 0x00ad0e70 | 728 | 12 | 1 | 11 | 0 | 33 | 35 |
| um_03 | UIManager -[blockheadCountChanged] | 0x00ad94f4 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| um_04 | UIManager -[blockheadInventoryChanged:inventoryIndex:itemWasAddedOrRemoved:] | 0x00acccdc | 340 | 7 | 1 | 11 | 0 | 17 | 10 |
| um_05 | UIManager -[blockheadReachedAddFuelDestination:workbench:] | 0x00ad0560 | 63 | 3 | 1 | 1 | 0 | 3 | 0 |
| um_06 | UIManager -[blockheadReachedCraftDestination:craftingItem:craftingObject:count:] | 0x00ad065c | 135 | 4 | 1 | 5 | 0 | 6 | 1 |
| um_07 | UIManager -[blockheadUI] | 0x00ade754 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_08 | UIManager -[blockheadWasRemoved] | 0x00ad9558 | 68 | 3 | 1 | 2 | 0 | 3 | 0 |
| um_09 | UIManager -[cameraUI] | 0x00ade9b8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_10 | UIManager -[canDisplayAd] | 0x00adc3d8 | 38 | 0 | 0 | 2 | 0 | 0 | 1 |
| um_11 | UIManager -[chatNotificationsShouldBeSupressed] | 0x00ade014 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| um_12 | UIManager -[chestUI] | 0x00ade710 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_13 | UIManager -[craftProgressUI] | 0x00ade798 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_14 | UIManager -[craftUI] | 0x00ade4f8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_15 | UIManager -[currentTouchIsInAnyButtons] | 0x00ade370 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_16 | UIManager -[currentTouchIsInInventoryButtons] | 0x00ade2f0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_17 | UIManager -[customizeBlockheadUI] | 0x00adebd8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_18 | UIManager -[dealloc] | 0x00aca3c8 | 542 | 7 | 2 | 29 | 2 | 35 | 1 |
| um_19 | UIManager -[deleteTimers] | 0x00ad1a3c | 98 | 3 | 1 | 3 | 0 | 4 | 0 |
| um_20 | UIManager -[dismissJetPackUI] | 0x00addd4c | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| um_21 | UIManager -[displayCraftProgressUIForTradeMissionForBlockhead:] | 0x00ad0ac8 | 234 | 7 | 1 | 2 | 2 | 11 | 4 |
| um_22 | UIManager -[displayCraftProgressUIIfActiveBlockhead:workbench:] | 0x00ad0878 | 148 | 7 | 1 | 2 | 0 | 7 | 1 |
| um_23 | UIManager -[displayDismountUI] | 0x00ad53a0 | 89 | 4 | 1 | 2 | 0 | 4 | 0 |
| um_24 | UIManager -[displayInventoryFullPopUpForPos:] | 0x00adb6f4 | 85 | 4 | 1 | 2 | 0 | 4 | 0 |
| um_25 | UIManager -[displayPauseUIIfAble] | 0x00ad9284 | 114 | 2 | 1 | 6 | 1 | 2 | 4 |
| um_26 | UIManager -[displayRegenerateUIForBlockhead:] | 0x00adbd18 | 141 | 6 | 1 | 3 | 0 | 7 | 1 |
| um_27 | UIManager -[displaySignUIForSign:] | 0x00ad5504 | 281 | 12 | 5 | 2 | 1 | 9 | 1 |
| um_28 | UIManager -[displaySleepUIForBlockhead:] | 0x00adb8b4 | 141 | 6 | 1 | 3 | 0 | 7 | 1 |
| um_29 | UIManager -[dpad] | 0x00ade470 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_30 | UIManager -[dpadShouldBeHiddenDueToOtherUI] | 0x00adddb8 | 151 | 3 | 1 | 1 | 0 | 6 | 9 |
| um_31 | UIManager -[endTouch:wasCancelled:index:] | 0x00ad8644 | 411 | 6 | 1 | 10 | 0 | 14 | 16 |
| um_32 | UIManager -[flashInventoryAtIndex:subIndex:forBlockhead:color:] | 0x00adc2dc | 63 | 2 | 1 | 2 | 0 | 2 | 1 |
| um_33 | UIManager -[gameBlockingUIDisplayed] | 0x00ad91bc | 50 | 0 | 0 | 3 | 0 | 0 | 2 |
| um_34 | UIManager -[hideAnyHideableUI] | 0x00ad5e60 | 253 | 7 | 1 | 4 | 0 | 10 | 9 |
| um_35 | UIManager -[hideAnyHideableUIDueToActiveInteractionStopping] | 0x00ad6254 | 202 | 6 | 1 | 2 | 0 | 9 | 11 |
| um_36 | UIManager -[hideAnyHideableUIDueToPanAtPoint:] | 0x00ad657c | 386 | 14 | 2 | 5 | 1 | 20 | 16 |
| um_37 | UIManager -[hideInventoryFullPopup] | 0x00adb848 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| um_38 | UIManager -[hidePauseUI] | 0x00ade1f0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_39 | UIManager -[hidePauseUIIfAble] | 0x00ad944c | 42 | 0 | 0 | 2 | 0 | 0 | 3 |
| um_40 | UIManager -[hideRegenerateUIForBlockhead:] | 0x00adbf4c | 140 | 5 | 1 | 3 | 0 | 7 | 2 |
| um_41 | UIManager -[hideSleepUIForBlockhead:] | 0x00adbae8 | 140 | 5 | 1 | 3 | 0 | 7 | 2 |
| um_42 | UIManager -[hungerUI] | 0x00ade8ec | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_43 | UIManager -[iapCancelled] | 0x00ade11c | 53 | 2 | 1 | 2 | 0 | 3 | 0 |
| um_44 | UIManager -[iapCompleted] | 0x00ade07c | 40 | 2 | 1 | 1 | 0 | 2 | 0 |
| um_45 | UIManager -[initWithWorld:cache:windowInfo:] | 0x00ac8480 | 2002 | 23 | 3 | 34 | 28 | 93 | 7 |
| um_46 | UIManager -[inspectNPCTapped:] | 0x00ad3968 | 212 | 8 | 1 | 3 | 0 | 10 | 4 |
| um_47 | UIManager -[interactionObjectTapped:hasCancel:] | 0x00ad2c0c | 529 | 21 | 1 | 3 | 0 | 25 | 21 |
| um_48 | UIManager -[inventoryFullUI] | 0x00ade974 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_49 | UIManager -[inventoryIsOnRightOfScreen] | 0x00add6c8 | 73 | 0 | 0 | 1 | 0 | 0 | 2 |
| um_50 | UIManager -[jetPackUI] | 0x00ade820 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_51 | UIManager -[mapDisplayed] | 0x00ade270 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_52 | UIManager -[mapUI] | 0x00ade580 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_53 | UIManager -[moveTouch:index:] | 0x00ad8048 | 383 | 5 | 1 | 9 | 0 | 14 | 16 |
| um_54 | UIManager -[ownershipSignUI] | 0x00adea84 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_55 | UIManager -[paintingTapped:] | 0x00ad3cb8 | 414 | 16 | 1 | 3 | 0 | 19 | 12 |
| um_56 | UIManager -[panBlockingUIDisplayed] | 0x00ad9128 | 37 | 0 | 0 | 2 | 0 | 0 | 1 |
| um_57 | UIManager -[pauseUI] | 0x00ade53c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_58 | UIManager -[petUI] | 0x00adeb94 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_59 | UIManager -[playUIPopSound] | 0x00ad4330 | 47 | 3 | 2 | 0 | 1 | 3 | 0 |
| um_60 | UIManager -[regenerateUI] | 0x00ade8a8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_61 | UIManager -[reloadCraftUI] | 0x00adc17c | 88 | 4 | 1 | 2 | 0 | 4 | 1 |
| um_62 | UIManager -[render:projectionMatrix:cameraZ:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:pinchScale:mapAlpha:] | 0x00acac40 | 1842 | 29 | 2 | 25 | 3 | 65 | 69 |
| um_63 | UIManager -[ridableObjectTapped:hasCancel:] | 0x00ad3450 | 326 | 12 | 1 | 3 | 0 | 15 | 9 |
| um_64 | UIManager -[selectedBlockheadChanged:forceUpdate:dontFollow:] | 0x00acd22c | 3277 | 61 | 3 | 35 | 5 | 180 | 82 |
| um_65 | UIManager -[selectedToolChanged:] | 0x00ad4514 | 37 | 2 | 1 | 1 | 0 | 2 | 0 |
| um_66 | UIManager -[setCurrentTouchIsInAnyButtons:] | 0x00ade3ac | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_67 | UIManager -[setCurrentTouchIsInInventoryButtons:] | 0x00ade32c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_68 | UIManager -[setFuelUIShouldBeDisplayed:forBlockhead:fuelObject:] | 0x00adca90 | 116 | 4 | 1 | 2 | 0 | 5 | 4 |
| um_69 | UIManager -[setHidePauseUI:] | 0x00ade22c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_70 | UIManager -[setInventoryUIToExpanded:] | 0x00ad1bc4 | 31 | 1 | 1 | 1 | 0 | 1 | 0 |
| um_71 | UIManager -[setMapDisplayed:] | 0x00ade2ac | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_72 | UIManager -[setServer:] | 0x00ad19d0 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| um_73 | UIManager -[showFreeOffers] | 0x00adca50 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_74 | UIManager -[showJetPackUIForActiveBlockhead] | 0x00addb7c | 116 | 6 | 1 | 3 | 0 | 6 | 0 |
| um_75 | UIManager -[showPetUIForPet:] | 0x00ad43ec | 74 | 4 | 1 | 1 | 0 | 4 | 0 |
| um_76 | UIManager -[showPurchaseDoubleTimeDialog] | 0x00adc9ec | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| um_77 | UIManager -[showTimeCrystalUITapped] | 0x00adc4dc | 52 | 1 | 1 | 3 | 0 | 1 | 1 |
| um_78 | UIManager -[showTimeCrystalUIWithRequiredCrystals:] | 0x00adc5ac | 163 | 8 | 4 | 3 | 2 | 10 | 5 |
| um_79 | UIManager -[showUIForActiveBlockheadReachingInteractionObject:] | 0x00ad9668 | 1699 | 31 | 2 | 20 | 1 | 77 | 60 |
| um_80 | UIManager -[showUIForTappedWorkbench:] | 0x00adb0f4 | 384 | 10 | 1 | 4 | 0 | 21 | 11 |
| um_81 | UIManager -[signTextUI] | 0x00adec1c | 54 | 0 | 0 | 1 | 0 | 0 | 11 |
| um_82 | UIManager -[sleepProgressUI] | 0x00ade864 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_83 | UIManager -[tap:] | 0x00ad6b84 | 479 | 18 | 2 | 7 | 1 | 23 | 23 |
| um_84 | UIManager -[tcUI] | 0x00ade5c4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_85 | UIManager -[tcUIDisplayed] | 0x00ade608 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_86 | UIManager -[timeCrystalCloseButtonTapped] | 0x00adc470 | 27 | 0 | 0 | 2 | 0 | 0 | 1 |
| um_87 | UIManager -[toolWasTapped:] | 0x00ad45a8 | 621 | 10 | 1 | 6 | 0 | 35 | 21 |
| um_88 | UIManager -[touchIsInUI:] | 0x00ad7300 | 274 | 3 | 1 | 6 | 0 | 10 | 19 |
| um_89 | UIManager -[tradeMissionUI] | 0x00adeb50 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_90 | UIManager -[tradePortalUI] | 0x00adeb0c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_91 | UIManager -[tradingPostBuyUI] | 0x00adea40 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_92 | UIManager -[tradingPostSellUI] | 0x00ade9fc | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_93 | UIManager -[updateChestUI] | 0x00adda78 | 65 | 3 | 1 | 1 | 0 | 3 | 1 |
| um_94 | UIManager -[updateTradePortalUIs] | 0x00add7ec | 163 | 4 | 1 | 3 | 0 | 8 | 2 |
| um_95 | UIManager -[useButtonTapped] | 0x00add260 | 282 | 9 | 1 | 4 | 0 | 15 | 17 |
| um_96 | UIManager -[useButtonTitle] | 0x00adcf34 | 203 | 6 | 2 | 4 | 0 | 10 | 10 |
| um_97 | UIManager -[useButtonVisibleAndEnabled] | 0x00adcc60 | 181 | 5 | 1 | 4 | 0 | 8 | 6 |
| um_98 | UIManager -[wearUI] | 0x00ade930 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_99 | UIManager -[windowInfoChanged:] | 0x00ad8cb0 | 286 | 4 | 1 | 8 | 0 | 12 | 5 |
| um_100 | UIManager -[workbenchChoiceUI] | 0x00ade644 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_101 | UIManager -[workbenchProgressBarUI] | 0x00adeac8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| um_102 | UIManager -[workbenchTapped:hasCancel:] | 0x00ad1c40 | 996 | 25 | 2 | 4 | 0 | 50 | 40 |
| um_103 | UIManager -[worldUI] | 0x00ade4b4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |

## Findings (E132)

**Batch: UIManager, 104 bodies / 21484 words** (listings um_00..um_103, all class
UIManager, 967 call rows / 592 branches / 14 route targets). This is the remainder of
the game UI manager: the five sibling bodies already carried by earlier evidence
(showCameraUI / dismissCameraUI / setDismissCameraUI: from the camera_ui batch,
startTouch:tapCount:index: and paintMixUI) are excluded; everything else in the class
lands here. Four census-tier bodies carry 41% of the words: `um_64 selectedBlockheadChanged:forceUpdate:dontFollow:`
(3277w / 82 branches), `um_45 initWithWorld:cache:windowInfo:` (2002w),
`um_62 render:...` (1842w / 69 branches) and `um_79 showUIForActiveBlockheadReachingInteractionObject:`
(1699w / 60 branches); `um_102 workbenchTapped:hasCancel:` (996w / 40 branches) is the
largest mid body.

- **The whole UIManager ivar map is now pinned** (45 ivars via `OBJC_IVAR_$_UIManager.*`,
  a contiguous 4..154 layout): world@4, dynamicWorld@8, cache@12, windowInfo@16; the
  panel views worldUI@20, pauseUI@24, mapUI@28, tcUI@32, dpad@36, workbenchChoiceUI@44,
  craftUI@48, newBlockheadUI@52, paintMixUI@56, chestUI@60, blockheadUI@64,
  craftProgressUI@68, addFuelUI@72, jetPackUI@76, sleepProgressUI@80, regenerateUI@84,
  hungerUI@88, wearUI@92, inventoryFullUI@96, cameraUI@100, signTextUI@104,
  tradingPostSellUI@108, tradingPostBuyUI@112, ownershipSignUI@116,
  workbenchProgressBarUI@120, tradePortalUI@124, tradeMissionUI@128, petUI@132,
  customizeBlockheadUI@136, the uiViews NSMutableArray@140; the state bytes/flags
  tcUIDisplayed@40, fuelInventoryItemTapped@144, pauseResumeTapped@146,
  dismissCameraUI@147, hidePauseUI@148, showTCUITapped@149, hideTCUITapped@150,
  showCameraUITapped@151, mapDisplayed@152, currentTouchIsInInventoryButtons@153,
  currentTouchIsInAnyButtons@154.

- **Accessor family (36 bodies)**: 27 identical object getters (Apportable offset-cell
  walk + getter `dmb ish`, e.g. worldUI@0xade4f0, dpad@0xade4ac, cameraUI@0xade9f4,
  signTextUI@0xadec58), 5 plain ldrsb byte getters (currentTouchIsInAnyButtons@154 etc.)
  and 4 atomic byte setters with `dmb ish` barriers around the strb
  (setCurrentTouchIsInAnyButtons:/setCurrentTouchIsInInventoryButtons:/setHidePauseUI:/setMapDisplayed:).
  `um_81 signTextUI` additionally fuses a UI-type classifier ({3, 0x1f} | {8} | {9, 0xe, 0xf} -> 3)
  into the exidx range.

- **The ctor `um_45`** builds the entire panel set in one run (DPad, TCUI, TradingPostSellUI,
  ChestUI, SleepProgressUI, CraftProgressUI, BlockheadUI, CustomizeBlockheadUI,
  InventoryFullUI, PetUI, JetPackUI, CraftUI, TradeMissionUI, TradePortalUI,
  WorkbenchProgressBarUI, OwnershipSignUI, TradingPostBuyUI(initWithWorld:windowInfo:cache:worldUI:),
  WearUI, HungerUI, RegenerateUI, AddFuelUI, PaintMixUI, NewBlockheadUI, WorkbenchChoiceUI,
  WorldUI(initWithWorld:uiManager:windowInfo:cache:client:server:)), registers each with
  addObject: into uiViews, installs the CrystalManager countWatcher, calls
  assignCraftProgressUIToLoadedWorkbenches:, and finishes with
  setActiveBlockhead:dontFollow:1 (asleep/meditating variants first).

- **The master selection sync `um_64`** (census) drives every panel from blockhead state:
  jetpack free-flight -> [world stopRiding]; hides the workbenchProgressBar/jetpack/
  inventoryFull/wear/fuel/hunger/blockhead panels; !dontFollow -> [world setFollowingBlockhead:];
  isCraftingAtAnyWorkbench -> craftProgressUI setCraftingItem:craftingObject:blockhead:count:
  (0x7c-byte record, memset fallback); onTradeMission -> TradeMissionManager
  craftableItemForMissionForBlockhead: -> CraftableItemObject initWithCraftableItem: -> the
  same fill; isAddingFuelToAnyWorkbench -> addFuelUI setDisplayed:1 + setFuelObject:blockhead:;
  asleep/meditating -> sleepProgressUI; regenerating -> regenerateUI; Chest -> chestUI
  setChest: + setAlwaysDisplayAllSubItems:; interactionObjectType==5 -> setTradingPost: by
  blockheadIsSeller:; isMissionInteraction -> tradeMissionUI setTradePortal:blockhead:;
  Mirror -> customizeBlockheadUI setDelegate:interactionObject:creationOptions:; signTextUI
  dialog dismissal; mapDisplayed/following tail with zoomToPos:pinchZoom:.

- **The object-tap routing family** (interactionObjectTapped: / ridableObjectTapped: /
  paintingTapped: / inspectNPCTapped: / workbenchTapped: / showUIForTappedWorkbench: /
  showUIForActiveBlockheadReachingInteractionObject:): every path shares the
  workbenchChoiceUI fill call `setDynamicObject:blockhead:hasCancel:hasRemove:hasActionButton:hasBanWithUsername:`,
  the center:/pinchScale/dimensions -> `zoomUIToOnscreen:dimensions:` camera framing
  (415.0f / 0x19f split), `setDisplayed:1` + `playUIPopSound`, the mod/ownership gate
  (isMod; server/client; ownerID vs localNetID isEqualToString:; ownerName;
  canBeRemovedByBlockhead:) and the interaction-type switch {2 chest, 4/6 sign, 5 trading
  post, 7 trade portal/mission, 8 ownership sign, 9 mirror/customize}. Workbench types
  0x14(20)/0x15(21) gate the craft panel; type 0xf(15) arms the fuel action.

- **The touch pipeline**: startTouch is already covered; this batch adds tap: (um_83),
  moveTouch:index: (um_53), endTouch:wasCancelled:index: (um_31), touchIsInUI: (um_88) and
  the button-zone flags (currentTouchIsInAnyButtons/currentTouchIsInInventoryButtons with
  their atomic setters). Shape: tcUIDisplayed / pauseUI(+hidePauseUI) / cameraUI /
  mapDisplayed special cases first, then a uiViews fast enumeration (0x10-byte state,
  0x20 count shape, objc_enumerationMutation guards), with the MenuDismiss sound
  (MJSoundManager multiSoundNamed:/play) on dismissals.

- **Hide/display and dialog crowd**: hideAnyHideableUI (+DueToActiveInteractionStopping,
  +DueToPanAtPoint:) drive canDismiss / dismissWhenBlockheadStopsInteracting /
  touchIsInViewAtAll: predicates with setDisplayed:0; displayPauseUIIfAble lazily allocates
  PauseUI (pauseResumeTapped handshake with hidePauseUIIfAble); displaySleepUI/
  displayRegenerateUI toggle setAlwaysDisplayAllSubItems: + hideAnyHideableUI;
  displaySignUIForSign: builds a BlockTextPromptAlertView (an alert with three CF strings + stack blocks);
  displayInventoryFullPopUpForPos: uses setBlockhead:pos:; displayDismountUI uses
  setBlockhead:type:5; the time-crystal flow is updateRequiredAmount: (-1 sentinel) + a
  BlockAlertView alert built with stringWithFormat:/uppercaseString + _Block_object_dispose, and the
  IAP pair (iapCompleted/iapCancelled) fans to tcUI/pauseUI with setHidePauseUI:0.

- **Stats**: 967 call rows (mostly objc_msgSend family through the GOT cells), 592
  in-body branches, 14 BL route targets, census-lite text for um_102/um_87/um_83 and
  stats-only boundaries for the four census bodies (census-grade, not per-instruction
  walkthroughs).

## Boundaries

- **Census-grade, not per-instruction**: the four bodies over 1000 words (um_45, um_62,
  um_64, um_79) are summarized at census level (full call histograms, complete cell maps,
  branch counts and structural constants via the evidence JSON); um_102 (996w) is the one
  largest body decoded from its full instruction stream at the same resolution as the
  rest.
- **Trailing literal pools inside listing spans**: every small listing ends with 2-20
  misdecoded pool words (`invalid` rows); two such words make the naive ldrsb scanner
  fire inside pool area (um_14 0xade538, um_92 0xadea3c) — they are pool data, not code.
- **Selector strings resolved from the ELF**: all `cell -> SEL/ivar/class` attributions
  come from the dynsym/reloc tables of the pinned libApplication.so (sha256 733d8210...),
  not from memory; two cells in um_27/um_78 print as "ELF"-garbage through the ad-hoc
  scanner but resolve cleanly in specs_uimanager.json (0xfff3bd14/0xfff3bd04
  __CFConstantStringClassReference; 0xffff2e1c/0xffff2dfc/0xffff2e3c _NSConcreteStackBlock
  family).
- **Pool floats read directly from the ELF** (file offset == vaddr): 415.0f = 0x43cf8000
  (um_49/um_79 split), -32.0f = 0xc2000000 (um_27/um_78), 0x52000000 word in um_78;
  0x19f(415) appears as the integer companion of the 415.0f compares.
- **Fused seams**: um_81 carries an adjacent helper in its exidx range; um_87 calls a
  non-ObjC helper at 0xad4f5c and um_102 calls one at 0xad2bd0 — both live in the gaps
  between the roster bodies and are documented as call targets, not decoded as members.
- **The five ex-batch siblings** (showCameraUI etc.) are referenced as call targets /
  ivar owners only; their bodies live in camera_ui.json and friends.
- No runtime behavior claims: this is a static bounded-body map; values observed at run
  time (which panels are actually up, real windowInfo numbers) are outside the batch.
