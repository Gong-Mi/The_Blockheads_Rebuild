# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 22053 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| mm_00 | MainMenuUI -[.cxx_construct] | 0x00a10360 | 80 | 0 | 0 | 6 | 0 | 6 | 1 |
| mm_01 | MainMenuUI -[IAPForWorldCreationOrTopupSucceeeded:transactionID:] | 0x00a0fdd0 | 68 | 2 | 1 | 2 | 0 | 2 | 2 |
| mm_02 | MainMenuUI -[appDatabase] | 0x00a0fee0 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_03 | MainMenuUI -[attemptingToConnectToWorld] | 0x00a101d8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_04 | MainMenuUI -[canDisplayAd] | 0x00a0fc64 | 65 | 0 | 0 | 4 | 0 | 0 | 3 |
| mm_05 | MainMenuUI -[cloudInterface] | 0x00a0ff44 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_06 | MainMenuUI -[cloudInterfaceIsReady] | 0x009f90cc | 55 | 2 | 1 | 2 | 0 | 2 | 0 |
| mm_07 | MainMenuUI -[cloudTopupFailed:] | 0x00a0fc4c | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| mm_08 | MainMenuUI -[cloudTopupSucceeded:] | 0x00a0fc30 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| mm_09 | MainMenuUI -[cloudWorldWasCreatedWithID:worldName:userName:userPhoto:timeSelection:] | 0x00a0f314 | 58 | 1 | 1 | 2 | 0 | 1 | 0 |
| mm_10 | MainMenuUI -[connected] | 0x009f7620 | 48 | 2 | 2 | 0 | 1 | 3 | 0 |
| mm_11 | MainMenuUI -[createWorldImmediately] | 0x00a0f288 | 35 | 1 | 2 | 1 | 0 | 1 | 0 |
| mm_12 | MainMenuUI -[createWorldPlayButtonTappedIsOnline:] | 0x00a0c7f0 | 125 | 5 | 1 | 3 | 0 | 5 | 2 |
| mm_13 | MainMenuUI -[createWorldUI] | 0x00a10294 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_14 | MainMenuUI -[crystalCountChanged:] | 0x00a0e40c | 704 | 9 | 3 | 4 | 2 | 24 | 17 |
| mm_15 | MainMenuUI -[currentMainMenuSelection] | 0x00a10214 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_16 | MainMenuUI -[dealloc] | 0x009fc874 | 444 | 8 | 2 | 21 | 2 | 28 | 2 |
| mm_17 | MainMenuUI -[defaultUserName] | 0x009f76e0 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| mm_18 | MainMenuUI -[deleteCurrentWorld] | 0x00a0cfe0 | 32 | 1 | 1 | 2 | 0 | 1 | 0 |
| mm_19 | MainMenuUI -[didDismissCreative:positiveActionTaken:] | 0x009fc3f4 | 71 | 2 | 1 | 0 | 1 | 2 | 2 |
| mm_20 | MainMenuUI -[didDismissMoreGames] | 0x00a0e2b0 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| mm_21 | MainMenuUI -[dismissAddCreditUI] | 0x00a0fbd4 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_22 | MainMenuUI -[dismissAlertViews] | 0x009fc610 | 153 | 3 | 1 | 6 | 0 | 8 | 0 |
| mm_23 | MainMenuUI -[dismissOptions] | 0x00a10070 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_24 | MainMenuUI -[doubleTimeRestoreTapped] | 0x00a100b0 | 49 | 3 | 1 | 1 | 1 | 3 | 0 |
| mm_25 | MainMenuUI -[doubleTimeUnlocked] | 0x00a0ff80 | 60 | 2 | 2 | 0 | 1 | 2 | 3 |
| mm_26 | MainMenuUI -[gameLaunchedWithUrlToJoinCloudWorldWithID:name:] | 0x00a0de90 | 124 | 3 | 1 | 7 | 0 | 3 | 0 |
| mm_27 | MainMenuUI -[gameLaunchedWithUrlToJoinHost:port:] | 0x00a0dca0 | 124 | 3 | 1 | 7 | 0 | 3 | 0 |
| mm_28 | MainMenuUI -[gameSavesChanged] | 0x009f91a8 | 128 | 4 | 1 | 5 | 1 | 4 | 1 |
| mm_29 | MainMenuUI -[hasRewardedVideoAvailable] | 0x00a0fd68 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_30 | MainMenuUI -[hostLANGameInCurrentWorld] | 0x00a0d1e4 | 169 | 7 | 1 | 3 | 0 | 7 | 2 |
| mm_31 | MainMenuUI -[iapCancelled] | 0x00a0ef70 | 45 | 2 | 1 | 2 | 0 | 2 | 0 |
| mm_32 | MainMenuUI -[iapCompleted] | 0x00a0f024 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_33 | MainMenuUI -[iapStarted] | 0x00a0ef0c | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_34 | MainMenuUI -[incentivizedVideoViewComplete:] | 0x00a0f12c | 31 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_35 | MainMenuUI -[initWithDelegate:windowInfo:cache:cloudInterface:] | 0x009f93a8 | 2904 | 45 | 31 | 43 | 17 | 149 | 32 |
| mm_36 | MainMenuUI -[isLoading] | 0x00a0d9c8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_37 | MainMenuUI -[isPauseMenu] | 0x00a0fc14 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| mm_38 | MainMenuUI -[joinCloudWorldAtHost:port:key:userName:pic:] | 0x00a0cf30 | 44 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_39 | MainMenuUI -[joinLanWorldButtonTapped] | 0x00a0ca4c | 97 | 3 | 1 | 3 | 0 | 3 | 1 |
| mm_40 | MainMenuUI -[joinOnlineWorldButtonTapped] | 0x00a0cbd0 | 216 | 10 | 4 | 3 | 1 | 10 | 3 |
| mm_41 | MainMenuUI -[joinWorldUI] | 0x00a102d8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_42 | MainMenuUI -[loadWorldPlayButtonTapped] | 0x00a0c3c8 | 266 | 7 | 7 | 4 | 0 | 13 | 7 |
| mm_43 | MainMenuUI -[loadWorldUI] | 0x00a10250 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_44 | MainMenuUI -[migrateCurrentWorldToCustomRules] | 0x00a0d060 | 32 | 1 | 1 | 2 | 0 | 1 | 0 |
| mm_45 | MainMenuUI -[moreGamesButton:] | 0x00a0e218 | 33 | 1 | 2 | 0 | 1 | 2 | 0 |
| mm_46 | MainMenuUI -[moveTouch:] | 0x00a0a4c4 | 595 | 3 | 1 | 19 | 0 | 14 | 28 |
| mm_47 | MainMenuUI -[multiplayerGameSelectCancelled] | 0x00a0da84 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_48 | MainMenuUI -[noodleNews:] | 0x009fc510 | 64 | 3 | 1 | 1 | 1 | 3 | 2 |
| mm_49 | MainMenuUI -[presentAddCreditUIForWorldWithName:worldID:currentCredit:] | 0x00a0f4c8 | 159 | 4 | 1 | 5 | 1 | 7 | 1 |
| mm_50 | MainMenuUI -[renameCurrentWorld:] | 0x00a0d0e0 | 65 | 3 | 1 | 2 | 0 | 3 | 1 |
| mm_51 | MainMenuUI -[render:projectionMatrix:] | 0x009fdf68 | 10738 | 42 | 9 | 93 | 1 | 247 | 205 |
| mm_52 | MainMenuUI -[searchCancelled] | 0x009f8294 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| mm_53 | MainMenuUI -[searchFailed:] | 0x009f824c | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_54 | MainMenuUI -[searchResultsReturned:] | 0x009f7ee4 | 218 | 6 | 2 | 2 | 1 | 9 | 8 |
| mm_55 | MainMenuUI -[selectJoinOption] | 0x00a0dac4 | 119 | 3 | 1 | 7 | 0 | 3 | 0 |
| mm_56 | MainMenuUI -[selectMostRecentlyPlayedWorld] | 0x00a0c014 | 237 | 3 | 1 | 8 | 0 | 3 | 4 |
| mm_57 | MainMenuUI -[setClockPositions] | 0x009f7710 | 475 | 1 | 0 | 5 | 0 | 10 | 7 |
| mm_58 | MainMenuUI -[setProgress:] | 0x00a0da04 | 32 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_59 | MainMenuUI -[settingsButton:] | 0x00a0e0d8 | 80 | 2 | 1 | 3 | 1 | 2 | 1 |
| mm_60 | MainMenuUI -[shareURL:message:fromRect:] | 0x00a0f3fc | 51 | 1 | 0 | 1 | 0 | 1 | 0 |
| mm_61 | MainMenuUI -[shouldDisplayAlertOnSearchFail] | 0x009f7ec8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| mm_62 | MainMenuUI -[showGDPRAlert] | 0x00a10174 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_63 | MainMenuUI -[showTimeCrystalPurcahseUI:] | 0x00a0e2c4 | 82 | 2 | 1 | 3 | 1 | 2 | 1 |
| mm_64 | MainMenuUI -[startAttemptingToConnectToWorld] | 0x00a0c9e4 | 26 | 0 | 0 | 1 | 0 | 0 | 1 |
| mm_65 | MainMenuUI -[startImagePickerWithDelegate:forRect:cropSize:] | 0x00a0f1a8 | 56 | 1 | 0 | 1 | 0 | 1 | 0 |
| mm_66 | MainMenuUI -[startIncentivizedVideo] | 0x00a0f0c8 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| mm_67 | MainMenuUI -[startSearchForCloudInfoFromWorldIndex:] | 0x009f8bf4 | 310 | 11 | 3 | 5 | 3 | 14 | 12 |
| mm_68 | MainMenuUI -[startWorldLoadingWithName:worldSize:isGenerating:] | 0x00a0d488 | 336 | 7 | 4 | 5 | 4 | 12 | 9 |
| mm_69 | MainMenuUI -[tcUI] | 0x00a1031c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_70 | MainMenuUI -[timeCrystalButton:] | 0x00a0e080 | 22 | 1 | 1 | 0 | 0 | 1 | 0 |
| mm_71 | MainMenuUI -[timeCrystalCloseButtonTapped] | 0x00a0f088 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_72 | MainMenuUI -[touchIsInUI:] | 0x00a09d70 | 32 | 0 | 0 | 1 | 0 | 0 | 0 |
| mm_73 | MainMenuUI -[updateCloudSearchInfo] | 0x009f8be0 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| mm_74 | MainMenuUI -[updateWorldTitles] | 0x009f82a8 | 560 | 16 | 6 | 4 | 4 | 36 | 9 |
| mm_75 | MainMenuUI -[willShowCreative:shouldMuteAudio:] | 0x009fc270 | 97 | 3 | 1 | 0 | 1 | 4 | 2 |
| mm_76 | MainMenuUI -[willShowMoreGames] | 0x00a0e29c | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| mm_77 | MainMenuUI -[windowInfoChanged:] | 0x009fcf64 | 1019 | 4 | 1 | 17 | 0 | 29 | 18 |

## Findings (E134)

- **The main-menu batch lands**: 78 bodies / 22053 words / 387 branches / 695 call rows of `MainMenuUI` (the 78 ledger rows not previously referenced; with the earlier 3 touch bodies (`touchIsInViewAtAll:` 0xa09cf0, `startTouch:tapCount:` 0xa09df0, `endTouch:` 0xa0ae40) the class is batched 81/81 at body level). The three heavy bodies are census-grade:

  | body | method | words | branches | calls |
  |---|---|---|---|---|
  | mm_35 | `MainMenuUI -[initWithDelegate:windowInfo:cache:cloudInterface:]` | 2904 | 32 | 149 |
  | mm_51 | `MainMenuUI -[render:projectionMatrix:]` | 10738 | 205 | 247 |
  | mm_77 | `MainMenuUI -[windowInfoChanged:]` | 1019 | 18 | 29 |

- **The full-class renderer** `render:projectionMatrix:` (mm_51, 10738w/205br/247 calls) is the menu frame: rotating background quad (uv seed -1.0f, orthoMatrix via 0x9fc108) -> star field (`getStarPoints` + `glDrawArrays`) -> 5 rotating clocks (clockPositions/HalfSizes/clockValues/clockSpeeds; `__wrap_fmodf` + `__modsi3`/`__aeabi_idiv`; 17 Vector + 17 Vector2 float* derivations) -> portal previews (`previewImageData` -> `CGDataProviderCreateWithData` with the `releasePixelsMainMenu` callback -> `CGImageCreate` -> `CPTexture2D initWithCGImage:orientation:sizeToFit:pixelFormat:mipmap:`, looped over portals) -> save-card titles (`BitmapString renderWithProjectionMatrix:`) -> sub-UI `renderFrame:projectionMatrix:` calls -> the loading UI. GL surface: 7x glUniformMatrix4fv, 7x glBindTexture, 6x drawShaderQuad, 5x glUniform1i, 3x glUniform4f + the 8 local sub-drawers 0xa08730..0xa09c7c.
- **The constructor** `initWithDelegate:windowInfo:cache:cloudInterface:` (mm_35, 2904w/149 calls): shader suite (StandardObject / StandardObjectColored / ColoredNoTexture / Star.vsh-fsh / PortalPreview.vsh-fsh + 'mask' uniform), textures (mainMenuBackground.png, clockFace.png, clockHand.png, TileMap.png, Items.png, InventoryButtonBackground(.Selected).png, settingsCog.png, portalPreviewMask.png, GameResources/), the three sub-UIs (LoadWorldUI / JoinWorldUI / CreateWorldUI initWithDelegate:windowInfo:cache:cloudInterface:), CrystalManager countWatcher wiring, the buttons (moreGamesButton 'MORE GAMES!', timeCrystalButton with the '' title + background textures, settingsButton with settingsCog.png glyph), the 'YOUR NAME' title, 8x lrand48 wrapper (0x9fc260) + 10x rect helper for the 5-clock init, the portal preview (basePortalPos/portalTexts/MJImageView), the GKLocalPlayer gate and a deferred `noodleNews:` via performSelector:withObject:afterDelay:.
- **windowInfoChanged:** (mm_77, 1019w) re-forwards to all five sub-UIs and rebuilds the whole layout (ortho matrix + setClockPositions + ~10 rect re-frames from windowInfo.actualDimensions).

- **The class layout (69 MainMenuUI ivars, resolved through the Apportable offset-cells)**: delegate +0x4, cloudInterface +0x8; renderer refs backgroundShader +0xc / starShader +0x10 / coloredTexturedShader +0x14 / coloredNoTextureShader +0x18 / portalPreviewShader +0x188, textures backgroundTexture +0x1c / clockTexture +0x20 / clockHandTexture +0x24 / tileTexture +0x2c / portalMaskTexture +0x190 / activePreviewTexture +0x18c (+index +0x194); titleTextView +0x28; mainMenuOptionsUI +0x30 (+needsToClose +0x34); orthoMatrix +0x40; windowInfo +0x80; cache +0x84; the 4 random Vector float sets (randomTimers +0x88 / angleSpeeds +0x98 / currentSpeeds +0xa8 / currentAngles +0xb8) and rotationTimer +0xc8; the 5 clocks (clockPositions +0xcc, clockHalfSizes +0xf4, clockTimers +0x108, clockSpeeds +0x11c, clockGoalSpeeds +0x130, clockValues +0x144); the scroll/list block (currentWorldIndex +0x158, currentScroll +0x15c, scrollVelocity +0x160, lastX +0x164, scrollInProgress +0x168, startTouchWasInView +0x169, scrollTargetIndex +0x16c, animationLoopIndex +0x170 / Timer +0x174); portal block (basePortalPos +0x178, portalTexts +0x180, latestCloudInfoSearchResultsByWorld +0x184, currentPortalOffset +0x1d8, portalMaskTexture +0x190); loading +0x198, progressBar +0x19c, loadingText +0x1a0; the crystal block (timeCrystalButton +0x1a4, timeCrystalImage +0x1a8, timeCrystalText +0x1ac); moreGamesButton +0x1b0, checkGoogleTimer +0x1b4, settingsButton +0x1b8; tcUI +0x1bc (+needsToClose +0x1c0); currentMainMenuSelection +0x1c4; loadWorldUI +0x1c8, createWorldUI +0x1cc, joinWorldUI +0x1d0, attemptingToConnectToWorld +0x1d4, gameListChanged +0x1d5; the credit block (addCreditUI +0x1dc, addCreditWorldID +0x1e0, addCreditWorldName +0x1e4, addCreditUINeedsDismissed +0x1e8, addCreditAlertView +0x1ec); tcPromptView +0x1f0; lastPlayerCountUpdateTime +0x1f8; searchingForPLayerCount +0x200.
- **Menu state machine**: `currentMainMenuSelection` 1=create, 2=join, 3=load (-1 = joining a world); `currentWorldIndex` -1 = none; `scrollTargetIndex` -2 and the render-side `cmn r0, 3` (-3) are additional sentinels; `attemptingToConnectToWorld` gates every join/host entry point.
- **Cloud sync chain**: `gameSavesChanged` (60.0s rate limit) and `cloudInterfaceIsReady` both re-issue `startSearchForCloudInfoFromWorldIndex:(currentWorldIndex-10)`; `startSearchForCloudInfoFromWorldIndex:` collects up to 20 not-yet-requested cloud saves (cloudGame==YES, 'saveID' keys, placeholder entries in latestCloudInfoSearchResultsByWorld) and hands them to `[cloudInterface startSearchForWorldsWithIds:searchDelegate:self]`; results come back through `searchResultsReturned:` (dict keyed by each element's 'wId') -> `updateWorldTitles`.
- **Strings/constants pinned**: defaultUserName 'YOUR NAME'; createWorldImmediately 'MY FIRST WORLD'; the credit-time formatter ladder (0xa0f744): 'NO CREDIT' / '< 1 MINUTE' / '%d MINUTES' / '%d HOUR%@, %d MINUTE%@' / '%d HOUR%@' / '%d DAY%@, %d HOUR%@' with 'S' plurals; the crystal display format '7acfe93afc08%dc65ae2c54ecaf07f' (+'%d'); 'INTERNET CONNECTION FAILED' / 'Please ensure you are connected to the internet.' / 'Cancel'; 'We shouldn't get here, this should be handled by LoadWorldUI'; 'More games!' + 'Spenny - Network reachability: %d' (NSLog); the double-time keychain entry 'com.majicjungle.blockheads.doubletime'; world-size labels 'SIZE : 4x' (2048) / 'SIZE : 16x' (8192); the scroll bound 415.0 and the x7.0/x5.0/x2.0 scroll constants.
- **Shared local helpers (non-ObjC, classified this batch)**: 0x9f7e7c = 5-arg rect builder (dst, x, y, w, h); 0x9fc108 = ortho-matrix builder (6 floats -> 16-float matrix, sum/difference pairs at 0x9fc164/0x9fc174); 0x9fc260 = lrand48 wrapper; 0x9f8b68 = 2-float (CGSize) builder; 0x9f8b94 = 4-float (color) builder; 0xa0ae10 = float2 writer; 0xa0f744 = credit-time formatter; 0x9fdf50 = releasePixelsMainMenu (CGDataProvider release callback).
- **Creative-mode audio state**: the `nn_state_*` globals (creativeIsShowing / audioIsMuted / oldMusicVolume, slots 0x105e82c/830/834) carry the MJSoundManager mute round-trip: willShowCreative: (+shouldMuteAudio:) saves musicVolume into oldMusicVolume, sets 0 and audioIsMuted=1; didDismissCreative:positiveActionTaken: restores it when both flags are set.
- The per-body census: 3 bodies >1000w [census], 7 bodies 301-1000w [census-lite/read], 68 bodies <=300w fully read.

- Per-body words/branches/calls table:

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | mm_00 | `MainMenuUI -[.cxx_construct]` | 80 | 1 | 6 | read |
  | mm_01 | `MainMenuUI -[IAPForWorldCreationOrTopupSucceeeded:transactionID:]` | 68 | 2 | 2 | read |
  | mm_02 | `MainMenuUI -[appDatabase]` | 25 | 0 | 1 | read |
  | mm_03 | `MainMenuUI -[attemptingToConnectToWorld]` | 15 | 0 | 0 | read |
  | mm_04 | `MainMenuUI -[canDisplayAd]` | 65 | 3 | 0 | read |
  | mm_05 | `MainMenuUI -[cloudInterface]` | 15 | 0 | 0 | read |
  | mm_06 | `MainMenuUI -[cloudInterfaceIsReady]` | 55 | 0 | 2 | read |
  | mm_07 | `MainMenuUI -[cloudTopupFailed:]` | 6 | 0 | 0 | read |
  | mm_08 | `MainMenuUI -[cloudTopupSucceeded:]` | 7 | 0 | 0 | read |
  | mm_09 | `MainMenuUI -[cloudWorldWasCreatedWithID:worldName:userName:userPhoto:timeSelection:]` | 58 | 0 | 1 | read |
  | mm_10 | `MainMenuUI -[connected]` | 48 | 0 | 3 | read |
  | mm_11 | `MainMenuUI -[createWorldImmediately]` | 35 | 0 | 1 | read |
  | mm_12 | `MainMenuUI -[createWorldPlayButtonTappedIsOnline:]` | 125 | 2 | 5 | read |
  | mm_13 | `MainMenuUI -[createWorldUI]` | 17 | 0 | 0 | read |
  | mm_14 | `MainMenuUI -[crystalCountChanged:]` | 704 | 17 | 24 | census-lite/read |
  | mm_15 | `MainMenuUI -[currentMainMenuSelection]` | 15 | 0 | 0 | read |
  | mm_16 | `MainMenuUI -[dealloc]` | 444 | 2 | 28 | census-lite/read |
  | mm_17 | `MainMenuUI -[defaultUserName]` | 12 | 0 | 0 | read |
  | mm_18 | `MainMenuUI -[deleteCurrentWorld]` | 32 | 0 | 1 | read |
  | mm_19 | `MainMenuUI -[didDismissCreative:positiveActionTaken:]` | 71 | 2 | 2 | read |
  | mm_20 | `MainMenuUI -[didDismissMoreGames]` | 5 | 0 | 0 | read |
  | mm_21 | `MainMenuUI -[dismissAddCreditUI]` | 16 | 0 | 0 | read |
  | mm_22 | `MainMenuUI -[dismissAlertViews]` | 153 | 0 | 8 | read |
  | mm_23 | `MainMenuUI -[dismissOptions]` | 16 | 0 | 0 | read |
  | mm_24 | `MainMenuUI -[doubleTimeRestoreTapped]` | 49 | 0 | 3 | read |
  | mm_25 | `MainMenuUI -[doubleTimeUnlocked]` | 60 | 3 | 2 | read |
  | mm_26 | `MainMenuUI -[gameLaunchedWithUrlToJoinCloudWorldWithID:name:]` | 124 | 0 | 3 | read |
  | mm_27 | `MainMenuUI -[gameLaunchedWithUrlToJoinHost:port:]` | 124 | 0 | 3 | read |
  | mm_28 | `MainMenuUI -[gameSavesChanged]` | 128 | 1 | 4 | read |
  | mm_29 | `MainMenuUI -[hasRewardedVideoAvailable]` | 26 | 0 | 1 | read |
  | mm_30 | `MainMenuUI -[hostLANGameInCurrentWorld]` | 169 | 2 | 7 | read |
  | mm_31 | `MainMenuUI -[iapCancelled]` | 45 | 0 | 2 | read |
  | mm_32 | `MainMenuUI -[iapCompleted]` | 25 | 0 | 1 | read |
  | mm_33 | `MainMenuUI -[iapStarted]` | 25 | 0 | 1 | read |
  | mm_34 | `MainMenuUI -[incentivizedVideoViewComplete:]` | 31 | 0 | 1 | read |
  | mm_35 | `MainMenuUI -[initWithDelegate:windowInfo:cache:cloudInterface:]` | 2904 | 32 | 149 | census |
  | mm_36 | `MainMenuUI -[isLoading]` | 15 | 0 | 0 | read |
  | mm_37 | `MainMenuUI -[isPauseMenu]` | 7 | 0 | 0 | read |
  | mm_38 | `MainMenuUI -[joinCloudWorldAtHost:port:key:userName:pic:]` | 44 | 0 | 1 | read |
  | mm_39 | `MainMenuUI -[joinLanWorldButtonTapped]` | 97 | 1 | 3 | read |
  | mm_40 | `MainMenuUI -[joinOnlineWorldButtonTapped]` | 216 | 3 | 10 | read |
  | mm_41 | `MainMenuUI -[joinWorldUI]` | 17 | 0 | 0 | read |
  | mm_42 | `MainMenuUI -[loadWorldPlayButtonTapped]` | 266 | 7 | 13 | read |
  | mm_43 | `MainMenuUI -[loadWorldUI]` | 17 | 0 | 0 | read |
  | mm_44 | `MainMenuUI -[migrateCurrentWorldToCustomRules]` | 32 | 0 | 1 | read |
  | mm_45 | `MainMenuUI -[moreGamesButton:]` | 33 | 0 | 2 | read |
  | mm_46 | `MainMenuUI -[moveTouch:]` | 595 | 28 | 14 | census-lite/read |
  | mm_47 | `MainMenuUI -[multiplayerGameSelectCancelled]` | 16 | 0 | 0 | read |
  | mm_48 | `MainMenuUI -[noodleNews:]` | 64 | 2 | 3 | read |
  | mm_49 | `MainMenuUI -[presentAddCreditUIForWorldWithName:worldID:currentCredit:]` | 159 | 1 | 7 | read |
  | mm_50 | `MainMenuUI -[renameCurrentWorld:]` | 65 | 1 | 3 | read |
  | mm_51 | `MainMenuUI -[render:projectionMatrix:]` | 10738 | 205 | 247 | census |
  | mm_52 | `MainMenuUI -[searchCancelled]` | 5 | 0 | 0 | read |
  | mm_53 | `MainMenuUI -[searchFailed:]` | 18 | 0 | 0 | read |
  | mm_54 | `MainMenuUI -[searchResultsReturned:]` | 218 | 8 | 9 | read |
  | mm_55 | `MainMenuUI -[selectJoinOption]` | 119 | 0 | 3 | read |
  | mm_56 | `MainMenuUI -[selectMostRecentlyPlayedWorld]` | 237 | 4 | 3 | read |
  | mm_57 | `MainMenuUI -[setClockPositions]` | 475 | 7 | 10 | census-lite/read |
  | mm_58 | `MainMenuUI -[setProgress:]` | 32 | 0 | 1 | read |
  | mm_59 | `MainMenuUI -[settingsButton:]` | 80 | 1 | 2 | read |
  | mm_60 | `MainMenuUI -[shareURL:message:fromRect:]` | 51 | 0 | 1 | read |
  | mm_61 | `MainMenuUI -[shouldDisplayAlertOnSearchFail]` | 7 | 0 | 0 | read |
  | mm_62 | `MainMenuUI -[showGDPRAlert]` | 25 | 0 | 1 | read |
  | mm_63 | `MainMenuUI -[showTimeCrystalPurcahseUI:]` | 82 | 1 | 2 | read |
  | mm_64 | `MainMenuUI -[startAttemptingToConnectToWorld]` | 26 | 1 | 0 | read |
  | mm_65 | `MainMenuUI -[startImagePickerWithDelegate:forRect:cropSize:]` | 56 | 0 | 1 | read |
  | mm_66 | `MainMenuUI -[startIncentivizedVideo]` | 25 | 0 | 1 | read |
  | mm_67 | `MainMenuUI -[startSearchForCloudInfoFromWorldIndex:]` | 310 | 12 | 14 | census-lite/read |
  | mm_68 | `MainMenuUI -[startWorldLoadingWithName:worldSize:isGenerating:]` | 336 | 9 | 12 | census-lite/read |
  | mm_69 | `MainMenuUI -[tcUI]` | 17 | 0 | 0 | read |
  | mm_70 | `MainMenuUI -[timeCrystalButton:]` | 22 | 0 | 1 | read |
  | mm_71 | `MainMenuUI -[timeCrystalCloseButtonTapped]` | 16 | 0 | 0 | read |
  | mm_72 | `MainMenuUI -[touchIsInUI:]` | 32 | 0 | 0 | read |
  | mm_73 | `MainMenuUI -[updateCloudSearchInfo]` | 5 | 0 | 0 | read |
  | mm_74 | `MainMenuUI -[updateWorldTitles]` | 560 | 9 | 36 | census-lite/read |
  | mm_75 | `MainMenuUI -[willShowCreative:shouldMuteAudio:]` | 97 | 2 | 4 | read |
  | mm_76 | `MainMenuUI -[willShowMoreGames]` | 5 | 0 | 0 | read |
  | mm_77 | `MainMenuUI -[windowInfoChanged:]` | 1019 | 18 | 29 | census |

## Boundaries

- mm_51 / mm_35 / mm_77 are census-grade: call histogram + full constant/pool tables + head/window samples define the semantics; they are not instruction-by-instruction reads.
- The 301-1000w bodies (mm_14 / mm_16 / mm_30 / mm_46 / mm_56 / mm_57 / mm_67 / mm_68 / mm_74) are read at dispatch/cell level with targeted windows; the loop/scroll-heavy ones (mm_14/mm_30/mm_46/mm_56/mm_57/mm_67/mm_68/mm_74) are summarized (census-lite), not fully register-traced. In mm_14 the exact argument binding of the stringWithFormat call (the fixed pattern + %d splice) is recorded at the cell/dispatch level only, as is the dealloc call order in mm_16.
- moveTouch: ends its scroll branch with a +/-999999.0 pair written through the float2 writer 0xa0ae10 into dead scratch; recorded as observed, no reader on that path.
- `touchIsInUI:` computes the window-relative point but returns constant 1; kept as the code does it.
- ivar offsets come from the Apportable offset-cell pattern resolved against the OBJC_IVAR symbols; the three `nn_state_*` globals are not class ivars (they are module state read via the same cell idiom).
- The 3 already-referenced touch bodies are out of this batch by design; everything else of `MainMenuUI` is in it.
- Static only: no runtime values, no live UIKit/MJ* internals beyond the call-site level.
