# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 106952 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| hf_00 | Blockhead -[addToCrystalDiscrepency:] | 0x00c811e0 | 19 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_01 | Blockhead -[allowsPanning] | 0x00c7b990 | 111 | 5 | 1 | 2 | 0 | 5 | 4 |
| hf_02 | Blockhead -[beingControlledByDPad] | 0x00c86e4c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_03 | Blockhead -[cameraPos] | 0x00c7b5fc | 169 | 3 | 1 | 7 | 0 | 7 | 11 |
| hf_04 | Blockhead -[cameraZOffset] | 0x00c7b8a0 | 60 | 1 | 1 | 3 | 0 | 2 | 3 |
| hf_05 | Blockhead -[canEnterFreeFlightMode] | 0x00c81a44 | 165 | 1 | 1 | 6 | 0 | 2 | 10 |
| hf_06 | Blockhead -[canTeleportToPos:] | 0x00c8122c | 329 | 2 | 1 | 8 | 0 | 10 | 16 |
| hf_07 | Blockhead -[center] | 0x00c82900 | 75 | 0 | 0 | 2 | 0 | 4 | 3 |
| hf_08 | Blockhead -[clientID] | 0x00c8a1f8 | 14 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_09 | Blockhead -[clientName] | 0x00c8a27c | 14 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_10 | Blockhead -[clientSaveDir] | 0x00c8a300 | 14 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_11 | Blockhead -[currentTraverseToKeyFrame] | 0x00bac9a8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_12 | Blockhead -[customizationChanged:] | 0x00c89e3c | 44 | 1 | 1 | 1 | 0 | 2 | 0 |
| hf_13 | Blockhead -[customizationComplete:] | 0x00c89eec | 74 | 3 | 0 | 4 | 0 | 4 | 0 |
| hf_14 | Blockhead -[customizeBlockheadUIShouldHaveOKButton] | 0x00c8a014 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| hf_15 | Blockhead -[dealloc] | 0x00b9ffe4 | 614 | 4 | 2 | 36 | 1 | 38 | 3 |
| hf_16 | Blockhead -[distanceTravelledThisDPadMovementSinceLastRequest] | 0x00c86e88 | 118 | 0 | 0 | 5 | 0 | 5 | 1 |
| hf_17 | Blockhead -[dpadShouldAllowUpDown] | 0x00c7c0d0 | 85 | 2 | 1 | 3 | 0 | 2 | 3 |
| hf_18 | Blockhead -[dpadShouldBeDisplayed] | 0x00c86ae4 | 218 | 7 | 1 | 6 | 0 | 8 | 10 |
| hf_19 | Blockhead -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00c38e68 | 17088 | 50 | 8 | 83 | 1 | 618 | 111 |
| hf_20 | Blockhead -[drawForButtonProjectionMatrix:modelViewMatrix:] | 0x00bed9ac | 17891 | 49 | 9 | 86 | 0 | 620 | 66 |
| hf_21 | Blockhead -[environment] | 0x00b8c9f8 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_22 | Blockhead -[environmentExposure] | 0x00b8ca78 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_23 | Blockhead -[environmentLight] | 0x00b8cab8 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_24 | Blockhead -[fillReceiptsReturned:] | 0x00c80b84 | 151 | 2 | 1 | 2 | 0 | 5 | 10 |
| hf_25 | Blockhead -[freeFlightButtonTapped] | 0x00c83864 | 124 | 3 | 1 | 7 | 0 | 4 | 0 |
| hf_26 | Blockhead -[getSaveDict] | 0x00b9e9d4 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| hf_27 | Blockhead -[infoForPathRecalculation] | 0x00c75410 | 3975 | 62 | 28 | 27 | 8 | 243 | 141 |
| hf_28 | Blockhead -[initSubDerivedStuffStuff] | 0x00b9111c | 816 | 7 | 31 | 16 | 3 | 35 | 1 |
| hf_29 | Blockhead -[initWithWorld:dynamicWorld:cache:netData:] | 0x00b9d0f8 | 297 | 4 | 2 | 17 | 1 | 5 | 4 |
| hf_30 | Blockhead -[isCurrentlyActiveBlockheadAccordingToNetData] | 0x00c8a484 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_31 | Blockhead -[isHeadingForSquare:] | 0x00bac764 | 145 | 4 | 2 | 3 | 0 | 5 | 8 |
| hf_32 | Blockhead -[isInJetPackFreeFlightMode] | 0x00c83a54 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_33 | Blockhead -[localNetID] | 0x00c81e80 | 61 | 1 | 1 | 4 | 0 | 1 | 3 |
| hf_34 | Blockhead -[motionShouldBeDiscreteValues] | 0x00c7b4a0 | 48 | 1 | 1 | 1 | 0 | 1 | 3 |
| hf_35 | Blockhead -[nextPos] | 0x00c8a030 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| hf_36 | Blockhead -[objectType] | 0x00b91dec | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| hf_37 | Blockhead -[pathNeedsRecalculated] | 0x00c8a0d4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_38 | Blockhead -[paused] | 0x00c80584 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_39 | Blockhead -[preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00c01a98 | 55344 | 69 | 18 | 197 | 12 | 886 | 906 |
| hf_40 | Blockhead -[previewData] | 0x00b9d59c | 190 | 3 | 1 | 11 | 1 | 4 | 0 |
| hf_41 | Blockhead -[remoteUpdate:] | 0x00bb7114 | 1814 | 26 | 5 | 44 | 5 | 64 | 79 |
| hf_42 | Blockhead -[renderPos] | 0x00c8a154 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| hf_43 | Blockhead -[requiresMotionEvents] | 0x00c7bee4 | 123 | 2 | 1 | 6 | 0 | 2 | 6 |
| hf_44 | Blockhead -[requiresPhysicalBlock] | 0x00c731c4 | 49 | 1 | 1 | 2 | 0 | 1 | 1 |
| hf_45 | Blockhead -[requiresSwipeEvents] | 0x00c7c224 | 63 | 0 | 0 | 4 | 0 | 0 | 3 |
| hf_46 | Blockhead -[rideObject] | 0x00c8a440 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_47 | Blockhead -[setClientID:] | 0x00c8a230 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| hf_48 | Blockhead -[setClientName:] | 0x00c8a2b4 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| hf_49 | Blockhead -[setClientSaveDir:] | 0x00c8a338 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| hf_50 | Blockhead -[setMotion:] | 0x00c7b31c | 97 | 2 | 1 | 5 | 0 | 2 | 6 |
| hf_51 | Blockhead -[setNeedsRemoved:] | 0x00bb91a8 | 36 | 1 | 1 | 0 | 1 | 1 | 0 |
| hf_52 | Blockhead -[setNoLongerWaitingForPath] | 0x00c79494 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_53 | Blockhead -[setPathNeedsRecalculated:] | 0x00c8a110 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_54 | Blockhead -[setPaused:] | 0x00c8041c | 90 | 1 | 1 | 5 | 0 | 3 | 1 |
| hf_55 | Blockhead -[setRidingObject:] | 0x00c7bd30 | 109 | 5 | 1 | 2 | 0 | 5 | 1 |
| hf_56 | Blockhead -[setWaitingForPathToPos:] | 0x00c7922c | 154 | 2 | 0 | 4 | 0 | 5 | 3 |
| hf_57 | Blockhead -[skinOptions] | 0x00c89df0 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| hf_58 | Blockhead -[stopRiding] | 0x00bb01f0 | 523 | 7 | 1 | 17 | 0 | 22 | 18 |
| hf_59 | Blockhead -[swipeUpGesture] | 0x00c7b560 | 39 | 1 | 1 | 1 | 0 | 1 | 1 |
| hf_60 | Blockhead -[tapIsWithinBodyRadius:] | 0x00c8219c | 291 | 3 | 1 | 2 | 0 | 22 | 12 |
| hf_61 | Blockhead -[teleportToPos:] | 0x00c81750 | 189 | 2 | 0 | 11 | 0 | 4 | 2 |
| hf_62 | Blockhead -[tileIsLitForSelf:atPos:] | 0x00ba0ed8 | 66 | 1 | 0 | 3 | 0 | 1 | 2 |
| hf_63 | Blockhead -[updateJetMotion:] | 0x00c83a90 | 2644 | 5 | 2 | 34 | 0 | 121 | 127 |
| hf_64 | Blockhead -[updateNetDataForClient:] | 0x00b9dedc | 702 | 11 | 1 | 26 | 1 | 18 | 23 |
| hf_65 | Blockhead -[updatePosition:] | 0x00baa488 | 1266 | 17 | 8 | 12 | 1 | 58 | 84 |
| hf_66 | Blockhead -[viewRadius] | 0x00c8a384 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_67 | Blockhead -[waitingForFillRequestAtPos:] | 0x00c81da4 | 55 | 0 | 0 | 3 | 0 | 1 | 3 |
| hf_68 | Blockhead -[waitingForPath] | 0x00c794d4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| hf_69 | Blockhead -[worldChanged:] | 0x00c730d0 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| hf_70 | Blockhead -[worldContentsChanged:] | 0x00c730e8 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |

# Blockhead batch IV (E127): motion / pathfinding / network / save / draw / identity

Blockhead's second slice: **71 bodies / 106,952 verified instruction words**, from the pinned original
libApplication.so (1.7.6, armeabi-v7a; sha256 733d8210…). Listings regenerate byte-identically from the pinned
r2 recipe (gen_listings) and every word/cell/call/branch is re-verified against the ELF (build_specs coverage gate).
7 bodies are census-grade (>1,000 words; 100,022 words = 93.5% of the batch),
5 are census-lite (300-1,000 words), and 59 are fully read (<=300 words).

| name | method | imp | words | class | br | callrows | disp | stret | blx | sel | ivar |
|---|---|---|---|---|---|---|---|---|---|---|---|
| hf_00 | Blockhead -[addToCrystalDiscrepency:] | 0xc811e0 | 19 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_01 | Blockhead -[allowsPanning] | 0xc7b990 | 111 | full | 4 | 5 | 0 | 0 | 5 | 5 | 2 |
| hf_02 | Blockhead -[beingControlledByDPad] | 0xc86e4c | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_03 | Blockhead -[cameraPos] | 0xc7b5fc | 169 | full | 11 | 7 | 0 | 2 | 1 | 3 | 7 |
| hf_04 | Blockhead -[cameraZOffset] | 0xc7b8a0 | 60 | full | 3 | 2 | 0 | 0 | 1 | 1 | 3 |
| hf_05 | Blockhead -[canEnterFreeFlightMode] | 0xc81a44 | 165 | full | 10 | 2 | 0 | 0 | 2 | 1 | 9 |
| hf_06 | Blockhead -[canTeleportToPos:] | 0xc8122c | 329 | census-lite | 16 | 10 | 4 | 0 | 2 | 2 | 12 |
| hf_07 | Blockhead -[center] | 0xc82900 | 75 | full | 3 | 4 | 0 | 0 | 0 | 0 | 3 |
| hf_08 | Blockhead -[clientID] | 0xc8a1f8 | 14 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_09 | Blockhead -[clientName] | 0xc8a27c | 14 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_10 | Blockhead -[clientSaveDir] | 0xc8a300 | 14 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_11 | Blockhead -[currentTraverseToKeyFrame] | 0xbac9a8 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_12 | Blockhead -[customizationChanged:] | 0xc89e3c | 44 | full | 0 | 2 | 0 | 0 | 1 | 1 | 1 |
| hf_13 | Blockhead -[customizationComplete:] | 0xc89eec | 74 | full | 0 | 4 | 3 | 0 | 0 | 3 | 4 |
| hf_14 | Blockhead -[customizeBlockheadUIShouldHaveOKButton] | 0xc8a014 | 7 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| hf_15 | Blockhead -[dealloc] | 0xb9ffe4 | 614 | census-lite | 3 | 38 | 2 | 0 | 36 | 4 | 36 |
| hf_16 | Blockhead -[distanceTravelledThisDPadMovementSinceLastRequest] | 0xc86e88 | 118 | full | 1 | 5 | 0 | 0 | 0 | 0 | 7 |
| hf_17 | Blockhead -[dpadShouldAllowUpDown] | 0xc7c0d0 | 85 | full | 3 | 2 | 0 | 0 | 2 | 2 | 3 |
| hf_18 | Blockhead -[dpadShouldBeDisplayed] | 0xc86ae4 | 218 | full | 10 | 8 | 0 | 0 | 8 | 7 | 6 |
| hf_19 | Blockhead -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0xc38e68 | 17088 | census | 111 | 618 | 156 | 3 | 137 | 21 | 106 |
| hf_20 | Blockhead -[drawForButtonProjectionMatrix:modelViewMatrix:] | 0xbed9ac | 17891 | census | 66 | 620 | 49 | 0 | 263 | 13 | 114 |
| hf_21 | Blockhead -[environment] | 0xb8c9f8 | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_22 | Blockhead -[environmentExposure] | 0xb8ca78 | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_23 | Blockhead -[environmentLight] | 0xb8cab8 | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_24 | Blockhead -[fillReceiptsReturned:] | 0xc80b84 | 151 | full | 10 | 5 | 0 | 0 | 3 | 2 | 3 |
| hf_25 | Blockhead -[freeFlightButtonTapped] | 0xc83864 | 124 | full | 0 | 4 | 0 | 0 | 3 | 3 | 7 |
| hf_26 | Blockhead -[getSaveDict] | 0xb9e9d4 | 21 | full | 0 | 1 | 0 | 0 | 1 | 1 | 0 |
| hf_27 | Blockhead -[infoForPathRecalculation] | 0xc75410 | 3975 | census | 141 | 243 | 31 | 9 | 191 | 46 | 36 |
| hf_28 | Blockhead -[initSubDerivedStuffStuff] | 0xb9111c | 816 | census-lite | 1 | 35 | 0 | 0 | 34 | 7 | 16 |
| hf_29 | Blockhead -[initWithWorld:dynamicWorld:cache:netData:] | 0xb9d0f8 | 297 | full | 4 | 5 | 0 | 0 | 4 | 4 | 19 |
| hf_30 | Blockhead -[isCurrentlyActiveBlockheadAccordingToNetData] | 0xc8a484 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_31 | Blockhead -[isHeadingForSquare:] | 0xbac764 | 145 | full | 8 | 5 | 0 | 0 | 4 | 4 | 4 |
| hf_32 | Blockhead -[isInJetPackFreeFlightMode] | 0xc83a54 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_33 | Blockhead -[localNetID] | 0xc81e80 | 61 | full | 3 | 1 | 0 | 0 | 1 | 1 | 4 |
| hf_34 | Blockhead -[motionShouldBeDiscreteValues] | 0xc7b4a0 | 48 | full | 3 | 1 | 0 | 0 | 1 | 1 | 1 |
| hf_35 | Blockhead -[nextPos] | 0xc8a030 | 24 | full | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| hf_36 | Blockhead -[objectType] | 0xb91dec | 7 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| hf_37 | Blockhead -[pathNeedsRecalculated] | 0xc8a0d4 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_38 | Blockhead -[paused] | 0xc80584 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_39 | Blockhead -[preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0xc01a98 | 55344 | census | 906 | 886 | 88 | 12 | 60 | 54 | 309 |
| hf_40 | Blockhead -[previewData] | 0xb9d59c | 190 | full | 0 | 4 | 0 | 0 | 3 | 3 | 11 |
| hf_41 | Blockhead -[remoteUpdate:] | 0xbb7114 | 1814 | census | 79 | 64 | 17 | 0 | 29 | 25 | 59 |
| hf_42 | Blockhead -[renderPos] | 0xc8a154 | 24 | full | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| hf_43 | Blockhead -[requiresMotionEvents] | 0xc7bee4 | 123 | full | 6 | 2 | 0 | 0 | 2 | 2 | 6 |
| hf_44 | Blockhead -[requiresPhysicalBlock] | 0xc731c4 | 49 | full | 1 | 1 | 0 | 0 | 1 | 1 | 2 |
| hf_45 | Blockhead -[requiresSwipeEvents] | 0xc7c224 | 63 | full | 3 | 0 | 0 | 0 | 0 | 0 | 4 |
| hf_46 | Blockhead -[rideObject] | 0xc8a440 | 17 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_47 | Blockhead -[setClientID:] | 0xc8a230 | 19 | full | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| hf_48 | Blockhead -[setClientName:] | 0xc8a2b4 | 19 | full | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| hf_49 | Blockhead -[setClientSaveDir:] | 0xc8a338 | 19 | full | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| hf_50 | Blockhead -[setMotion:] | 0xc7b31c | 97 | full | 6 | 2 | 1 | 0 | 1 | 2 | 5 |
| hf_51 | Blockhead -[setNeedsRemoved:] | 0xbb91a8 | 36 | full | 0 | 1 | 0 | 0 | 1 | 1 | 0 |
| hf_52 | Blockhead -[setNoLongerWaitingForPath] | 0xc79494 | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_53 | Blockhead -[setPathNeedsRecalculated:] | 0xc8a110 | 17 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_54 | Blockhead -[setPaused:] | 0xc8041c | 90 | full | 1 | 3 | 0 | 0 | 3 | 1 | 6 |
| hf_55 | Blockhead -[setRidingObject:] | 0xc7bd30 | 109 | full | 1 | 5 | 0 | 0 | 5 | 5 | 3 |
| hf_56 | Blockhead -[setWaitingForPathToPos:] | 0xc7922c | 154 | full | 3 | 5 | 3 | 0 | 0 | 2 | 5 |
| hf_57 | Blockhead -[skinOptions] | 0xc89df0 | 19 | full | 0 | 1 | 0 | 0 | 0 | 0 | 1 |
| hf_58 | Blockhead -[stopRiding] | 0xbb01f0 | 523 | census-lite | 18 | 22 | 1 | 1 | 5 | 7 | 23 |
| hf_59 | Blockhead -[swipeUpGesture] | 0xc7b560 | 39 | full | 1 | 1 | 0 | 0 | 1 | 1 | 1 |
| hf_60 | Blockhead -[tapIsWithinBodyRadius:] | 0xc8219c | 291 | full | 12 | 22 | 4 | 0 | 2 | 3 | 2 |
| hf_61 | Blockhead -[teleportToPos:] | 0xc81750 | 189 | full | 2 | 4 | 2 | 0 | 0 | 2 | 11 |
| hf_62 | Blockhead -[tileIsLitForSelf:atPos:] | 0xba0ed8 | 66 | full | 2 | 1 | 1 | 0 | 0 | 1 | 3 |
| hf_63 | Blockhead -[updateJetMotion:] | 0xc83a90 | 2644 | census | 127 | 121 | 10 | 0 | 2 | 4 | 49 |
| hf_64 | Blockhead -[updateNetDataForClient:] | 0xb9dedc | 702 | census-lite | 23 | 18 | 6 | 1 | 7 | 11 | 32 |
| hf_65 | Blockhead -[updatePosition:] | 0xbaa488 | 1266 | census | 84 | 58 | 23 | 1 | 13 | 16 | 15 |
| hf_66 | Blockhead -[viewRadius] | 0xc8a384 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_67 | Blockhead -[waitingForFillRequestAtPos:] | 0xc81da4 | 55 | full | 3 | 1 | 0 | 0 | 0 | 0 | 3 |
| hf_68 | Blockhead -[waitingForPath] | 0xc794d4 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| hf_69 | Blockhead -[worldChanged:] | 0xc730d0 | 6 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| hf_70 | Blockhead -[worldContentsChanged:] | 0xc730e8 | 6 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Findings (E127)

- **The batch's center of mass is the draw trio.** hf_39 `preDrawUpdate:cameraMinXWorld:...` alone is
  **55,344 words / 906 branches** - 51.7% of the batch and the heaviest single body seen in the
  class after `update:accurateDT:isSimulation:` (E124, 37,886 w). It is the per-frame pre-draw spine: 108 sinf,
  94 memcpy matrix composites, sound/particle/dpad/rider triggers, day-night color; only 88 of its 886 call rows
  are objc dispatches (the rest are C++/C helpers, 160x local 0xc384e0). The draw pair hf_19 (`draw:projection...`,
  17,088 w) and hf_20 (`drawForButtonProjectionMatrix:...`, 17,891 w) are the two ~17k model draws (DrawCube
  sets through per-bone matrices + the GL uniform pipeline).
- **The authoritative ivar map is now extractable from the ELF itself** (no live-process dependency):
  Blockhead's `class_ro_t.ivar_list` = 221 ivars, instanceStart **0x38**, instanceSize **0x97c**; `state`
  [0x38] is a `BlockheadState` struct (size **0x6c**) with 26 members - interacting c+0x00, interactionType
  i+0x04, goalInteractionTypeWhileWalking i+0x08, interactingSquare {x,y}+0x0c, interactionTimer f+0x14,
  gatherSpeed f+0x18, gatherTimer f+0x1c, health f+0x20, happiness f+0x24, fullness f+0x28, energy f+0x2c,
  meditationProgress f+0x30, drownFraction f+0x34, environment f+0x38, environmentTemperature f+0x3c,
  environmentExposure f+0x40, environmentLight f+0x44, heat f+0x48, animationType i+0x4c, subAnimationType
  i+0x50, coffeeEnergyTimer f+0x54, foodPauseTimer f+0x58, death f+0x5c, regenerating c+0x60,
  regenerationProgress f+0x64, onTradeMission c+0x68.
- **Offset convention (correction worth pinning):** the access effective address is
  `(offset-cell value) + (literal displacement)`, and the cell value **is** the runtime offset (same-build
  identity + live object-graph verification, `IVAR_OFFSET_READING.md`). The E124 doc printed the displacement
  for BlockheadState members - those numbers are **struct-relative**; the absolute byte offset adds the state
  base 0x38 (e.g. E124's "action/state enum [self+0x50]" = absolute `[self+0x88]` = state.subAnimationType;
  the death float is absolute `[self+0x94]` = state.death). This batch's semantics use absolute offsets.
- **Motion/pathfinding spine (the batch's stated purpose, now complete around E124's tick):**
  - gates: `canEnterFreeFlightMode` (state.subAnimationType 0x88 in {5,6,7} \|\| regenerating \|\|
    onTradeMission \|\| path \|\| waitingForPath \|\| rideObject \|\| fishingRod \|\| actionQueue.count);
    `canTeleportToPos:` adds the centered-world window (worldWidthMacro*32/2 on both axes).
  - jetpack: `setMotion:` -> jetPackIncomingAcceleration (0x840); `updateJetMotion:` (2,644 w) the flight
    integrator with 41 tile probes and the world wrap; `cameraPos`/`cameraZOffset` follow
    smoothedJetPackVelocity*0.75f; `freeFlightButtonTapped` zeroes velocities, animationType=0x20,
    [world.uiManager dismissJetPackUI].
  - dpad: `requiresSwipeEvents`/`requiresMotionEvents`/`dpadShouldBeDisplayed`/`dpadShouldAllowUpDown`/
    `motionShouldBeDiscreteValues` + `distanceTravelledThisDPadMovementSinceLastRequest` (0.9f/0.1f
    smoothed delta of floatPos - floatPosWhenDPadMovementStarted).
  - path: `setWaitingForPathToPos:` (interaction-type query on the goal tile + protected re-query),
    `pathNeedsRecalculated`/`setPathNeedsRecalculated:` (atomic byte 0x29c), `isHeadingForSquare:`
    (finalGoalSquare 0x224, else path[0] goal via getWorldPosForWorldIndex), `teleportToPos:` (gate,
    [self updatePosition:], floatPos=(x+0.5f, y) center snap, the nextTo->to->prevFrom->from square cascade,
    fromTile=toTile=tileAtWorldPositionLoaded, updateNeedsToBeSent=1), `updatePosition:` (super + the tile-entry
    pipeline: 8 door/trapdoor/gate probes, setDoorAtPos:toOpen:direction: x2, treasure/troll, torch placement x5,
    achievement reports x7, server broadcast).
  - misc: `tapIsWithinBodyRadius:` = the wrap-normalized body box (+/-0.5 on x).
- **Network/save surface:** `remoteUpdate:` (1,814 w) is the packet **unpacker** (getBytes:length:; resolves
  objects through dynamicWorld lookups + HandCar/PassengerCar/SteamTrain/FishingRod via class/isKindOfClass:;
  2 NSLog debug prints; applies pos/squares/state/ride/fishing/jetpack/paused/queue fields) and
  `updateNetDataForClient:` is the **packer** (dynamicObjectNetData base + the same field family, ends in
  [NSData dataWithBytes:length:]). `infoForPathRecalculation` (3,975 w) builds the path-recalc dictionary blob
  (NSMutableDictionary, numberWithInt:, 9 stret dictionary builds). Fill handshake: `fillReceiptsReturned:`
  matches [item unsignedIntValue] against waitingForFillResponseIndex and clears waitingForFillResponse;
  `waitingForFillRequestAtPos:` = worldIndexAtWorldPos(pos, world) == waitingForFillResponseIndex.
  Identity: `localNetID` = clientID when server-controlled/net, else [dynamicWorld localNetID];
  `isCurrentlyActiveBlockheadAccordingToNetData` byte 0x93c.
- **Save/identity surface:** `previewData` = the blockhead preview blob (0x28-byte header: skinOptions 0x14-byte
  copy + hat/shirt/pants/shoes item types and color indices as u16 + happiness*127.0f byte; appendData: of
  [name dataUsingEncoding:NSUTF8StringEncoding]); `getSaveDict` = forwarder to
  getSaveDictIncludingWorkbenchOrInterationObject:0; clientID/clientName/clientSaveDir are objc_getProperty
  getters (0xa4/0xa8/0x810) with objc_setProperty_atomic setters; customization commit = memcpy skinOptions
  (0x14) + updateSkin + creationDataNeedsToBeSent + [dynamicWorld dynamicWorldChangedAtPos:objectType:];
  dealloc (614 w) = the full teardown incl. [super dealloc] via objc_msgSendSuper2 and the two cube loops.
- **Verified constants in play:** 0.75f (cameraPos jetpack blend), 0.9f/0.1f (dpad distance smoothing),
  0.5f (teleport x centering; tapIsWithinBodyRadius box), 127.0f (previewData happiness byte), 0x18 (objectType),
  0x20 (freeFlightButtonTapped animationType), 10 (nextTerrainDifficulty seed), 4.0f/1.0f (init creation block),
  0x1b..0x1e/0x21 (stopRiding animation set). VFP immediates were decoded with capstone: the r2 text "5" renders
  **0.5** for vmov.f64 - one near-miss caught and corrected during this batch.

## Boundaries

- The 7 census bodies (>1,000 words: hf_19/hf_20/hf_27/hf_39/hf_41/hf_63/hf_65) are characterized by aggregate
  statistics (counts, call histogram, cell sets) + targeted windows; their full branch trees stay in the listings.
  Internal helper sub-names (e.g. 0xc384e0 x160 inside hf_39) are not resolved beyond their call sites.
- `previewData`'s exact 0x28-byte header field order is read from the memcpy/ldrh sequence; the trailing bytes'
  grouping is partly inferred.
- Offsets bind to the pinned 1.7.6 ELF (sha256 733d8210…). The live-verified field map (1.7.5, `live_verified_
  fields.json`) corroborates the cell-value-is-offset rule for the four game classes.
- `state` struct member offsets above are layout-derived from the ObjC type string (i/f/c alignment); all offsets
  used in the semantics were additionally confirmed at their access sites (cell value + displacement).
