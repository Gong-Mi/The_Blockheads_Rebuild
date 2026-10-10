# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 16513 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| gy_00 | GameView -[loadWorldAtIndex:allowPVP:] | 0x009347e4 | 357 | 8 | 7 | 10 | 0 | 18 | 5 |
| gy_01 | GameView -[mainMenuSoundFinshedFadingOut] | 0x0093a55c | 111 | 5 | 3 | 1 | 2 | 6 | 1 |
| gy_02 | GameView -[mainMenuUI] | 0x009449e8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_03 | GameView -[mainThreadFileWriteFailed:] | 0x0092059c | 145 | 5 | 4 | 2 | 2 | 5 | 1 |
| gy_04 | GameView -[messageForAchivementWithIdentifier:] | 0x0093c7b8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_05 | GameView -[migrateWorldToCustomRulesAtIndex:] | 0x009345fc | 122 | 5 | 3 | 1 | 1 | 5 | 2 |
| gy_06 | GameView -[moveSecondaryTouch:] | 0x0092cba8 | 140 | 3 | 1 | 5 | 0 | 3 | 7 |
| gy_07 | GameView -[multipleWorldsFoundForClientMatch:options:] | 0x009357b4 | 290 | 11 | 5 | 3 | 1 | 9 | 4 |
| gy_08 | GameView -[netClientMatchServerFound:] | 0x00935f2c | 263 | 10 | 1 | 3 | 1 | 12 | 1 |
| gy_09 | GameView -[panGesture:state:translation:velocity:tapLocation:] | 0x0092ded0 | 821 | 13 | 1 | 12 | 0 | 38 | 40 |
| gy_10 | GameView -[paymentQueue:restoreCompletedTransactionsFailedWithError:] | 0x0092564c | 158 | 6 | 5 | 0 | 2 | 10 | 0 |
| gy_11 | GameView -[paymentQueue:updatedTransactions:] | 0x00921e64 | 171 | 5 | 1 | 0 | 0 | 8 | 15 |
| gy_12 | GameView -[paymentQueueRestoreCompletedTransactionsFinished:] | 0x009258c4 | 20 | 1 | 1 | 0 | 0 | 1 | 0 |
| gy_13 | GameView -[pickerShowing] | 0x00944a70 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_14 | GameView -[playTappedInNewWorldScreenWithSaveName:worldSize:customRules:expertMode:] | 0x009312dc | 516 | 10 | 10 | 9 | 1 | 22 | 15 |
| gy_15 | GameView -[playersChanged] | 0x0093ff8c | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| gy_16 | GameView -[popoverControllerDidDismissPopover:] | 0x00924b10 | 121 | 4 | 1 | 3 | 1 | 4 | 3 |
| gy_17 | GameView -[populateGameSaves] | 0x009180cc | 3166 | 45 | 32 | 7 | 13 | 173 | 116 |
| gy_18 | GameView -[presentPickerUIWithSourceType:] | 0x00923918 | 276 | 11 | 1 | 6 | 3 | 14 | 5 |
| gy_19 | GameView -[presentSavedToCameraRollAlert] | 0x0093c874 | 86 | 4 | 4 | 0 | 1 | 4 | 0 |
| gy_20 | GameView -[presentShareUIForImage:] | 0x0093a8f8 | 342 | 12 | 6 | 4 | 4 | 15 | 5 |
| gy_21 | GameView -[presentShareUIForURL:message:rectFromScreenCenter:] | 0x0093b008 | 344 | 11 | 2 | 4 | 4 | 14 | 9 |
| gy_22 | GameView -[recentConnections] | 0x00942288 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_23 | GameView -[removeEntryFromiCloudRecentConnectionList:] | 0x00928bc4 | 315 | 9 | 4 | 0 | 2 | 18 | 9 |
| gy_24 | GameView -[renameWorldAtIndex:withName:] | 0x0093a3b0 | 107 | 4 | 3 | 1 | 0 | 4 | 4 |
| gy_25 | GameView -[resize:insets:] | 0x0092f298 | 261 | 3 | 1 | 8 | 0 | 6 | 3 |
| gy_26 | GameView -[restoreTransaction:] | 0x00924cf4 | 434 | 20 | 9 | 2 | 5 | 24 | 10 |
| gy_27 | GameView -[rewardIncentivizedVideoCurrency:] | 0x0094135c | 725 | 26 | 10 | 4 | 6 | 42 | 8 |
| gy_28 | GameView -[secondaryTouchCancelled] | 0x0092d188 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_29 | GameView -[sendMessage:] | 0x0093f928 | 133 | 4 | 2 | 2 | 0 | 6 | 8 |
| gy_30 | GameView -[setChatHaxOngoing:] | 0x00944ba4 | 16 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_31 | GameView -[setGdprPrompt:] | 0x00944c24 | 16 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_32 | GameView -[setGlView:] | 0x00944894 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_33 | GameView -[setNewWelcomeMessage:] | 0x009439d4 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| gy_34 | GameView -[setPaused:] | 0x00938c58 | 85 | 1 | 1 | 4 | 0 | 1 | 5 |
| gy_35 | GameView -[setPickerShowing:] | 0x00944aac | 16 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_36 | GameView -[setViewController:] | 0x0094480c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_37 | GameView -[setWelcomeMessageShowing:] | 0x00944b28 | 16 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_38 | GameView -[shouldDisplayInterstitial] | 0x0093b6c8 | 350 | 5 | 2 | 14 | 2 | 8 | 17 |
| gy_39 | GameView -[shouldDisplayNewAddedFeaturesAlert] | 0x00944348 | 26 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_40 | GameView -[showBlockheadAvailablePrompt:] | 0x0093ec54 | 311 | 12 | 12 | 2 | 2 | 10 | 13 |
| gy_41 | GameView -[showChatUI] | 0x0093f538 | 117 | 4 | 1 | 3 | 1 | 4 | 3 |
| gy_42 | GameView -[showDieConfirmationForBlockhead:] | 0x009422c4 | 315 | 13 | 6 | 2 | 2 | 13 | 1 |
| gy_43 | GameView -[showDoubleTimePromptIfGoodTime:] | 0x0093ce48 | 410 | 16 | 7 | 4 | 4 | 15 | 7 |
| gy_44 | GameView -[showGDPRAlert] | 0x009443b0 | 106 | 4 | 1 | 0 | 1 | 4 | 0 |
| gy_45 | GameView -[showLowCreditWarningWithMinutes:] | 0x00943a40 | 356 | 14 | 9 | 2 | 2 | 13 | 6 |
| gy_46 | GameView -[showTutorialPopupWithTitle:message:lastMessage:] | 0x0093dcf4 | 258 | 12 | 4 | 2 | 1 | 11 | 3 |
| gy_47 | GameView -[showWelcomeBackPopupWithMessage:] | 0x0093d818 | 210 | 10 | 4 | 2 | 1 | 9 | 2 |
| gy_48 | GameView -[startCameraZoomForTeaserRecord] | 0x00925914 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_49 | GameView -[startHostingNetworkGameWithUserName:userPhoto:] | 0x00934f7c | 204 | 6 | 2 | 3 | 2 | 7 | 1 |
| gy_50 | GameView -[startImagePickerWithDelegate:forRect:cropSize:] | 0x00923f78 | 237 | 6 | 4 | 7 | 2 | 7 | 3 |
| gy_51 | GameView -[startIncentivizedVideo] | 0x00941128 | 141 | 7 | 4 | 1 | 2 | 7 | 5 |
| gy_52 | GameView -[startSearchingForClientNetworkGameAtHost:port:userName:userPhoto:cloudKey:] | 0x009353f0 | 241 | 9 | 1 | 3 | 1 | 10 | 2 |
| gy_53 | GameView -[startSecondaryTouch:withTouch:withEvent:] | 0x0092c89c | 195 | 7 | 1 | 5 | 0 | 7 | 6 |
| gy_54 | GameView -[startTimer] | 0x00917818 | 130 | 2 | 1 | 0 | 0 | 7 | 1 |
| gy_55 | GameView -[startupInterstitial] | 0x00920b98 | 228 | 11 | 4 | 1 | 3 | 11 | 12 |
| gy_56 | GameView -[stop] | 0x00942274 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_57 | GameView -[swipeGesture] | 0x0092ee80 | 46 | 2 | 1 | 1 | 0 | 2 | 1 |
| gy_58 | GameView -[tapGesture:center:] | 0x0092eba4 | 130 | 6 | 1 | 2 | 0 | 6 | 5 |
| gy_59 | GameView -[textField:shouldChangeCharactersInRange:replacementString:] | 0x0093fff0 | 165 | 7 | 1 | 0 | 1 | 10 | 6 |
| gy_60 | GameView -[timeoutTimer] | 0x00917db8 | 98 | 3 | 1 | 1 | 0 | 5 | 3 |
| gy_61 | GameView -[touchIsInChatView:] | 0x0093ff18 | 29 | 1 | 0 | 1 | 0 | 1 | 0 |
| gy_62 | GameView -[updateSaveGameValue:forKey:save:] | 0x00933e7c | 480 | 17 | 7 | 2 | 7 | 28 | 10 |
| gy_63 | GameView -[updateTranslation:] | 0x0092de5c | 29 | 1 | 0 | 1 | 0 | 1 | 0 |
| gy_64 | GameView -[updateiCloudRecentConnectionList] | 0x00928030 | 741 | 27 | 10 | 2 | 6 | 41 | 17 |
| gy_65 | GameView -[viewController] | 0x009447c8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_66 | GameView -[viewServerWelcomeMessage:customRules:allowEdit:] | 0x00937da8 | 940 | 24 | 24 | 4 | 7 | 45 | 23 |
| gy_67 | GameView -[welcomeMessageShowing] | 0x00944aec | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_68 | GameView -[willEnterForeground] | 0x00931204 | 54 | 2 | 1 | 1 | 0 | 2 | 0 |
| gy_69 | GameView -[willResignActive] | 0x0092f6ac | 140 | 5 | 1 | 5 | 1 | 5 | 8 |
| gy_70 | GameView -[world] | 0x009449a4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gy_71 | GameView -[worldIsSimulating] | 0x00925954 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |

## Findings (E131)

**Batch: GameView batch B (E131), 72 bodies / 16,513 instruction words** (listings gy_00..gy_71, all class
GameView; alphabetical second half). GameView is the app-shell class of The Blockheads - the world launcher, gesture
router, alert/UI presenter and IAP/network screens. 1 body is census-grade (>1,000 words; 3,166 words
= 19.2% of the batch), 12 are census-lite (300-1,000 words; 6,460 words =
39.1%), the remaining 59 are small (<300 words, fully
characterized). Heaviest three: gy_17 `populateGameSaves` 3,166w, gy_66 `viewServerWelcomeMessage:customRules:
allowEdit:` 940w, gy_09 `panGesture:state:translation:velocity:tapLocation:` 821w.

| name | method | imp | words | class | br | callrows | disp | stret | blx | sel | ivar |
|---|---|---|---|---|---|---|---|---|---|---|---|
| gy_00 | GameView -[loadWorldAtIndex:allowPVP:] | 0x9347e4 | 357 | census-lite | 5 | 18 | 0 | 0 | 17 | 8 | 13 |
| gy_01 | GameView -[mainMenuSoundFinshedFadingOut] | 0x93a55c | 111 | full | 1 | 6 | 0 | 0 | 6 | 5 | 1 |
| gy_02 | GameView -[mainMenuUI] | 0x9449e8 | 17 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_03 | GameView -[mainThreadFileWriteFailed:] | 0x92059c | 145 | full | 1 | 5 | 0 | 0 | 5 | 5 | 3 |
| gy_04 | GameView -[messageForAchivementWithIdentifier:] | 0x93c7b8 | 8 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_05 | GameView -[migrateWorldToCustomRulesAtIndex:] | 0x9345fc | 122 | full | 2 | 5 | 0 | 0 | 5 | 5 | 1 |
| gy_06 | GameView -[moveSecondaryTouch:] | 0x92cba8 | 140 | full | 7 | 3 | 1 | 0 | 2 | 3 | 6 |
| gy_07 | GameView -[multipleWorldsFoundForClientMatch:options:] | 0x9357b4 | 290 | full | 4 | 9 | 0 | 0 | 9 | 10 | 4 |
| gy_08 | GameView -[netClientMatchServerFound:] | 0x935f2c | 263 | full | 1 | 12 | 0 | 0 | 12 | 10 | 4 |
| gy_09 | GameView -[panGesture:state:translation:velocity:tapLocation:] | 0x92ded0 | 821 | census-lite | 40 | 38 | 5 | 2 | 12 | 13 | 17 |
| gy_10 | GameView -[paymentQueue:restoreCompletedTransactionsFailedWithError:] | 0x92564c | 158 | full | 0 | 10 | 0 | 0 | 10 | 6 | 0 |
| gy_11 | GameView -[paymentQueue:updatedTransactions:] | 0x921e64 | 171 | full | 15 | 8 | 1 | 0 | 5 | 5 | 0 |
| gy_12 | GameView -[paymentQueueRestoreCompletedTransactionsFinished:] | 0x9258c4 | 20 | full | 0 | 1 | 0 | 0 | 1 | 1 | 0 |
| gy_13 | GameView -[pickerShowing] | 0x944a70 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_14 | GameView -[playTappedInNewWorldScreenWithSaveName:worldSize:customRules:expertMode:] | 0x9312dc | 516 | census-lite | 15 | 22 | 0 | 0 | 21 | 10 | 10 |
| gy_15 | GameView -[playersChanged] | 0x93ff8c | 25 | full | 0 | 1 | 0 | 0 | 1 | 1 | 1 |
| gy_16 | GameView -[popoverControllerDidDismissPopover:] | 0x924b10 | 121 | full | 3 | 4 | 0 | 0 | 4 | 4 | 4 |
| gy_17 | GameView -[populateGameSaves] | 0x9180cc | 3166 | census | 116 | 173 | 0 | 0 | 149 | 33 | 10 |
| gy_18 | GameView -[presentPickerUIWithSourceType:] | 0x923918 | 276 | full | 5 | 14 | 8 | 0 | 6 | 11 | 7 |
| gy_19 | GameView -[presentSavedToCameraRollAlert] | 0x93c874 | 86 | full | 0 | 4 | 0 | 0 | 4 | 4 | 0 |
| gy_20 | GameView -[presentShareUIForImage:] | 0x93a8f8 | 342 | census-lite | 5 | 15 | 3 | 0 | 11 | 12 | 4 |
| gy_21 | GameView -[presentShareUIForURL:message:rectFromScreenCenter:] | 0x93b008 | 344 | census-lite | 9 | 14 | 3 | 0 | 10 | 11 | 5 |
| gy_22 | GameView -[recentConnections] | 0x942288 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_23 | GameView -[removeEntryFromiCloudRecentConnectionList:] | 0x928bc4 | 315 | full | 9 | 18 | 0 | 0 | 16 | 9 | 0 |
| gy_24 | GameView -[renameWorldAtIndex:withName:] | 0x93a3b0 | 107 | full | 4 | 4 | 0 | 0 | 4 | 4 | 1 |
| gy_25 | GameView -[resize:insets:] | 0x92f298 | 261 | full | 3 | 6 | 0 | 0 | 3 | 3 | 8 |
| gy_26 | GameView -[restoreTransaction:] | 0x924cf4 | 434 | census-lite | 10 | 24 | 0 | 2 | 20 | 20 | 2 |
| gy_27 | GameView -[rewardIncentivizedVideoCurrency:] | 0x94135c | 725 | census-lite | 8 | 42 | 0 | 0 | 42 | 26 | 4 |
| gy_28 | GameView -[secondaryTouchCancelled] | 0x92d188 | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_29 | GameView -[sendMessage:] | 0x93f928 | 133 | full | 8 | 6 | 0 | 1 | 4 | 4 | 2 |
| gy_30 | GameView -[setChatHaxOngoing:] | 0x944ba4 | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_31 | GameView -[setGdprPrompt:] | 0x944c24 | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_32 | GameView -[setGlView:] | 0x944894 | 17 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_33 | GameView -[setNewWelcomeMessage:] | 0x9439d4 | 27 | full | 0 | 1 | 0 | 0 | 1 | 1 | 1 |
| gy_34 | GameView -[setPaused:] | 0x938c58 | 85 | full | 5 | 1 | 0 | 0 | 1 | 1 | 5 |
| gy_35 | GameView -[setPickerShowing:] | 0x944aac | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_36 | GameView -[setViewController:] | 0x94480c | 17 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_37 | GameView -[setWelcomeMessageShowing:] | 0x944b28 | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_38 | GameView -[shouldDisplayInterstitial] | 0x93b6c8 | 350 | census-lite | 17 | 8 | 0 | 0 | 8 | 5 | 14 |
| gy_39 | GameView -[shouldDisplayNewAddedFeaturesAlert] | 0x944348 | 26 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_40 | GameView -[showBlockheadAvailablePrompt:] | 0x93ec54 | 311 | full | 13 | 10 | 3 | 0 | 7 | 11 | 3 |
| gy_41 | GameView -[showChatUI] | 0x93f538 | 117 | full | 3 | 4 | 0 | 0 | 4 | 4 | 4 |
| gy_42 | GameView -[showDieConfirmationForBlockhead:] | 0x9422c4 | 315 | full | 1 | 13 | 0 | 0 | 13 | 12 | 3 |
| gy_43 | GameView -[showDoubleTimePromptIfGoodTime:] | 0x93ce48 | 410 | census-lite | 7 | 15 | 0 | 0 | 15 | 15 | 5 |
| gy_44 | GameView -[showGDPRAlert] | 0x9443b0 | 106 | full | 0 | 4 | 0 | 0 | 4 | 4 | 0 |
| gy_45 | GameView -[showLowCreditWarningWithMinutes:] | 0x943a40 | 356 | full | 6 | 13 | 0 | 0 | 13 | 13 | 4 |
| gy_46 | GameView -[showTutorialPopupWithTitle:message:lastMessage:] | 0x93dcf4 | 258 | full | 3 | 11 | 0 | 0 | 11 | 11 | 3 |
| gy_47 | GameView -[showWelcomeBackPopupWithMessage:] | 0x93d818 | 210 | full | 2 | 9 | 0 | 0 | 9 | 10 | 2 |
| gy_48 | GameView -[startCameraZoomForTeaserRecord] | 0x925914 | 16 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_49 | GameView -[startHostingNetworkGameWithUserName:userPhoto:] | 0x934f7c | 204 | full | 1 | 7 | 0 | 0 | 7 | 6 | 4 |
| gy_50 | GameView -[startImagePickerWithDelegate:forRect:cropSize:] | 0x923f78 | 237 | full | 3 | 7 | 3 | 0 | 3 | 6 | 8 |
| gy_51 | GameView -[startIncentivizedVideo] | 0x941128 | 141 | full | 5 | 7 | 0 | 0 | 7 | 7 | 2 |
| gy_52 | GameView -[startSearchingForClientNetworkGameAtHost:port:userName:userPhoto:cloudKey:] | 0x9353f0 | 241 | full | 2 | 10 | 0 | 0 | 10 | 9 | 4 |
| gy_53 | GameView -[startSecondaryTouch:withTouch:withEvent:] | 0x92c89c | 195 | full | 6 | 7 | 3 | 0 | 4 | 7 | 6 |
| gy_54 | GameView -[startTimer] | 0x917818 | 130 | full | 1 | 7 | 0 | 0 | 0 | 1 | 0 |
| gy_55 | GameView -[startupInterstitial] | 0x920b98 | 228 | full | 12 | 11 | 0 | 0 | 11 | 11 | 1 |
| gy_56 | GameView -[stop] | 0x942274 | 5 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_57 | GameView -[swipeGesture] | 0x92ee80 | 46 | full | 1 | 2 | 0 | 0 | 2 | 2 | 1 |
| gy_58 | GameView -[tapGesture:center:] | 0x92eba4 | 130 | full | 5 | 6 | 1 | 0 | 5 | 6 | 2 |
| gy_59 | GameView -[textField:shouldChangeCharactersInRange:replacementString:] | 0x93fff0 | 165 | full | 6 | 10 | 3 | 1 | 5 | 7 | 0 |
| gy_60 | GameView -[timeoutTimer] | 0x917db8 | 98 | full | 3 | 5 | 0 | 0 | 3 | 3 | 2 |
| gy_61 | GameView -[touchIsInChatView:] | 0x93ff18 | 29 | full | 0 | 1 | 1 | 0 | 0 | 1 | 1 |
| gy_62 | GameView -[updateSaveGameValue:forKey:save:] | 0x933e7c | 480 | census-lite | 10 | 28 | 0 | 0 | 24 | 17 | 2 |
| gy_63 | GameView -[updateTranslation:] | 0x92de5c | 29 | full | 0 | 1 | 1 | 0 | 0 | 1 | 1 |
| gy_64 | GameView -[updateiCloudRecentConnectionList] | 0x928030 | 741 | census-lite | 17 | 41 | 0 | 0 | 39 | 27 | 2 |
| gy_65 | GameView -[viewController] | 0x9447c8 | 17 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_66 | GameView -[viewServerWelcomeMessage:customRules:allowEdit:] | 0x937da8 | 940 | census-lite | 23 | 45 | 5 | 6 | 28 | 24 | 5 |
| gy_67 | GameView -[welcomeMessageShowing] | 0x944aec | 15 | full | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| gy_68 | GameView -[willEnterForeground] | 0x931204 | 54 | full | 0 | 2 | 0 | 0 | 2 | 2 | 1 |
| gy_69 | GameView -[willResignActive] | 0x92f6ac | 140 | full | 8 | 5 | 0 | 0 | 5 | 5 | 5 |
| gy_70 | GameView -[world] | 0x9449a4 | 17 | full | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| gy_71 | GameView -[worldIsSimulating] | 0x925954 | 27 | full | 0 | 1 | 0 | 0 | 1 | 1 | 1 |

- **GameView's authoritative ivar map is now statically extracted** (ELF class_ro, class list @0xE8BF58): 112 ivars,
  instanceStart 0x4, running to gdprPrompt@0x204. Highlights used by this batch: viewController@0x4, glView@0x8,
  mainMenuUI@0x14, world@0x18, appDatabase@0x24, bhClient@0x28, bhServer@0x2c, projectionMatrix@0x30 (16 floats),
  cameraZ@0x70, touchStartPos@0x74, touchStartTranslation@0x7c, pinchStartOffset@0x84, pinchOffset@0x8c,
  pinchScale@0x98 (double), pinchStartScale@0xa0, pinchVelocity@0xa4, lastPinchFactor@0xa8, hasPinchVelocity@0xac,
  pinching@0xad, translationOffset@0xb0, pinchZooming@0xb8, scrollVelocity@0xbc, scrolling@0xc4, hasVelocity@0xc5,
  lastBackgroundDragEvent@0xc8 (double), windowInfo@0xd0 (8 floats), continueTapped@0xf0, newTapped@0xf1,
  gameSaves@0xfc, loadIndex@0x100, loadWorldName@0x104, loadSaveID@0x108, allowPVPWhenHostingGame@0x10c,
  pvpDisabledWhenLoadingGame@0x10d, paused@0x10e, totalGamePlayTimePassed@0x110 (double), needsToExitWorld@0x124,
  the alert/UI pointer block (fileWriteAlertView@0x130, doubleTimePromptAlertView@0x134, welcomeBackAlertView@0x138,
  blockheadPromptAlertView@0x13c, tutorialAlertView@0x140, crystalsAddedAlertView@0x144, popover@0x158,
  diePromptAlertView@0x1c0, lowCreditAlertView@0x1d0, cloudMessageAlertView@0x1d4), hasBoughtIAP@0x152,
  isZoomingCameraOut@0x165, anyWorldsHaveBeenPlayed@0x168, averageVelocity@0x16c, velocityCount@0x174,
  searchingClientMatch@0x178, multiPlayerJoinLocalMultipleSelectionAlertView@0x17c, imagePickerDelegate@0x180,
  imagePickerCropSize@0x184, chatView@0x18c, imagePicker@0x190, imagePickerActionSheet@0x194, imagePickerRect@0x198,
  movieViewInProgress@0x1a9, worldWidthMacro@0x1b0, customRules@0x1b4, expertMode@0x1b8, recentConnectionsList@0x1bc,
  cloudInterface@0x1c8, urlToOpenOnceLoaded@0x1e0, startTouchHasntMoved@0x1e6, startTouchPos@0x1e8,
  primaryTouchIsActiveInUI@0x1f0, secondaryStartTouchHasntMoved@0x1f1, secondaryTouchStarted@0x1f2,
  secondaryStartTouchPos@0x1f4, secondaryTouchIsActiveInUI@0x1fc, secondaryTouchCancelled@0x1fd, iapInProgress@0x1fe,
  pickerShowing@0x1ff, welcomeMessageShowing@0x200, chatHaxOngoing@0x201, gdprPrompt@0x204.
- **Offset-cell decoding**: the Apportable ivar idiom resolves THREE levels - cell word + PIC base (0x0105faf4) gives a
  slot; the slot holds a pointer into the ivar-offset table; the offset word + self is the field. 10 bodies reference
  dynsym-anonymous slots (pickerShowing, chatHaxOngoing, welcomeMessageShowing, gdprPrompt); all resolved by matching the
  class_ro offsets (511/513/512/516).
- **World-loading & saves front (the batch's stated purpose)**: `loadWorldAtIndex:allowPVP:` stages index/allowPVP/
  continueTapped then copies customRules/expertMode/worldWidthMacro/worldName/saveID into the load* ivars (worldWidthMacro
  defaults to 512) and tears down any bhClient; `playTappedInNewWorldScreenWithSaveName:...` builds the new world's saveID
  from the device UDID + a time suffix and maps the world-size label vocabulary ('1/16','1/4','4x','16','16x');
  `migrateWorldToCustomRulesAtIndex:` + `updateSaveGameValue:forKey:save:` + `renameWorldAtIndex:withName:` are the save-DB
  edit trio (DatabaseEnvironment 'main' + Database '%@/world_db/' '%@_worldv2', dataForKey:/setData:forKey:/property
  lists); `populateGameSaves` (census) rebuilds the saves list from '%@/game/' / '%@/saves/' / iCloud
  'connectionList' with 12 fast-enumeration loops and the in-class save-dict helper 0x91b244 (x7).
- **Gesture front**: the pan/scroll handler gy_09 (census-lite, 40 branches) drives scrollVelocity/translationOffset/
  averageVelocity smoothing (Vector2 family, 250000.0 = 500^2 velocity cap, 0.025 blend) behind the
  requiresDirectionalSwipes -> allowsPanning -> [world loadComplete] gates and the hideAnyHideableUIDueToPanAtPoint:/
  startPinchOrPan/updateTranslationDueToPinchOrPan: chain; the secondary-touch trio start/move/cancel uses the
  secondaryTouchStarted/secondaryStartTouchHasntMoved/secondaryTouchIsActiveInUI byte triple, the 2.0-point movement
  threshold and world startTouch:tapCount:index: with index 1; `tapGesture:center:` routes taps chat-first
  (endEditingOrHide) then world tap:; `swipeGesture` mirrors [world requiresSwipeEvents].
- **Timers & exit paths**: `startTimer` arms the invisible connection watchdog - a GCD CreateDispatchTimer with the
  1.3833s interval (0x3fb11111) on the global queue whose source is parked in the class' BSS-tail statics (source pointer
  0x1063bfc, started flag 0x1063c01); `timeoutTimer` cancels/releases that source, tears down bhClient (release +
  cleanup + nil) and fires actuallyDoExitWorldRightNowReallyNow; `willResignActive` starts the watchdog while an ad/movie/
  IAP is up (movieViewInProgress/chartboostShowing/iapInProgress) and otherwise stops music
  ([[MJSoundManager instance] stopMusicForDeactivateEvent]) + pauses; `willEnterForeground` dismisses a stale double-time
  prompt (dismissWithClickedButtonIndex:0 animated:NO).
- **IAP front**: `paymentQueue:updatedTransactions:` switches 1/2/3 -> completeTransaction:/failedTransaction:/
  restoreTransaction:; `restoreTransaction:` gates on productIdentifier 'doubletimeb' (with a crystals/credit receipt
  JSON path via transactionReceipt) and on [world doubleTimeUnlocked], then credits double-time, cheers with
  'timeCrystalBuy.wav' and finishes the StoreKit transaction (+ NSUserDefaults hasBoughtIAP);
  `rewardIncentivizedVideoCurrency:` handles the rewarded-video payout (50000 = 0xc350 cap, CrystalManager
  modify:modifyString: with the obfuscated key '7acfe93afc08%dc65ae2c54ecaf07f' + stringFromMD5, 'Thank You!' alert,
  'timeCrystalBuy.wav', lastRewardedVideoTime timestamp, displayInterstitialForTag:'Hax');
  `paymentQueue:restoreCompletedTransactionsFailedWithError:` / `...Finished:` show the 'Purchase Verification Failed'
  alert / clear via iapCancelled; `startIncentivizedVideo` gates on HZIncentivizedAd hasRewardedVideoAvailable + the
  NSUserDefaults 'adConfig' != 'disabled'.
- **Ads/UI front**: `startupInterstitial` cascades self hasDisplayedAd/shouldDisplayInterstitial + HZInterstitialAd
  chartboostInitialized/hasPendingCreative/isAvailableForTag:'Startup' (fetchForTag:'Hax'/'Pause', retry via
  performSelector:withObject:afterDelay:, cmp 6); `shouldDisplayInterstitial` is the master eligibility predicate
  (totalGamePlayTimePassed > 600.0, hasBoughtIAP, the nil-chain over every blocking alert, 120-cooldown on
  'lastAdDisplayTime', [world uiManager] canDisplayAd).
- **Alert family texts pinned from CFString cells** (flags 0x7c8 objects): 'Failed To Save Data'/'An error occured while
  saving...File: %@'; 'Photo taken!'; 'Enable multiplayer and free crystals?' + the GDPR text + 'Allow'/"Don't Allow";
  'CONGRATS!'/'YOU NOW HAVE ALL YOU NEED TO WARP IN A %@ BLOCKHEAD!' + ordinal words 'SECOND'/'THIRD'/'FORTH'/'FIFTH' +
  'TO THE PORTAL!'/'NOT NOW'; 'R.I.P.'/'ARE YOU SURE YOU WISH TO LET %@ DIE PERMANENTLY?'/'LET %@ DIE'/"NO DON'T DIE!";
  'DOUBLE-TIME!' + the 'Craft at double speed...' text; 'LOW WORLD CREDIT!'/'%@ only has %@ of world credit remaining...'
  + the '1 HOUR'/'10 MINUTES'/'< 1 MINUTE' minutes mapping; 'WELCOME BACK!'; tutorial 'SKIP'/'OK';
  'Thank You!'/'Your purchase of double time has been restored...'.
- **Network/social front**: `startHostingNetworkGameWithUserName:userPhoto:` builds BHNetServerMatch (privacy 'public') +
  BHServer initWithDelegate:match:netNodeType:saveID:maxPlayers: (maxPlayers constant 6); `startSearchingFor...` builds
  BHNetClientMatch with a performSelector afterDelay search alert; `netClientMatchServerFound:` disposes the old client and
  connects [[BHClient alloc] initWithDelegate:self match:match netNodeType:([match isLocal] ? 1 : 3)];
  `multipleWorldsFoundForClientMatch:options:` is the 'CHOOSE WORLD:' TableSelectionAlertView ('OK'/'CANCEL' blocks);
  iCloud recents sync in `updateiCloudRecentConnectionList` (defaultStore arrayForKey:'connectionList', host/port/
  user/saveID/cloudKey fields, worldInfoForiCloudSave merge, removeLastObject cap) and
  `removeEntryFromiCloudRecentConnectionList:`; `sendMessage:` routes '/' commands to bhServer handleCommand:issueClient:
  and plain lines to sendChatMessage:sendToClients:.
- **Share/picker front**: `presentShareUIForImage:` / `presentShareUIForURL:message:rectFromScreenCenter:` build
  UIActivityViewController sheets (activity exclusions Message/AssignToContact/Print, share text 'I crafted a camera in
  #TheBlockheads and took this photo', completion handler sharePhotoFinished) with the iPad UIPopoverController path
  (helper 0x92432c rect, 80.0x120.0, windowInfo/glView); `startImagePickerWithDelegate:forRect:cropSize:` +
  `presentPickerUIWithSourceType:` drive the GKImagePicker/UIActionSheet ('Take Photo...'/'Choose From Library...'/
  'Cancel') + UIImagePickerController isSourceTypeAvailable: split; `popoverControllerDidDismissPopover:` restores the
  status bar and  finishes the delegate; `textField:shouldChangeCharactersInRange:replacementString:` caps input at 15
  chars and force-uppercases replacement text via setText:.
- **Misc verified constants**: 600.0 (0x4082c000; new-features threshold in gy_39 and play-time gate in gy_38), 120
  (0x78 ad cooldown), 250000.0 / 0.025 (gesture smoothing), 1024.0 (0x44800000 projection in resize:insets:), 2.0
  (secondary-touch movement threshold), 512 (0x200 default worldWidthMacro), 6 (maxPlayers; interstitial retry gate),
  50000 (0xc350 reward cap), 15 (chat length cap), 1.3833 (0x3fb11111 watchdog interval), 0xffffe600/0xffffe604 statics
  for the watchdog source + flag (BSS tail 0x1063bfc / 0x1063c01).

## Boundaries

- Static analysis only, bound to the pinned 1.7.6 libApplication.so (sha256 733d8210...94c7, armeabi-v7a); all 72 listings
  regenerate byte-identically via the pipeline gen_listings recipe and every word/cell/call/branch is re-verified by the
  build_specs coverage gate (words: 16,513).
- The census body gy_17 (populateGameSaves) is characterized by aggregate statistics (116 branches, 173 call rows, call
  histogram, selector/string/ivar sets) + the helper trace (0x91b244 x7 -> C function 0x944da8); its full branch trees
  stay in the listing. The 12 census-lite bodies (gy_00, gy_09, gy_14, gy_20, gy_21, gy_26, gy_27, gy_38, gy_43, gy_62, gy_64, gy_66) are characterized by the machine-extracted
  evidence (ordered selector/CFString/ivar/call maps) + targeted windows - not word-by-word.
- Block bodies are summarized: the CreateDispatchTimer block inside gy_54, the UIActivityViewController completion
  handlers inside gy_20/gy_21, and the ButtonAtIndex blocks of the alert family were not expanded instruction-by-
  instruction.
- The two watchdog statics (0x1063bfc source / 0x1063c01 flag) live in the zero-filled BSS tail beyond the file's
  0x10611b0 bytes; their runtime values are initializer-written, so the static file only proves the access pattern
  (strb 1 set at startTimer entry, strb 0 clear at timeoutTimer entry, pointer load in both), not stored values - hence "static timer storage"
  phrasing above.
- VFP immediates were read from the ELF directly (file offset == vaddr; struct.unpack) rather than from listing pool
  comments; r2 pool text was not trusted for the 600.0/1.3833/250000.0/0.025 values.
- The iOS UI/StoreKit/GameCenter/Chartboost/Heyzap surface has no Android runtime counterpart in the rebuild; its
  semantics are recorded for the app-shell logic (states, gates, save/network side effects), not for UI porting.
- gy_14's size-label constants (the '104'/'116' CFStrings) and gy_54's second timer constant (0xf08eb000 pair) are
  recorded as observed; their unit semantics were not further derivable from the listing alone.
