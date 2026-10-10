# World closure sweep part 1 (E114)

The World class closure sweep (part 1): the mid-size operational bodies and the UI/gate/forwarder tail. 70 bodies, 6190 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wx_00 | World -[setCustomSlotAtIndex:toItemType:count:] | 0x005d5f80 | 388 | 10 | 5 | 3 | 3 | 19 | 7 |
| wx_01 | World -[privateAddItemToFoundList:addBasketContents:] | 0x005d7f2c | 344 | 11 | 1 | 1 | 0 | 16 | 18 |
| wx_02 | World -[getCurrentCreditTimeString] | 0x005d2c7c | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| wx_03 | World -[addChestItemsToFoundList:] | 0x005d855c | 262 | 2 | 1 | 2 | 0 | 9 | 14 |
| wx_04 | World -[reportAchievementWithIdentifier:] | 0x005c47b8 | 212 | 11 | 3 | 0 | 5 | 11 | 1 |
| wx_05 | World -[sendUpdatedSunColor] | 0x005d6910 | 234 | 9 | 2 | 3 | 4 | 9 | 8 |
| wx_06 | World -[setSunColorRule:] | 0x005d6590 | 224 | 3 | 5 | 3 | 1 | 13 | 1 |
| wx_07 | World -[blockheadAvailablePromptDismissedWithToThePortal] | 0x005c8284 | 222 | 8 | 1 | 6 | 0 | 10 | 4 |
| wx_08 | World -[queueBlockheadAIActionToTile:atPos:forBlockhead:] | 0x005ab274 | 167 | 5 | 0 | 1 | 0 | 7 | 6 |
| wx_09 | World -[sendUpdatedCustomSlots] | 0x005d6cb8 | 196 | 7 | 2 | 3 | 3 | 7 | 2 |
| wx_10 | World -[startObservingMotionEvents] | 0x00566948 | 179 | 6 | 1 | 4 | 1 | 6 | 4 |
| wx_11 | World -[sendNewPrivacySettingToServer:] | 0x005d179c | 179 | 6 | 5 | 3 | 2 | 7 | 7 |
| wx_12 | World -[sendNewPasswordToServer:] | 0x005d1484 | 168 | 7 | 2 | 3 | 2 | 8 | 3 |
| wx_13 | World -[viewOrEditWelcomeMessage] | 0x005cf470 | 160 | 5 | 1 | 5 | 1 | 5 | 4 |
| wx_14 | World -[blockheadFilesReturnedFromServer:] | 0x005d8acc | 156 | 4 | 1 | 1 | 0 | 7 | 5 |
| wx_15 | World -[stopObservingMotionEvents] | 0x00566c14 | 148 | 4 | 1 | 4 | 0 | 6 | 4 |
| wx_16 | World -[serverFillReply:] | 0x005c61d4 | 144 | 3 | 1 | 1 | 0 | 6 | 5 |
| wx_17 | World -[welcomeMessageRecievedFromServer:] | 0x005cf858 | 125 | 4 | 3 | 3 | 0 | 5 | 1 |
| wx_18 | World -[showBlockheadAvailablePrompt:forBlockhead:] | 0x005c8094 | 124 | 4 | 1 | 3 | 0 | 4 | 7 |
| wx_19 | World -[sendUpdatedFoundItemsListToServer] | 0x005d7d54 | 118 | 4 | 1 | 3 | 1 | 4 | 1 |
| wx_20 | World -[tutorialAlertDismissedWithContinue:] | 0x005cdfbc | 110 | 5 | 1 | 1 | 1 | 5 | 3 |
| wx_21 | World -[pauseResumeButtonTapped] | 0x005b6410 | 107 | 4 | 2 | 2 | 0 | 4 | 2 |
| wx_22 | World -[imagePickerFinishedWithImage:] | 0x005cf010 | 106 | 5 | 1 | 2 | 1 | 5 | 0 |
| wx_23 | World -[setDpadControl:] | 0x005d79c8 | 102 | 4 | 2 | 1 | 1 | 4 | 3 |
| wx_24 | World -[appendDebugLog:] | 0x005cf1b8 | 95 | 2 | 3 | 3 | 0 | 3 | 0 |
| wx_25 | World -[setNewWelcomeMessage:] | 0x005cf6f0 | 90 | 3 | 1 | 3 | 0 | 3 | 4 |
| wx_26 | World -[startImagePickerWithDelegate:forRect:cropSize:] | 0x005ceebc | 85 | 3 | 0 | 2 | 0 | 3 | 0 |
| wx_27 | World -[setDpadDirectControlDisabled:] | 0x005d7b9c | 68 | 2 | 2 | 1 | 1 | 2 | 1 |
| wx_28 | World -[abortInProgressPathIfForBlockhead:] | 0x005c1cd0 | 67 | 3 | 1 | 1 | 0 | 3 | 2 |
| wx_29 | World -[incentivizedVideoViewComplete:] | 0x005c8d90 | 66 | 3 | 1 | 1 | 0 | 4 | 0 |
| wx_30 | World -[welcomeMessageDictRecieved:fromClient:] | 0x005cf370 | 64 | 3 | 2 | 1 | 0 | 3 | 0 |
| wx_31 | World -[textFieldShouldReturn:] | 0x005d2098 | 61 | 2 | 1 | 1 | 0 | 2 | 1 |
| wx_32 | World -[showTutorialPopupWithTitle:message:] | 0x005ce174 | 59 | 2 | 1 | 1 | 0 | 2 | 0 |
| wx_33 | World -[showWorldCreditUI] | 0x005d2b90 | 59 | 3 | 1 | 1 | 0 | 3 | 0 |
| wx_34 | World -[playersChanged] | 0x005c875c | 58 | 3 | 1 | 2 | 0 | 3 | 0 |
| wx_35 | World -[pauseExitToMenuButtonTapped] | 0x005b65bc | 55 | 1 | 1 | 0 | 0 | 3 | 0 |
| wx_36 | World -[canAddWorldCredit] | 0x005d2ab8 | 54 | 1 | 1 | 2 | 0 | 1 | 1 |
| wx_37 | World -[.cxx_destruct] | 0x005daa8c | 54 | 0 | 0 | 3 | 0 | 4 | 0 |
| wx_38 | World -[connected] | 0x00552d58 | 52 | 2 | 3 | 0 | 1 | 3 | 0 |
| wx_39 | World -[addItemToFoundList:] | 0x005d848c | 52 | 1 | 1 | 2 | 0 | 1 | 2 |
| wx_40 | World -[cancelAllActionsAtPos:orWithInteractionObjectID:] | 0x005ab1ac | 50 | 2 | 0 | 1 | 0 | 2 | 0 |
| wx_41 | World -[shareURL:message:fromRect:] | 0x005d3348 | 50 | 1 | 0 | 0 | 0 | 1 | 0 |
| wx_42 | World -[openOwnerPortal] | 0x005d3474 | 49 | 2 | 1 | 2 | 0 | 2 | 0 |
| wx_43 | World -[saveSunlightChangedAtPos:] | 0x005be2cc | 43 | 1 | 0 | 1 | 0 | 2 | 0 |
| wx_44 | World -[newServerPasswordSet:] | 0x005d13d8 | 43 | 2 | 1 | 1 | 0 | 2 | 0 |
| wx_45 | World -[pauseButtonTapped] | 0x005b6368 | 42 | 2 | 1 | 1 | 0 | 2 | 1 |
| wx_46 | World -[playerIsMuted:] | 0x005cfe00 | 41 | 2 | 1 | 1 | 0 | 2 | 0 |
| wx_47 | World -[worldUIDragging] | 0x005bddac | 36 | 2 | 1 | 1 | 0 | 2 | 0 |
| wx_48 | World -[currentTotalBlockheadCountIncludingNet] | 0x005c8660 | 35 | 2 | 1 | 1 | 0 | 2 | 0 |
| wx_49 | World -[customRulesChanged] | 0x005d5684 | 35 | 2 | 1 | 1 | 0 | 2 | 0 |
| wx_50 | World -[foundListContainsEggWithDodoBreed:] | 0x005d89ec | 31 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_51 | World -[customRuleForOptionNamed:] | 0x005d560c | 30 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_52 | World -[addDodoEggToFoundListWithBreed:] | 0x005d8974 | 30 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_53 | World -[isControllingBlockheadsForClientPlayer:] | 0x005c86ec | 28 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_54 | World -[updatePhysicalBlockToLatestVersion:] | 0x005c8844 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_55 | World -[showDieConfirmationForBlockhead:] | 0x005cee00 | 27 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_56 | World -[addItemsFromServerFoundItemsList:] | 0x005d7ce8 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_57 | World -[archiveLightBlocksForClient:] | 0x005d8f0c | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_58 | World -[setPinchScale:] | 0x005da33c | 27 | 0 | 0 | 1 | 0 | 1 | 0 |
| wx_59 | World -[mapVisible] | 0x005c8d28 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_60 | World -[banPlayerWithNameFromPlayerButton:] | 0x005d0c5c | 26 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_61 | World -[kickPlayerWithNameFromPlayerButton:] | 0x005d0cc4 | 26 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_62 | World -[hasRewardedVideoAvailable] | 0x005d704c | 26 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_63 | World -[iapStarted] | 0x005c2790 | 25 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_64 | World -[startIncentivizedVideo] | 0x005c27f4 | 25 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_65 | World -[achievementsButtonTapped] | 0x005c4b60 | 25 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_66 | World -[instructionsButtonTapped] | 0x005c4bc4 | 25 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_67 | World -[chatButton] | 0x005c85fc | 25 | 1 | 1 | 0 | 0 | 1 | 0 |
| wx_68 | World -[worldUI] | 0x005d3410 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| wx_69 | World -[hideChatView] | 0x005d8a68 | 25 | 1 | 1 | 0 | 0 | 1 | 0 |

## What this sweep closes

The World class closure sweep (part 1 of 2): the mid-size operational bodies
plus the UI/gate/forwarder tail. Load-bearing picks:

- **setCustomSlotAtIndex:toItemType:count:** (388w) - the custom-slot editor
  (arrayWithArray:/replaceObjectAtIndex:withObject: + clampi +
  itemTypeIsStackable clamp, expertMode gate, 0x559f78 helper).
- **privateAddItemToFoundList:addBasketContents:** (344w) - the recursive
  found-list add (containsIndex: dedup, subItems recursion, the dodo-egg
  path).
- **reportAchievementWithIdentifier:** (212w) - the Game Center bridge
  (GKAchievement initWithIdentifier:/setPercentComplete: 0x64 = 100 +
  GKLocalPlayer reportAchievements:withCompletionHandler: + the
  NSUserDefaults latch).
- **.cxx_destruct** (54w) - std::unordered_set<PhysicalBlock> dtor x2 +
  std::map<int, unsigned char> dtor x1: the member set E113's .cxx_construct
  opens, now closed at both ends.
- **pauseExitToMenuButtonTapped** (55w) - __android_log_print x2 then
  exitWorld: the Android log-bridge stub inside the cross-platform build.
- The sun-color pair (sendUpdatedSunColor 234w / setSunColorRule: 224w) and
  the custom-slots pair (sendUpdatedCustomSlots 196w / the wc_00 editor) -
  the plist+gzip+send family again (0x42/0x64), with 0x559f78 as the shared
  helper.
- The motion pair (startObservingMotionEvents 179w / stopObservingMotionEvents
  148w) - NSTimer + CMMotionManager feed driving the E107 acceleration
  pipeline; setDpadControl: toggles it with the NSUserDefaults latch.
- The security packet pair (sendNewPrivacySettingToServer: 179w /
  sendNewPasswordToServer: 168w) - helper 0x55468c sixth appearance.
- **connected** (52w) - the Reachability class (reachabilityWithHostName: +
  currentReachabilityStatus).
- The UI/gate tail - prompt picker/show (wx_07/18), welcome-message trio
  (wx_13/17/25), image-picker pair (wx_22/26), share sheet, owner portal,
  mute/kick/ban wrappers, tutorial popups and the 25w one-line forwarders;
  setPinchScale: (27w) is the objc_copyStruct 8-byte copy into the pinchScale
  field.

## Boundaries

- All seventy bodies read in full or near-full (max 388w); summary-style
  semantics for the sub-60w forwarders.
- The helper selectors (0x5ab510/0x559f78/0x559f54/0x55468c) are recorded as
  call sites with known identities from earlier batches.
- wx_63 and wx_65 listings are trimmed at the next IMP; headers keep the
  extracted ends.
