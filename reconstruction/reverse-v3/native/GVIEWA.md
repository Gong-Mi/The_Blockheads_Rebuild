# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 15107 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| gx_00 | GameView -[.cxx_construct] | 0x00944c64 | 81 | 0 | 0 | 7 | 0 | 7 | 0 |
| gx_01 | GameView -[acceleration:] | 0x0092bc24 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| gx_02 | GameView -[achievementViewControllerDidFinish:] | 0x0093c6c8 | 30 | 1 | 1 | 1 | 0 | 1 | 0 |
| gx_03 | GameView -[achievementsButtonTapped] | 0x0093c420 | 170 | 10 | 2 | 1 | 3 | 10 | 3 |
| gx_04 | GameView -[actionSheet:didDismissWithButtonIndex:] | 0x00923d68 | 132 | 5 | 1 | 2 | 1 | 5 | 4 |
| gx_05 | GameView -[actuallyDoExitWorldRightNowReallyNow] | 0x00931aec | 737 | 21 | 5 | 15 | 3 | 36 | 8 |
| gx_06 | GameView -[alertView:clickedButtonAtIndex:] | 0x00944558 | 156 | 6 | 5 | 0 | 2 | 8 | 4 |
| gx_07 | GameView -[alertView:didDismissWithButtonIndex:] | 0x00939c3c | 477 | 12 | 2 | 10 | 3 | 21 | 16 |
| gx_08 | GameView -[allowsFPSRateCut] | 0x0093c7d8 | 39 | 0 | 0 | 2 | 0 | 0 | 1 |
| gx_09 | GameView -[allowsRotation] | 0x00938dac | 103 | 1 | 1 | 5 | 0 | 1 | 5 |
| gx_10 | GameView -[appDatabase] | 0x0094491c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gx_11 | GameView -[appDatabaseEnvironment] | 0x00944960 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gx_12 | GameView -[authenticateGameCenter] | 0x00921064 | 131 | 5 | 3 | 2 | 2 | 4 | 3 |
| gx_13 | GameView -[cancelSelectedWhileAttemptingToConnect] | 0x00939580 | 37 | 2 | 1 | 1 | 0 | 2 | 0 |
| gx_14 | GameView -[cancelTimer] | 0x00917d20 | 38 | 0 | 0 | 0 | 0 | 2 | 1 |
| gx_15 | GameView -[chartboostIncentivizedVideoViewComplete:] | 0x00942178 | 63 | 3 | 1 | 1 | 1 | 2 | 0 |
| gx_16 | GameView -[chatHaxOngoing] | 0x00944b68 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| gx_17 | GameView -[chatMessageRecieved:displayNotification:] | 0x0093fb3c | 222 | 9 | 2 | 4 | 1 | 9 | 7 |
| gx_18 | GameView -[chatViewBack] | 0x0093f8c4 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| gx_19 | GameView -[chatViewOpen] | 0x0093f7d8 | 59 | 2 | 1 | 1 | 0 | 2 | 1 |
| gx_20 | GameView -[chatViewVisible] | 0x0093f770 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| gx_21 | GameView -[checkForLikeAfterActivate] | 0x0091b500 | 506 | 19 | 10 | 1 | 5 | 29 | 8 |
| gx_22 | GameView -[cleanupSearchingMatch] | 0x009352ac | 81 | 4 | 1 | 1 | 0 | 4 | 0 |
| gx_23 | GameView -[clearChat] | 0x0093feb4 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| gx_24 | GameView -[cloudAuthenticateCompleteWasSuccess:] | 0x0092f8dc | 34 | 1 | 1 | 1 | 0 | 1 | 1 |
| gx_25 | GameView -[cloudAuthenticateContainedCrystals:] | 0x0091bce8 | 317 | 12 | 5 | 1 | 3 | 20 | 7 |
| gx_26 | GameView -[cloudAuthenticateContainedMessageWithTitle:message:] | 0x0091c1dc | 259 | 11 | 4 | 2 | 2 | 11 | 3 |
| gx_27 | GameView -[cloudAuthenticateUnlockedCloudFeatures] | 0x00940e88 | 39 | 1 | 1 | 1 | 0 | 1 | 1 |
| gx_28 | GameView -[cloudWorldWasCreatedWithID:worldName:userName:userPhoto:timeSelection:] | 0x00942c04 | 884 | 21 | 17 | 3 | 6 | 53 | 4 |
| gx_29 | GameView -[completeTransaction:] | 0x00922110 | 1287 | 46 | 30 | 6 | 11 | 71 | 35 |
| gx_30 | GameView -[connectionSucceededToMultiplayerServerWithWorldInfo:] | 0x00936348 | 333 | 8 | 6 | 10 | 0 | 18 | 0 |
| gx_31 | GameView -[connectionToServerLostShouldRetry:] | 0x009390c8 | 302 | 8 | 7 | 4 | 1 | 10 | 5 |
| gx_32 | GameView -[connectionToServerOK] | 0x00938f48 | 96 | 3 | 1 | 2 | 0 | 3 | 2 |
| gx_33 | GameView -[connectionToServerRejectedForReason:extraDataDict:] | 0x00939614 | 394 | 8 | 20 | 5 | 1 | 11 | 24 |
| gx_34 | GameView -[customRulesHTMLTextForRules:buttonTitle:] | 0x0093687c | 1355 | 16 | 26 | 5 | 2 | 60 | 60 |
| gx_35 | GameView -[dealloc] | 0x00920374 | 138 | 3 | 2 | 5 | 1 | 8 | 0 |
| gx_36 | GameView -[delayedOpenURLIfNeeded] | 0x00940284 | 720 | 16 | 7 | 6 | 1 | 36 | 22 |
| gx_37 | GameView -[deleteSaveFile:] | 0x00932e80 | 229 | 7 | 1 | 0 | 1 | 12 | 8 |
| gx_38 | GameView -[deleteWorldAtIndex:] | 0x00933214 | 794 | 17 | 7 | 4 | 3 | 40 | 23 |
| gx_39 | GameView -[didBecomeActive] | 0x0092f964 | 1172 | 36 | 7 | 18 | 8 | 60 | 26 |
| gx_40 | GameView -[didCompleteAdWithTag:] | 0x0093c008 | 65 | 3 | 1 | 1 | 1 | 2 | 0 |
| gx_41 | GameView -[didEnterBackground] | 0x00930bb4 | 404 | 15 | 1 | 8 | 2 | 17 | 11 |
| gx_42 | GameView -[didHideAdWithTag:] | 0x0093bf58 | 44 | 2 | 1 | 1 | 0 | 2 | 0 |
| gx_43 | GameView -[didShowAdWithTag:] | 0x0093bdb8 | 104 | 5 | 2 | 1 | 2 | 5 | 0 |
| gx_44 | GameView -[displayGameCenterAccountAlertView:] | 0x0093c10c | 197 | 6 | 4 | 2 | 3 | 8 | 3 |
| gx_45 | GameView -[displayInterstitialForTag:] | 0x0093bc40 | 94 | 5 | 1 | 1 | 1 | 5 | 1 |
| gx_46 | GameView -[displaySearchingAlertIfShould] | 0x00934d78 | 129 | 3 | 4 | 4 | 1 | 3 | 4 |
| gx_47 | GameView -[doExitWorld] | 0x00932670 | 415 | 9 | 1 | 7 | 0 | 23 | 5 |
| gx_48 | GameView -[doubleTapGesture:center:] | 0x0092edac | 53 | 1 | 0 | 3 | 0 | 1 | 1 |
| gx_49 | GameView -[exitWorld] | 0x00932cec | 101 | 3 | 1 | 3 | 0 | 5 | 0 |
| gx_50 | GameView -[failedTransaction:] | 0x009253bc | 164 | 10 | 4 | 0 | 3 | 10 | 1 |
| gx_51 | GameView -[fileWriteFailed:] | 0x009207e0 | 31 | 2 | 1 | 0 | 0 | 1 | 0 |
| gx_52 | GameView -[gameCenterViewControllerDidFinish:] | 0x0093c740 | 30 | 1 | 1 | 1 | 0 | 1 | 0 |
| gx_53 | GameView -[gameSaves] | 0x009448d8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gx_54 | GameView -[gameSoundFinshedFadingOut] | 0x0093a718 | 120 | 6 | 3 | 0 | 2 | 8 | 0 |
| gx_55 | GameView -[gdprPrompt] | 0x00944be4 | 16 | 0 | 0 | 0 | 0 | 0 | 0 |
| gx_56 | GameView -[getDefaultGameSaveForWorldWithID:] | 0x0091b268 | 166 | 4 | 2 | 1 | 1 | 7 | 8 |
| gx_57 | GameView -[glView] | 0x00944850 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gx_58 | GameView -[handleOpenURL:] | 0x00940dc4 | 49 | 2 | 1 | 1 | 0 | 2 | 0 |
| gx_59 | GameView -[hasRewardedVideoAvailable] | 0x00940ff0 | 78 | 4 | 3 | 0 | 2 | 4 | 2 |
| gx_60 | GameView -[heyzapAdFailed] | 0x00920f28 | 36 | 2 | 1 | 0 | 1 | 2 | 0 |
| gx_61 | GameView -[heyzapAdHidden] | 0x00920fb8 | 43 | 2 | 1 | 1 | 0 | 2 | 0 |
| gx_62 | GameView -[hideChatView] | 0x0093f70c | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| gx_63 | GameView -[iapCancelled] | 0x00923778 | 58 | 2 | 1 | 3 | 0 | 3 | 0 |
| gx_64 | GameView -[iapCompleted] | 0x00923698 | 56 | 2 | 1 | 3 | 0 | 3 | 0 |
| gx_65 | GameView -[iapStarted] | 0x00923860 | 46 | 2 | 1 | 2 | 0 | 2 | 0 |
| gx_66 | GameView -[imagePicker:pickedImage:] | 0x00924378 | 244 | 10 | 1 | 4 | 2 | 11 | 6 |
| gx_67 | GameView -[imagePickerDidCancel:] | 0x00924748 | 242 | 10 | 1 | 4 | 2 | 11 | 6 |
| gx_68 | GameView -[initAds] | 0x0092085c | 207 | 11 | 3 | 0 | 3 | 10 | 0 |
| gx_69 | GameView -[instructionsButtonTapped] | 0x0093c9cc | 215 | 7 | 3 | 2 | 2 | 10 | 6 |
| gx_70 | GameView -[instructionsViewController] | 0x00944a2c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| gx_71 | GameView -[instructionsViewDone] | 0x0093cd28 | 72 | 2 | 1 | 2 | 0 | 2 | 1 |

## Findings (E130)

**Batch: GameView, first half (selectors a..i), 72 bodies / 15,107 words.** All
class GameView; listings `gx_00..gx_71` (+ `_gl`) in this batch dir, roster +
`specs_a.json` (72 bodies, 722 call rows, 14 routes). GameView is the
application-shell class of the port (Game Center, Heyzap/Chartboost ads, IAP,
chat, iCloud, modal alerts, lifecycle) - not the world renderer; the sibling
batch (gameview-b) carries the rest of the selectors.

Reading depth per the batch conventions: the 57 bodies <=300w were read in
full; the 12 bodies 300-1000w (gx_05, gx_07, gx_21, gx_25, gx_28, gx_30,
gx_31, gx_33, gx_36, gx_38, gx_41, gx_47) via an annotated register trace
(`_work/tracer.py`, which recovers the Apportable offset-cell route through
frame spills) plus send-sequence digests and targeted raw reads; the 3
census-tier bodies (gx_29 1287w, gx_34 1355w, gx_39 1172w) structurally
(send tables, branch skeleton, string/ivar features, one jump-table decode).

- **The GameView ivar map is fully pinned** (native/class_metadata.json,
  `OBJC_IVAR_$_GameView.*`, 112 ivars, instance size 520): viewController@4,
  glView@8, cache@12, basicShader@16, mainMenuUI@20, world@24,
  instructionsViewController@28, appDatabaseEnvironment@32, appDatabase@36,
  bhClient@40, bhServer@44, projectionMatrix@48 (64B), cameraZ@112, the
  seven Vector2 touch/pinch members@116..192, windowInfo@208 (32B),
  continueTapped..joinWorldTapped@240/241/242, multiplayerWorldData(W
  aiting)@244/248, gameSaves@252, loadIndex@256, loadWorldName@260,
  loadSaveID@264, paused@270, totalGamePlayTimePassed@272, timeCounter@280,
  the alert-view set (disconnect@296, joinWorld@300, fileWrite@304,
  doubleTimePrompt@308, welcomeBack@312, blockheadPrompt@316, tutorial@320,
  crystalsAdded@324, gameCenterAccount@348, diePrompt@448, lowCredit@464,
  cloudMessage@468, confirm@472, gdprPrompt@516), localGKName@332, the GC
  flags@336..362 (matchWillBeServer, matchMakerIsAddingToGame, hasBoughtIAP,
  hasAuthenticatedGameCenter@358, isInProgressOfAuthenticatingGameCenter@359,
  hasRenderedFrameSinceActivate@362), searchingClientMatch@376,
  imagePickerDelegate@384, chatView@396, imagePicker@400/imagePickerActionSheet
  @404, gameCenterFriends@428, worldWidthMacro@432, customRules@436,
  recentConnectionsList@444, cloudInterface@456, showAddCreditAfterWorldExited
  Info@460, urlToOpenOnceLoaded@480, videoNetworkPingPongIsVungle@484,
  startTouchPos@488/secondaryStartTouchPos@500 (CGPoint), iapInProgress@510,
  pickerShowing@511, welcomeMessageShowing@512, chatHaxOngoing@513,
  gdprPrompt@516. gx_00 `.cxx_construct` is the Vector2 constructor pass
  (touchStartPos, touchStartTranslation, pinchStartOffset, pinchOffset,
  translationOffset, scrollVelocity, averageVelocity - construction order).

- **The exit chain is three-deep and now mapped**: `exitWorld` (gx_49):
  logs ("Evolution"/"exitWorld start"), needsToExitWorld@292 = YES,
  [world doPortalShotNextFrame], [world saveAll], [chatView release] + nil.
  `doExitWorld` (gx_47): dismisses the instructions view, then branches on
  [world loadComplete] - true: [world saveAll] + [world
  finishBulkDatabaseUpdate]; both: [self setPaused:] + [self
  actuallyDoExitWorldRightNowReallyNow]; tail cleans bhServer/bhClient/
  chatView. `actuallyDoExitWorldRightNowReallyNow` (gx_05, 737w, census-lite):
  world/server/client teardown, early-return when world==nil, then
  instructions dismissal, diePrompt/lowCredit alert dismissals, releases
  (world, chatView, loadWorldName, multiplayerWorldData, mainMenuUI),
  [self populateGameSaves], music handoff (if [MJSoundManager instance]
  isPlayingMP3 -> fadeOutMP3PlaybackWithFinishNotificationObject:...action:
  @selector(gameSoundFinshedFadingOut) else play GameResources/
  mountainKingLoop.mp4 with setLoopMP3s:YES), and a fresh
  [[MainMenuUI alloc] initWithDelegate:self windowInfo:cache:cloudInterface:]
  with the deferred add-credit prompt
  (presentAddCreditUIForWorldWithName:worldID:currentCredit: from
  showAddCreditAfterWorldExitedInfo["worldID"/"worldName"]).

- **Game Center / GPGS**: authenticateGameCenter (gx_12) checks
  boolForKey:@"GPGSShouldSignIn" and hasAuthenticatedGameCenter@358, then
  sets isInProgressOfAuthenticatingGameCenter@359 = YES and installs
  [[GKLocalPlayer localPlayer] setAuthenticateHandler:<captured block>].
  achievementsButtonTapped (gx_03) branches on isAuthenticated: present
  GKAchievementViewController (setAchievementDelegate:self, present from
  self.viewController, release) or setBool:YES forKey:@"GPGSShouldSignIn" +
  [self authenticateGameCenter]. displayGameCenterAccountAlertView:(message)
  (gx_44) gates on isInProgressOfAuthenticatingGameCenter and canOpenURL:
  "gamecenter:/me/account"; the alert is title "Sign In", cancel "Cancel",
  extra button "Sign In". gx_07's didDismiss handler: the fileWrite alert
  dismissal calls __wrap_exit(0) (process exit), the gameCenterAccount alert
  with button 1 opens the gamecenter URL, and each dismissal path ends with
  [mainMenuUI multiplayerGameSelectCancelled].

- **GDPR flow**: gx_06 alertView:clickedButtonAtIndex: writes
  [NSUserDefaults standardUserDefaults] setInteger:(buttonIndex==1 ? 2 : 3)
  forKey:@"gdprStatus" when alertView == gdprPrompt@516, and then - on every
  path of the body - builds and shows (and autoreleases) the privacy
  restart alert ("Privacy Setting Changed" / "Please restart the game for
  the new setting to take effect." / "OK"). gx_55 is the gdprPrompt getter.

- **Ads (Heyzap + Chartboost)**: initAds (gx_68) starts Heyzap with
  publisher id "7e4482c1be37901e95ec6b42c8e14e21", sets the HZInterstitialAd
  delegate, prefetches tag "Startup", registers two
  NSNotificationCenter addObserver:self calls (@selector(heyzapAdHidden) and
  @selector(heyzapAdFailed), file-scope name constants), then
  [[self viewController] setChartboostInitialized:YES] and
  [self performSelector:@selector(startupInterstitial) afterDelay:1.0].
  displayInterstitialForTag: (gx_45) checks isAvailableForTag:, sets
  chartboostShowing + movieViewInProgress@425 then showForTag:/fetchForTag:.
  Rewarded video: chartboostIncentivizedVideoViewComplete (gx_15) rewards the
  callback's int argument after 0.1s via
  performSelector:@selector(rewardIncentivizedVideoCurrency:) +
  [NSNumber numberWithInt:]; didCompleteAdWithTag: (gx_40) grants the fixed
  20; didShowAdWithTag:/didHideAdWithTag:/heyzapAdHidden/heyzapAdFailed/
  chartboost state via setChartboostShowing: and movieViewInProgress@425,
  and didShowAdWithTag: records
  [NSDate timeIntervalSinceReferenceDate] under "lastAdDisplayTime".
  hasRewardedVideoAvailable (gx_59) returns NO when
  defaults["adConfig"] == "disabled", else [HZIncentivizedAd isAvailable].

- **IAP (gx_29 completeTransaction: 1287w, census)**: dispatch on
  [transaction payment].productIdentifier - "doubletimeb" ->
  [self.world purchaseDoubleTime] + "timeCrystalBuy.wav" + "Thank You!"
  alert; "7dayscredit"/"30dayscredit" and crystal SKUs
  ("crystalsage","crystalsepoch","crystalsera","crystalseon") route through
  the receipt (transactionReceipt -> NSJSONSerialization ->
  purchaseToken/productId, SKPaymentTransactionReceiptSignedData) ->
  NSDictionary dictionaryWithObjectsAndKeys: -> local helper 0x0092352c ->
  [self.appDatabase setData:... forKey:@"last_receipt"...] and
  [self.world IAPForWorldTopupSucceeeded:transactionID:] /
  [self.mainMenuUI IAPForWorldCreationOrTopupSucceeeded:transactionID:].
  The crystal path shares the MD5 "purchase token" scheme (see below) plus
  [world timeCrystalCloseButtonTapped] + [world crystalsPurchased] +
  [self displayInterstitialForTag:@"Hax"]. Tail: [[SKPaymentQueue
  defaultQueue] finishTransaction:], consumePurchase:, defaults
  setBool:YES forKey:@"hasBoughtIAP", setInteger: forKey:
  "totalTCBuyCount", [self iapCompleted]. failedTransaction: (gx_50) skips
  the alert for code 2 (SKErrorPaymentCancelled) and always finishes the
  transaction and calls [self iapCancelled]; iapStarted/iapCompleted/
  iapCancelled (gx_65/64/63) toggle iapInProgress@510 and notify
  [world uiManager] and mainMenuUI.

- **The crystal "purchase token" scheme recurs in four bodies**: the two MD5
  templates `7acfe93afc08%dc65ae2c54ecaf07f` / `7acfe93afc08c%d65ae2c54e
  caf07f` + stringFromMD5 are used by checkForLikeAfterActivate (gx_21,
  keychain service "com.majicjungle.blockheads.liked" via SFHFKeychainUtils,
  single "Thank You!" like reward + "Hax" interstitial),
  cloudAuthenticateContainedCrystals: (gx_25, iCloud grant), the crystal path
  of completeTransaction: (gx_29) and didBecomeActive: (gx_39); each ends in
  [CrystalManager instance] modify:modifyString: / amountString /
  commitSaveIfNeeded + [world crystalsPurchased] + "timeCrystalBuy.wav".

- **Chat (gx_17-23, 62)**: chatMessageRecieved:displayNotification: gates on
  needsToExitWorld@292 and [world playerIsMuted:[world objectForKey:
  "playerID"]], lazily builds chatView = [[ChatView alloc] init] @396 with
  setDelegate:self, overrides the notification flag with
  ![[world uiManager] chatNotificationsShouldBeSupressed], then
  [chatView addChatMessage:message displayNotification:] and
  [chatView showInView:self.glView isNotification:YES displayTextEntry:NO].
  clearChat/hideChatView/chatViewBack/open/visible (gx_23/62/18/19/20) route
  straight into ChatView (clear/hide/endEditingOrHide/visible/isNotification).

- **iCloud**: cloudWorldWasCreatedWithID:worldName:userName:userPhoto:
  timeSelection: (gx_28, 884w) installs a world under
  "%@/saves/%@"(worldID)/, writes the "worldv2" plist (saveVersion,
  migrationComplete_1.7, connectionDate, creationDate, cloudGame,
  remoteGame, playerID, userName, worldName, saveDate, saveID =
  lowercaseString + stringFromMD5), prepends to recentConnectionsList@444,
  rewrites "%@/game/recentConnections" + updateiCloudRecentConnectionList,
  and copies avatar.png to "%@/saves/%@/avatar_%@_.png" via
  copyItemAtPath:toPath:error:; ends with populateGameSaves +
  [mainMenuUI gameSavesChanged]. cloudAuthenticateCompleteWasSuccess: /
  cloudAuthenticateContainedMessageWithTitle:message: /
  cloudAuthenticateUnlockedCloudFeatures (gx_24/26/27) cover the ready
  banner, the BlockAlertView (uppercased title/message, OK button block,
  world paused via pauseButtonTapped + uiManager setHidePauseUI:YES) and
  mainMenuUI selectJoinOption.

- **Multiplayer session callbacks**: connectionSucceeded... (gx_30) dismisses
  joinWorldAlertView@300, reloads expertMode@440/worldWidthMacro@432/
  pvpDisabledWhenLoadingGame@269/loadWorldName@260/customRules@436 from the
  world info and calls the local helper 0x0091b244. connectionToServerOK
  (gx_32) dismisses+releases disconnectAlertView unless
  disconnectAlertViewShouldExitWhenDismissed@328. connectionToServerLost
  ShouldRetry: (gx_31) tears the session down ([world connectionToServerLost]
  + pauseButtonTapped) and posts "Disconnected"/"The connection was lost."/OK
  or "Connection Issue"/"Attempting to reconnect..."/"Exit".
  connectionToServerRejectedForReason:extraDataDict: (gx_33) resolves the
  rejection reason through a 15-entry jump table (sub r0,r0,1; cmp r0,0xe;
  `add pc,pc,r0,lsl #2` @0x939938, table @0x93993c) into the server-message
  set: 1 banned-from-connecting, 2 invalid-username, 3/4 another-player-
  logged-in, 5 username-in-use-by-another-device, 6 whitelist, 7 device-
  username-conflict ("running actions for another username..."), 8
  incorrect-key, 9 incorrect-password, 10 kicked, 11 banned, 14 max-players,
  13/fallback "The server rejected your connection request. Please try again
  later." (title "Connection failed", OK). GKMatchmaker sharedMatchmaker
  cancel is the Cancel path of the join alert (gx_07).

- **Gates/derivations**: allowsFPSRateCut (gx_08) = (bhClient==nil &&
  bhServer==nil); allowsRotation (gx_09) = all four modal alerts nil &&
  (world==nil || [world allowsRotation]); displaySearchingAlertIfShould
  (gx_46) requires joinWorldAlertView nil + searchingClientMatch != nil +
  multi-player selection alert nil + world nil; didEnterBackground (gx_41)
  gates the client teardown on pickerShowing@511 / movieViewInProgress@425 /
  [viewController chartboostShowing] / welcomeMessageShowing@512 /
  iapInProgress@510 / chatHaxOngoing@513 all clear, saves the world and
  exits it, then clears pickerShowing and cleanupSearchingMatch.
  didBecomeActive (gx_39, 1172w, census) re-arms everything: cancelTimer,
  chartboost reset, cloud reconnect, populateGameSaves +
  selectMostRecentlyPlayedWorld, the crystal token reconcile,
  checkForLikeAfterActivate, [[MJSoundManager instance]
  restartMusicAfterActiveEvent:], [world startSimulatingIfNeeded], a
  MainMenuUI resume progress UI (startWorldLoadingWithName:worldSize:
  isGenerating: + setProgress:), stale alert dismissal,
  [[TradeMissionManager instance] reCheckForMissions] and the
  GPGSShouldSignIn default update.

- **Misc smalls**: deleteSaveFile: recurses a directory tree then
  removeItemAtPath (gx_37); deleteWorldAtIndex: prunes recentConnections/
  deletes the save dir + database key "%@_worldv2" (gx_38); instructions
  flow builds InstructionsView/InstructionsViewiPhone nibs, setGameView: and
  present/dismiss (gx_69/70/71); image picker flow (gx_04/66/67) toggles the
  status bar and iPad popover vs view-controller dismissal; fileWriteFailed:
  hops to the main thread via performSelectorOnMainThread (gx_51); cancelTimer
  (gx_14) cancels/releases the file-scope dispatch source; gx_01
  `acceleration:` is a dead-store stub; gx_16/chatHaxOngoing@513 and
  gx_10/11/53/57/55/70 are offset-cell getters (dmb ish), gx_56 returns the
  game-save dict by "saveID" (or an empty NSDictionary).

## Boundaries

- **Depth by tier.** Full read: the 57 bodies <=300w. Census-lite (annotated
  trace + digest + targeted raw spans): gx_05, gx_07, gx_21, gx_25, gx_28,
  gx_30, gx_31, gx_33, gx_36, gx_38, gx_41, gx_47. Census (send/branch/ivar/
  string tables + selective spans): gx_29, gx_34, gx_39. No body was
  executed; all claims are static reads of the pinned ELF
  (sha256 733d8210...c94c7), resolved through the reloc/dynsym routes and
  direct `struct` reads (constant pool never taken from the disassembler).
- **gx_68**: the two addObserver `name:` constants are file-scope cells that
  are only loader-filled (values not statically resolvable, shown as
  `slot ... word 0`/data pointers); the `object:` operand and the
  performSelector `withObject:` operand are likewise not pinned.
- **gx_36**: the `enable-cloud` branch performs a struct-returning
  objc_msgSend_stret call whose operands were not fully decoded; the
  query-parameter paths (id/name, ip/port, host/port with default "15151")
  are from the annotated trace only.
- **gx_29**: the exact split of "7dayscredit"/"30dayscredit" versus the
  crystal SKUs across the receipt helper (0x0092352c) vs the crystal-token
  branch was summarized, not line-verified; local helpers 0x0092352c and
  0x0091b244 have no dynsym names.
- **gx_33**: reason codes 12 and 15 targets did not resolve to a distinct
  string in the probed windows (likely sharing existing messages or the
  default); codes 1-11, 13, 14 are machine-verified against their CFStrings.
- **Call arguments stated as `[self setPaused:]` (gx_47) and several
  dismissWithClickedButtonIndex:animated: argument pairs** (gx_05's alert
  dismissals) were not value-pinned; -1/animated:YES is only asserted where
  the imm/register value was read (gx_32, gx_41).
- **gx_39**: the two `setBool:? forKey:@"GPGSShouldSignIn"` sites'
  YES/NO mapping per isAuthenticated result was not value-pinned.
- **Block literals** captured by sends (gx_26 OK block, gx_12 auth-handler
  block, gx_68 stack block) have their invoke functions outside the body
  range; only the construction site is recorded.
- Every callee outside the 72 body ranges (World, UIManager, ChatView,
  CrystalManager, BHClient/BHServer, ...) is recorded at call-site level
  only - their behavior is covered by their own batches.
