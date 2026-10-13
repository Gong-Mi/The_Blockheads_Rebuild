# JoinWorldUI (E137)

The join-world screen class lands: server list handling, the connection flow, password entry and the world-card render. 50 bodies, 36441 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| jw_00 | JoinWorldUI -[advancedButton:] | 0x0061b710 | 1021 | 9 | 8 | 6 | 1 | 27 | 27 |
| jw_01 | JoinWorldUI -[advancedCancelButton:] | 0x0061c704 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| jw_02 | JoinWorldUI -[advancedLocalNetworkButton:] | 0x0061c74c | 93 | 4 | 2 | 2 | 0 | 4 | 0 |
| jw_03 | JoinWorldUI -[advancedOnlineButton:] | 0x0061c8c0 | 1718 | 26 | 8 | 15 | 6 | 38 | 56 |
| jw_04 | JoinWorldUI -[advancedSearchButton:] | 0x0061fd00 | 1799 | 24 | 8 | 11 | 3 | 39 | 62 |
| jw_05 | JoinWorldUI -[alertView:didDismissWithButtonIndex:] | 0x0061e914 | 561 | 15 | 3 | 10 | 1 | 30 | 19 |
| jw_06 | JoinWorldUI -[cloudConnectionCancelled] | 0x006221fc | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| jw_07 | JoinWorldUI -[cloudConnectionFailed:presentTopupUI:] | 0x00622018 | 121 | 3 | 1 | 4 | 0 | 3 | 8 |
| jw_08 | JoinWorldUI -[cloudConnectionRequestSucceededWithHost:port:key:] | 0x00622260 | 52 | 1 | 1 | 3 | 0 | 1 | 0 |
| jw_09 | JoinWorldUI -[customControl:] | 0x006188d4 | 100 | 4 | 2 | 2 | 2 | 4 | 0 |
| jw_10 | JoinWorldUI -[customHost] | 0x00625498 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| jw_11 | JoinWorldUI -[customHostButton:] | 0x0061f580 | 240 | 12 | 5 | 3 | 1 | 12 | 0 |
| jw_12 | JoinWorldUI -[customPort] | 0x006254dc | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| jw_13 | JoinWorldUI -[customPortButton:] | 0x0061f940 | 240 | 12 | 5 | 3 | 1 | 12 | 0 |
| jw_14 | JoinWorldUI -[dealloc] | 0x00603b38 | 438 | 4 | 2 | 29 | 1 | 31 | 0 |
| jw_15 | JoinWorldUI -[dismissAlertViews] | 0x00603b24 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| jw_16 | JoinWorldUI -[endTouch:] | 0x00624918 | 702 | 1 | 0 | 19 | 0 | 34 | 24 |
| jw_17 | JoinWorldUI -[expertControl:] | 0x00618a64 | 100 | 4 | 2 | 2 | 2 | 4 | 0 |
| jw_18 | JoinWorldUI -[finalCancelButton:] | 0x00618bf4 | 572 | 5 | 2 | 4 | 0 | 10 | 38 |
| jw_19 | JoinWorldUI -[finalJoinButton:] | 0x006194e4 | 441 | 10 | 3 | 10 | 0 | 19 | 16 |
| jw_20 | JoinWorldUI -[gameLaunchedWithUrlToJoinCloudWorldWithID:name:] | 0x00603134 | 236 | 9 | 3 | 4 | 1 | 11 | 2 |
| jw_21 | JoinWorldUI -[gameLaunchedWithUrlToJoinHost:port:] | 0x00602fac | 98 | 4 | 1 | 2 | 0 | 6 | 0 |
| jw_22 | JoinWorldUI -[imagePickerFinishedWithImage:] | 0x0062279c | 280 | 11 | 2 | 3 | 2 | 15 | 5 |
| jw_23 | JoinWorldUI -[imageWithImage:scaledToSize:] | 0x006225cc | 116 | 2 | 0 | 0 | 0 | 9 | 7 |
| jw_24 | JoinWorldUI -[initFinalButtons] | 0x00610e58 | 869 | 9 | 7 | 5 | 1 | 21 | 29 |
| jw_25 | JoinWorldUI -[initNickAndPicButtons:] | 0x00611bec | 2924 | 22 | 9 | 10 | 4 | 54 | 145 |
| jw_26 | JoinWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:] | 0x00601af0 | 1272 | 25 | 18 | 20 | 8 | 46 | 29 |
| jw_27 | JoinWorldUI -[joinRandomButton:] | 0x0061499c | 625 | 12 | 5 | 5 | 1 | 16 | 18 |
| jw_28 | JoinWorldUI -[moveTouch:] | 0x00623e20 | 702 | 1 | 0 | 19 | 0 | 34 | 24 |
| jw_29 | JoinWorldUI -[nickNameButton:] | 0x0061f25c | 201 | 10 | 5 | 2 | 1 | 10 | 0 |
| jw_30 | JoinWorldUI -[picButton:] | 0x00622460 | 80 | 2 | 0 | 1 | 0 | 4 | 2 |
| jw_31 | JoinWorldUI -[pvpControl:] | 0x00618744 | 100 | 4 | 2 | 2 | 2 | 4 | 0 |
| jw_32 | JoinWorldUI -[renderFrame:projectionMatrix:] | 0x0060a798 | 6576 | 5 | 1 | 43 | 0 | 50 | 26 |
| jw_33 | JoinWorldUI -[searchButton:] | 0x0062191c | 236 | 12 | 4 | 3 | 1 | 12 | 0 |
| jw_34 | JoinWorldUI -[searchCancelled] | 0x00622430 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| jw_35 | JoinWorldUI -[searchFailed:] | 0x00622330 | 64 | 2 | 1 | 3 | 0 | 2 | 2 |
| jw_36 | JoinWorldUI -[searchOptionsButton:] | 0x00615360 | 3321 | 27 | 21 | 20 | 8 | 69 | 148 |
| jw_37 | JoinWorldUI -[searchResultsReturned:] | 0x00621da4 | 157 | 6 | 2 | 5 | 0 | 6 | 7 |
| jw_38 | JoinWorldUI -[searchResultsSelectionChanged] | 0x00621ccc | 54 | 2 | 1 | 2 | 0 | 2 | 0 |
| jw_39 | JoinWorldUI -[searchWorldSelected] | 0x00619bc8 | 1746 | 14 | 19 | 11 | 3 | 44 | 73 |
| jw_40 | JoinWorldUI -[shouldDisplayAlertOnSearchFail] | 0x00622444 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| jw_41 | JoinWorldUI -[startNewSession] | 0x006034e4 | 400 | 14 | 3 | 8 | 3 | 19 | 5 |
| jw_42 | JoinWorldUI -[startSearch] | 0x0061e690 | 161 | 6 | 1 | 7 | 0 | 6 | 1 |
| jw_43 | JoinWorldUI -[startTouch:] | 0x00622bfc | 1161 | 2 | 0 | 20 | 0 | 34 | 58 |
| jw_44 | JoinWorldUI -[state] | 0x00625520 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| jw_45 | JoinWorldUI -[textField:shouldChangeCharactersInRange:replacementString:] | 0x0061e398 | 190 | 7 | 1 | 1 | 1 | 10 | 9 |
| jw_46 | JoinWorldUI -[textFieldShouldReturn:] | 0x0061f1d8 | 33 | 1 | 1 | 1 | 0 | 1 | 0 |
| jw_47 | JoinWorldUI -[userName] | 0x00625410 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| jw_48 | JoinWorldUI -[userPhoto] | 0x00625454 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| jw_49 | JoinWorldUI -[windowInfoChanged:] | 0x00604210 | 6498 | 10 | 10 | 38 | 0 | 107 | 295 |

## Findings (E137)

- **The JoinWorldUI batch lands**: 50 bodies / 36441 words / 1135 branches / 861 call rows of `JoinWorldUI` (objc method table order 0x00601af0 `initWithDelegate:windowInfo:cache:cloudInterface:` .. 0x00625520 `state`). The coverage ledger holds exactly 50 JoinWorldUI rows and none of them was refs-covered before this batch - the batch is the whole class at body level. 10 bodies >1000w [census], 9 bodies 301-1000w [census-lite], 31 bodies <=300w fully read.

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | jw_00 | `JoinWorldUI -[advancedButton:]` | 1021 | 27 | 27 | census |
  | jw_01 | `JoinWorldUI -[advancedCancelButton:]` | 18 | 0 | 0 | read |
  | jw_02 | `JoinWorldUI -[advancedLocalNetworkButton:]` | 93 | 0 | 4 | read |
  | jw_03 | `JoinWorldUI -[advancedOnlineButton:]` | 1718 | 56 | 38 | census |
  | jw_04 | `JoinWorldUI -[advancedSearchButton:]` | 1799 | 62 | 39 | census |
  | jw_05 | `JoinWorldUI -[alertView:didDismissWithButtonIndex:]` | 561 | 19 | 30 | census-lite |
  | jw_06 | `JoinWorldUI -[cloudConnectionCancelled]` | 25 | 0 | 1 | read |
  | jw_07 | `JoinWorldUI -[cloudConnectionFailed:presentTopupUI:]` | 121 | 8 | 3 | read |
  | jw_08 | `JoinWorldUI -[cloudConnectionRequestSucceededWithHost:port:key:]` | 52 | 0 | 1 | read |
  | jw_09 | `JoinWorldUI -[customControl:]` | 100 | 0 | 4 | read |
  | jw_10 | `JoinWorldUI -[customHost]` | 17 | 0 | 0 | read |
  | jw_11 | `JoinWorldUI -[customHostButton:]` | 240 | 0 | 12 | read |
  | jw_12 | `JoinWorldUI -[customPort]` | 17 | 0 | 0 | read |
  | jw_13 | `JoinWorldUI -[customPortButton:]` | 240 | 0 | 12 | read |
  | jw_14 | `JoinWorldUI -[dealloc]` | 438 | 0 | 31 | census-lite |
  | jw_15 | `JoinWorldUI -[dismissAlertViews]` | 5 | 0 | 0 | read |
  | jw_16 | `JoinWorldUI -[endTouch:]` | 702 | 24 | 34 | census-lite |
  | jw_17 | `JoinWorldUI -[expertControl:]` | 100 | 0 | 4 | read |
  | jw_18 | `JoinWorldUI -[finalCancelButton:]` | 572 | 38 | 10 | census-lite |
  | jw_19 | `JoinWorldUI -[finalJoinButton:]` | 441 | 16 | 19 | census-lite |
  | jw_20 | `JoinWorldUI -[gameLaunchedWithUrlToJoinCloudWorldWithID:name:]` | 236 | 2 | 11 | read |
  | jw_21 | `JoinWorldUI -[gameLaunchedWithUrlToJoinHost:port:]` | 98 | 0 | 6 | read |
  | jw_22 | `JoinWorldUI -[imagePickerFinishedWithImage:]` | 280 | 5 | 15 | read |
  | jw_23 | `JoinWorldUI -[imageWithImage:scaledToSize:]` | 116 | 7 | 9 | read |
  | jw_24 | `JoinWorldUI -[initFinalButtons]` | 869 | 29 | 21 | census-lite |
  | jw_25 | `JoinWorldUI -[initNickAndPicButtons:]` | 2924 | 145 | 54 | census |
  | jw_26 | `JoinWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:]` | 1272 | 29 | 46 | census |
  | jw_27 | `JoinWorldUI -[joinRandomButton:]` | 625 | 18 | 16 | census-lite |
  | jw_28 | `JoinWorldUI -[moveTouch:]` | 702 | 24 | 34 | census-lite |
  | jw_29 | `JoinWorldUI -[nickNameButton:]` | 201 | 0 | 10 | read |
  | jw_30 | `JoinWorldUI -[picButton:]` | 80 | 2 | 4 | read |
  | jw_31 | `JoinWorldUI -[pvpControl:]` | 100 | 0 | 4 | read |
  | jw_32 | `JoinWorldUI -[renderFrame:projectionMatrix:]` | 6576 | 26 | 50 | census |
  | jw_33 | `JoinWorldUI -[searchButton:]` | 236 | 0 | 12 | read |
  | jw_34 | `JoinWorldUI -[searchCancelled]` | 5 | 0 | 0 | read |
  | jw_35 | `JoinWorldUI -[searchFailed:]` | 64 | 2 | 2 | read |
  | jw_36 | `JoinWorldUI -[searchOptionsButton:]` | 3321 | 148 | 69 | census |
  | jw_37 | `JoinWorldUI -[searchResultsReturned:]` | 157 | 7 | 6 | read |
  | jw_38 | `JoinWorldUI -[searchResultsSelectionChanged]` | 54 | 0 | 2 | read |
  | jw_39 | `JoinWorldUI -[searchWorldSelected]` | 1746 | 73 | 44 | census |
  | jw_40 | `JoinWorldUI -[shouldDisplayAlertOnSearchFail]` | 7 | 0 | 0 | read |
  | jw_41 | `JoinWorldUI -[startNewSession]` | 400 | 5 | 19 | census-lite |
  | jw_42 | `JoinWorldUI -[startSearch]` | 161 | 1 | 6 | read |
  | jw_43 | `JoinWorldUI -[startTouch:]` | 1161 | 58 | 34 | census |
  | jw_44 | `JoinWorldUI -[state]` | 15 | 0 | 0 | read |
  | jw_45 | `JoinWorldUI -[textField:shouldChangeCharactersInRange:replacementString:]` | 190 | 9 | 10 | read |
  | jw_46 | `JoinWorldUI -[textFieldShouldReturn:]` | 33 | 0 | 1 | read |
  | jw_47 | `JoinWorldUI -[userName]` | 17 | 0 | 0 | read |
  | jw_48 | `JoinWorldUI -[userPhoto]` | 17 | 0 | 0 | read |
  | jw_49 | `JoinWorldUI -[windowInfoChanged:]` | 6498 | 295 | 107 | census |

- **The heavy bodies** (>300w), in listing order:

  | body | method | words | branches | calls |
  |---|---|---|---|---|
  | jw_00 | `JoinWorldUI -[advancedButton:]` | 1021 | 27 | 27 |
  | jw_03 | `JoinWorldUI -[advancedOnlineButton:]` | 1718 | 56 | 38 |
  | jw_04 | `JoinWorldUI -[advancedSearchButton:]` | 1799 | 62 | 39 |
  | jw_05 | `JoinWorldUI -[alertView:didDismissWithButtonIndex:]` | 561 | 19 | 30 |
  | jw_14 | `JoinWorldUI -[dealloc]` | 438 | 0 | 31 |
  | jw_16 | `JoinWorldUI -[endTouch:]` | 702 | 24 | 34 |
  | jw_18 | `JoinWorldUI -[finalCancelButton:]` | 572 | 38 | 10 |
  | jw_19 | `JoinWorldUI -[finalJoinButton:]` | 441 | 16 | 19 |
  | jw_24 | `JoinWorldUI -[initFinalButtons]` | 869 | 29 | 21 |
  | jw_25 | `JoinWorldUI -[initNickAndPicButtons:]` | 2924 | 145 | 54 |
  | jw_26 | `JoinWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:]` | 1272 | 29 | 46 |
  | jw_27 | `JoinWorldUI -[joinRandomButton:]` | 625 | 18 | 16 |
  | jw_28 | `JoinWorldUI -[moveTouch:]` | 702 | 24 | 34 |
  | jw_32 | `JoinWorldUI -[renderFrame:projectionMatrix:]` | 6576 | 26 | 50 |
  | jw_36 | `JoinWorldUI -[searchOptionsButton:]` | 3321 | 148 | 69 |
  | jw_39 | `JoinWorldUI -[searchWorldSelected]` | 1746 | 73 | 44 |
  | jw_41 | `JoinWorldUI -[startNewSession]` | 400 | 5 | 19 |
  | jw_43 | `JoinWorldUI -[startTouch:]` | 1161 | 58 | 34 |
  | jw_49 | `JoinWorldUI -[windowInfoChanged:]` | 6498 | 295 | 107 |

- **The whole-class state machine** (`state`, +0x14; pinned by jw_00/03/04/27/36/39 and the endTouch:/moveTouch:/startTouch:/renderFrame: routers):
  0 = main join screen (advancedButton, joinRandomButton, disabledTextView 'ONLINE PLAY DISABLED'); 1 = random-join screen (final buttons + nick/pic rows + searchOptionsButton; finalJoinButton title 'JOIN RANDOM WORLD'); 2 = ADVANCED screen (advancedCancel/LocalNetwork/Online/Search buttons); 3 = local-network join (final buttons + nick/pic); 4 = online IP/port screen (final buttons + nick/pic + host/port rows); 5 = SEARCH screen (final buttons + searchResultsUI/searchButton/searchOptionsButton); 6 = selected-world detail (searchResultTitle + nick/pic + final buttons); 7 = url/cloud-join final screen; 8/9 = the SEARCH OPTIONS pages (finalCancelButton + pvp/custom/expert controls).
- **Entry edges**: advancedButton: -> 2; advancedCancelButton: -> 0; advancedLocalNetworkButton: -> 3; advancedOnlineButton: -> 4; advancedSearchButton: -> 5; searchOptionsButton: -> 8 from state 1 and -> 9 from state 5; searchWorldSelected -> 6; joinRandomButton: -> 1; gameLaunchedWithUrlToJoinCloudWorldWithID:name: -> 7; startNewSession -> 0. finalCancelButton: walks back: 1->0, 7->0, 3->2, 4->2, 5->2 (also cancels the cloud search, re-enables and re-frames the join button), 6->5 (also retitles 'JOIN WORLD...'), 8->1, 9->5 (+startSearch).
- **The cloud/URL join chain**: cloudConnectionCancelled (jw_06) and cloudConnectionFailed:presentTopupUI: (jw_07, fail codes 2/3/4 reopen the nickname entry; otherwise presentAddCreditUIForWorldWithName:worldID:currentCredit:0.0f) fall back to [delegate multiplayerGameSelectCancelled]; cloudConnectionRequestSucceededWithHost:port:key: (jw_08) forwards to [delegate joinCloudWorldAtHost:port:key:userName:pic:]; the url-join entry points store customHost/customPort (jw_21) or cloudURLJoinWorldID/Name (jw_20, name fallback 'WORLD', final button retitled 'JOIN %@' and state=7) and then programmatically press advanced/online. The JOIN button state 7 path calls [cloudInterface connectToWorldWithID:cloudURLJoinWorldID userName:userName delegate:self] after [delegate startAttemptingToConnectToWorld]; state 6 takes the wId/name from the selected search result.
- **Search chain**: searchButton: (jw_33) opens the styled text alert (textEntryType 3, returnKey 6); alertView:didDismissWithButtonIndex: (jw_05) uppercases + stores it as the searchButton title and calls startSearch (jw_42: [cloudInterface cancelSearch:self] -> [searchResultsUI searchStarted] -> [cloudInterface startSearchForWorldsMatchingString:searchDelegate:allowPVP:customRules:expertMode:] with the three preference ivars -> finalJoinButton disabled). Result flow: searchResultsReturned: (jw_37: state 5 -> [searchResultsUI setResults:], state 1 -> instant join of the first result's 'wId'), searchFailed: (jw_35: state 5 -> [searchResultsUI abortSearch:1] else delegate cancel), searchCancelled (jw_34) empty stub, searchResultsSelectionChanged (jw_38: join button enabled iff a result is selected), shouldDisplayAlertOnSearchFail (jw_40) = YES, searchWorldSelected (jw_39) = state 6 + the world-detail text. searchOptionsButton: (jw_36) builds the options page and the three preference setters (jw_09/17/31) persist customRules/expertMode/pvp to NSUserDefaults ('customRulesJoinPreference'/'expertModeJoinPreference'/'pvpJoinPreference').
- **The touch trio is one machine**: endTouch: (jw_16, 702w), moveTouch: (jw_28, 702w) and startTouch: (jw_43, 1161w) share the identical per-state forward table (34 sends each, same receiver lists; extracted programmatically from the listings). startTouch: additionally OR-accumulates each forwarded sxtb BOOL result (movne/and) and returns the accumulated byte; endTouch:/moveTouch: are void. renderFrame:projectionMatrix: (jw_32, 6576w) forwards across the same state table (49 sends) after a [delegate attemptingToConnectToWorld] early-out.
- **The layout contract (shared by every rect in the class)**: rects are written by helper 0x602f14(dst, x, y, w, h) (4-float writer; a second copy 0x602f60, a CGSize pair writer 0x6225a0, and predicate 0x602ed0 = (x==2||x==1)). The y term comes from a windowInfo gate chain: compare windowInfo+4 (width) against 415.0f (0x19f; float pool copies per body); below the gate the base is windowInfo+0xc - 160.0f (0xa0) else 0.0f, then the row offsets are applied (common floats: w=226.0f (0x4362), h=40.0f (0x4220), x in {4.0f (0x4080), -113.0f (0xc2e2), -230.0f (0xc366)}, row terms 8/44/48/60/64/80/88/96/132/144 and -32/-44/-48/-80/-96/-128/-140). The 415.0f value is also the width gate that picks the short string variants ('YOUR ALIAS:', 'SERVER IP:').
- **Strings pinned (extracted from the static CFString structs)**: titles 'ADVANCED...', 'JOIN RANDOM WORLD...', 'SEARCH OPTIONS...', 'JOIN LOCAL WORLD', 'JOIN ONLINE WORLD', 'JOIN WORLD', 'JOIN WORLD...', '<- BACK', 'YOUR ALIAS:', 'YOUR NICKNAME:', 'YOUR PIC:', 'PVP:', 'RULES:', 'EXPERT MODE:', 'SERVER IP:', 'SERVER IP/URL:', 'SERVER PORT:', segmented-control titles 'OFF'/'ON'/'EITHER' and 'SURVIVAL'/'CUSTOM', the status ladder 'REQUIRES PASSWORD, PVP ENABLED/DISABLED', 'WHITELISTED, PVP ENABLED/DISABLED', 'PVP ENABLED/DISABLED', formats 'JOIN %@', 'OWNER : %@
', '%@
%@%@', an empty '' string; alert titles/messages 'Server IP/URL' + "Please enter the server's IP address or URL.", 'Server Port' + "Please enter the server's port. The default is 15151.", 'Your Nickname' + 'Your blockheads on the server world will be tied to this nickname.', 'World Search By Name', 'Cancel'/'Done'/'Search'; the 'ONLINE PLAY DISABLED' text; textures 'textEntry.png', 'avatar.png', 'InventoryButtonBackground.png'/'InventoryButtonBackgroundSelected.png'/'InventoryButtonBackgroundGreen.png'/'InventoryButtonBackgroundSelectedGreen.png'; defaults keys 'joinUserName', 'pvpJoinPreference', 'customRulesJoinPreference', 'expertModeJoinPreference', 'gdprStatus'; server-join keys 'wId', 'name', 'owner', 'pw', 'pvp', 'whitelisted'; fallbacks '127.0.0.1', '15151'.
- **The four text-entry alerts** (jw_11/13/29/33) are one template: UIAlertView style 2 (plain text), delegate:self, 'Cancel' + other button; the textField gets autocorrection 0, enablesReturnKeyAutomatically 1, returnKeyType 9 (host/port/nickname) or 6 (search), keyboardType 3 (URL, host/port) or 1 (nickname/search); the host/port/search alerts pre-fill tf.text with the current button title; textEntryType (0=nickname, 1=host, 2=port, 3=search) routes the completion in jw_05; textFieldShouldReturn: (jw_46) dismisses with index 1; the 16-char cap and auto-uppercase live in jw_45 (host/port are exempt from both).
- **The avatar path**: jw_26 ctor and jw_41 startNewSession load Documents/avatar.png ([NSSearchPathForDirectoriesInDomains(0xe,1,1) objectAtIndex:0] + stringByAppendingPathComponent:) into UIImage -> CPTexture2D initWithUIImage: -> [picButton setGlyphTexture:]; jw_22 writes the picked image back to avatar.png through the 64x64 scaler (jw_23, UIGraphics-based); jw_30 starts the picker through [delegate startImagePickerWithDelegate:forRect:cropSize:CGSize(320,320)].
- **ivar notes**: the batch references all 44 class ivars (class_metadata.json JoinWorldUI; instance_size 180 / 0xb4): delegate +0x4, windowInfo +0x8, cache +0xc, cloudInterface +0x10, state +0x14, disabledTextView +0x18, advancedButton +0x1c .. cloudURLJoinWorldName +0xb0; every ivar access in this class is the Apportable offset-cell form (ldr cell -> ldr [cell+picbase] -> ldr [slot] -> add self).

## Boundaries

- The ten >1000w bodies (jw_00, jw_03, jw_04, jw_25, jw_26, jw_32, jw_36, jw_39, jw_43, jw_49) are census-grade: the per-state receiver tables, call histograms, string sets, constant pools and branch skeletons are pinned, but their per-block binding is not an instruction-by-instruction read. The nine 301-1000w bodies were read with the register-annotated trace plus targeted windows.
- The rect math is recorded at expression level: the gate constant pair 415.0f/160.0f, the w/h/x constants and the row floats are exact (pool-decoded), but which addend of the y expression maps to which windowInfo field (windowInfo+4 vs +0xc) is derived from the code shape, not from a runtime sample.
- jw_25: the BOOL argument is consumed by the nick/pic screen at block level (which sub-view reads it is not register-traced); the same for the jw_39 stringWithFormat assembly ("%@
%@%@" argument order recorded at expression level only).
- jw_45: the NSNotFound comparison uses the raw 0x7fffffff literal at cell 0x61e678 (verified by direct ELF read); the r2 pool row mislabels that cell as a PIC-base cell.
- jw_05/jw_11/jw_13/jw_29/jw_33 block literals: these alerts carry no stack blocks (index-based delegate completion); dismissAlertViews (jw_15) is an empty stub, so the textEntryAlertView is cleared only by the completion tail in jw_05.
- Listing bounds: jw_49 windowInfoChanged: = 6498 words as received (header exidx), jw_32 renderFrame:projectionMatrix: = 6576 words; the tsv-gap sizes quoted for the batch coincide with the received listings. TRIMMED listings: jw_10 (17w), jw_28 (702w), jw_34 (5w), jw_47 (17w), jw_48 (17w) - bodies bounded at the next ObjC IMP; jw_10/jw_47/jw_48 share the exidx suffix 0x625520 (linker artifact).
- searchCancelled (jw_34) is a genuinely empty 5-word body - recorded as-read; no cancellation forward lives in it.
- Static only: no runtime values. UIKit/MJ*/SearchResultsUI semantics beyond the call-site level and the extracted literals are not claimed; helper names (CGRect/CGSize writers, predicate) are shape-derived.
