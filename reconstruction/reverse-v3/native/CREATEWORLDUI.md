# CreateWorldUI (E136)

The create-world screen class lands: the full CreateWorldUI surface (name/size/privacy/time controls, cloud create chain, IAP receipt verification, finalCreateButton, frame render). 53 bodies, 36355 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| cwu_00 | CreateWorldUI -[IAPForWorldCreationSucceeeded:transactionID:] | 0x00b1f6fc | 49 | 1 | 1 | 1 | 0 | 1 | 4 |
| cwu_01 | CreateWorldUI -[alertView:didDismissWithButtonIndex:] | 0x00b30dfc | 369 | 12 | 3 | 6 | 1 | 20 | 9 |
| cwu_02 | CreateWorldUI -[cloudConnectionCancelled] | 0x00b32ddc | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| cwu_03 | CreateWorldUI -[cloudConnectionFailed:presentTopupUI:] | 0x00b32d70 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| cwu_04 | CreateWorldUI -[cloudConnectionRequestSucceededWithHost:port:key:] | 0x00b32e40 | 52 | 1 | 1 | 3 | 0 | 1 | 0 |
| cwu_05 | CreateWorldUI -[cloudCreateWorldCancelled] | 0x00b32d0c | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| cwu_06 | CreateWorldUI -[cloudCreateWorldFailed:] | 0x00b32bc8 | 81 | 3 | 1 | 3 | 0 | 3 | 6 |
| cwu_07 | CreateWorldUI -[cloudCreateWorldSucceededWithWorldID:] | 0x00b3299c | 139 | 4 | 2 | 6 | 0 | 4 | 0 |
| cwu_08 | CreateWorldUI -[cloudCreateWorldVerificationFailed:] | 0x00b32858 | 81 | 3 | 1 | 3 | 0 | 3 | 6 |
| cwu_09 | CreateWorldUI -[cloudCreateWorldVerificationReturnedUsedReceipt] | 0x00b326d8 | 96 | 5 | 2 | 2 | 0 | 4 | 2 |
| cwu_10 | CreateWorldUI -[cloudCreateWorldVerificationSucceeded] | 0x00b32280 | 247 | 8 | 5 | 5 | 2 | 11 | 13 |
| cwu_11 | CreateWorldUI -[createCloudWorldWithReceiptData:transactionID:] | 0x00b1f354 | 234 | 3 | 9 | 2 | 0 | 12 | 0 |
| cwu_12 | CreateWorldUI -[createWorldName] | 0x00b32fc0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| cwu_13 | CreateWorldUI -[createWorldSize] | 0x00b3308c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| cwu_14 | CreateWorldUI -[customRules] | 0x00b32f10 | 44 | 1 | 1 | 2 | 0 | 1 | 2 |
| cwu_15 | CreateWorldUI -[customRulesControl:] | 0x00b2dd6c | 100 | 2 | 3 | 3 | 0 | 3 | 4 |
| cwu_16 | CreateWorldUI -[customRulesHelpButton:] | 0x00b2ea30 | 162 | 6 | 5 | 1 | 1 | 5 | 1 |
| cwu_17 | CreateWorldUI -[dealloc] | 0x00b11088 | 434 | 4 | 2 | 28 | 1 | 31 | 0 |
| cwu_18 | CreateWorldUI -[delayedVerifyWorldWithAppReceipt] | 0x00b32680 | 22 | 1 | 1 | 0 | 0 | 1 | 0 |
| cwu_19 | CreateWorldUI -[dismissAlertViews] | 0x00b10d08 | 224 | 4 | 1 | 5 | 0 | 12 | 0 |
| cwu_20 | CreateWorldUI -[endTouch:] | 0x00b3029c | 563 | 2 | 1 | 17 | 0 | 18 | 34 |
| cwu_21 | CreateWorldUI -[expertModeControl:] | 0x00b2defc | 31 | 1 | 1 | 1 | 0 | 1 | 0 |
| cwu_22 | CreateWorldUI -[expertModeSelection] | 0x00b33148 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cwu_23 | CreateWorldUI -[finalCancelButton:] | 0x00b1aae8 | 3537 | 7 | 4 | 12 | 0 | 66 | 181 |
| cwu_24 | CreateWorldUI -[finalCreateButton:] | 0x00b1f7c0 | 12536 | 96 | 57 | 66 | 17 | 279 | 507 |
| cwu_25 | CreateWorldUI -[imagePickerFinishedWithImage:] | 0x00b31e20 | 280 | 0 | 0 | 0 | 0 | 15 | 5 |
| cwu_26 | CreateWorldUI -[imageWithImage:scaledToSize:] | 0x00b31c50 | 116 | 2 | 0 | 0 | 0 | 9 | 7 |
| cwu_27 | CreateWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:] | 0x00b0cc48 | 2035 | 34 | 26 | 18 | 11 | 63 | 46 |
| cwu_28 | CreateWorldUI -[locationHelpButton:] | 0x00b2e6a4 | 162 | 6 | 5 | 1 | 1 | 5 | 1 |
| cwu_29 | CreateWorldUI -[moveTouch:] | 0x00b2f9d0 | 563 | 2 | 1 | 17 | 0 | 18 | 34 |
| cwu_30 | CreateWorldUI -[nickNameButton:] | 0x00b317f0 | 200 | 10 | 5 | 2 | 1 | 10 | 0 |
| cwu_31 | CreateWorldUI -[picButton:] | 0x00b31b10 | 80 | 2 | 0 | 1 | 0 | 4 | 2 |
| cwu_32 | CreateWorldUI -[privacyControl:] | 0x00b2dc74 | 31 | 1 | 1 | 1 | 0 | 1 | 0 |
| cwu_33 | CreateWorldUI -[privacyHelpButton:] | 0x00b2df78 | 162 | 6 | 5 | 1 | 1 | 5 | 1 |
| cwu_34 | CreateWorldUI -[privacySelection] | 0x00b330d0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cwu_35 | CreateWorldUI -[productsRequest:didReceiveResponse:] | 0x00b0f5cc | 317 | 10 | 4 | 2 | 0 | 17 | 11 |
| cwu_36 | CreateWorldUI -[renderFrame:projectionMatrix:] | 0x00b17148 | 3688 | 5 | 2 | 32 | 0 | 36 | 26 |
| cwu_37 | CreateWorldUI -[showFinalOnlineCreateAlertView] | 0x00b1e614 | 236 | 9 | 5 | 2 | 2 | 7 | 1 |
| cwu_38 | CreateWorldUI -[startNewSession] | 0x00b0fac0 | 1170 | 23 | 8 | 12 | 4 | 36 | 38 |
| cwu_39 | CreateWorldUI -[startTouch:] | 0x00b2edbc | 773 | 2 | 1 | 17 | 0 | 18 | 51 |
| cwu_40 | CreateWorldUI -[state] | 0x00b33184 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cwu_41 | CreateWorldUI -[textField:shouldChangeCharactersInRange:replacementString:] | 0x00b30b68 | 165 | 7 | 1 | 0 | 1 | 10 | 6 |
| cwu_42 | CreateWorldUI -[textFieldShouldReturn:] | 0x00b313c0 | 33 | 1 | 1 | 1 | 0 | 1 | 0 |
| cwu_43 | CreateWorldUI -[timeControl:] | 0x00b2dcf0 | 31 | 1 | 1 | 1 | 0 | 1 | 0 |
| cwu_44 | CreateWorldUI -[timeHelpButton:] | 0x00b2e304 | 167 | 6 | 4 | 2 | 1 | 5 | 1 |
| cwu_45 | CreateWorldUI -[timeSelection] | 0x00b3310c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cwu_46 | CreateWorldUI -[updatePriceViewsForInitialWorldCredit] | 0x00b0eca4 | 575 | 16 | 1 | 7 | 4 | 29 | 21 |
| cwu_47 | CreateWorldUI -[userName] | 0x00b33004 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| cwu_48 | CreateWorldUI -[userPhoto] | 0x00b33048 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| cwu_49 | CreateWorldUI -[verifyWorldWithReceipt:transactionID:] | 0x00b1e22c | 250 | 3 | 9 | 3 | 0 | 12 | 0 |
| cwu_50 | CreateWorldUI -[windowInfoChanged:] | 0x00b11750 | 5758 | 13 | 11 | 33 | 0 | 104 | 255 |
| cwu_51 | CreateWorldUI -[worldNameButton:] | 0x00b31444 | 235 | 12 | 4 | 3 | 1 | 12 | 0 |
| cwu_52 | CreateWorldUI -[worldSizeControl:] | 0x00b2da8c | 122 | 3 | 1 | 2 | 0 | 5 | 5 |

## Findings (E136)

- **The CreateWorldUI batch lands**: 53 bodies / 36355 words / 1280 branches / 902 call rows of `CreateWorldUI` (objc method table order 0x00b0cc48 `initWithDelegate:windowInfo:cache:cloudInterface:` .. 0x00b33184 `state`, covering the whole class at body level; the class has no previously-referenced bodies outside this batch). 6 bodies >1000w [census], 7 bodies 301-1000w [census-lite], 40 bodies <=300w fully read.

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | cwu_00 | `CreateWorldUI -[IAPForWorldCreationSucceeeded:transactionID:]` | 49 | 4 | 1 | read |
  | cwu_01 | `CreateWorldUI -[alertView:didDismissWithButtonIndex:]` | 369 | 9 | 20 | census-lite |
  | cwu_02 | `CreateWorldUI -[cloudConnectionCancelled]` | 25 | 0 | 1 | read |
  | cwu_03 | `CreateWorldUI -[cloudConnectionFailed:presentTopupUI:]` | 27 | 0 | 1 | read |
  | cwu_04 | `CreateWorldUI -[cloudConnectionRequestSucceededWithHost:port:key:]` | 52 | 0 | 1 | read |
  | cwu_05 | `CreateWorldUI -[cloudCreateWorldCancelled]` | 25 | 0 | 1 | read |
  | cwu_06 | `CreateWorldUI -[cloudCreateWorldFailed:]` | 81 | 6 | 3 | read |
  | cwu_07 | `CreateWorldUI -[cloudCreateWorldSucceededWithWorldID:]` | 139 | 0 | 4 | read |
  | cwu_08 | `CreateWorldUI -[cloudCreateWorldVerificationFailed:]` | 81 | 6 | 3 | read |
  | cwu_09 | `CreateWorldUI -[cloudCreateWorldVerificationReturnedUsedReceipt]` | 96 | 2 | 4 | read |
  | cwu_10 | `CreateWorldUI -[cloudCreateWorldVerificationSucceeded]` | 247 | 13 | 11 | read |
  | cwu_11 | `CreateWorldUI -[createCloudWorldWithReceiptData:transactionID:]` | 234 | 0 | 12 | read |
  | cwu_12 | `CreateWorldUI -[createWorldName]` | 17 | 0 | 0 | read |
  | cwu_13 | `CreateWorldUI -[createWorldSize]` | 17 | 0 | 0 | read |
  | cwu_14 | `CreateWorldUI -[customRules]` | 44 | 2 | 1 | read |
  | cwu_15 | `CreateWorldUI -[customRulesControl:]` | 100 | 4 | 3 | read |
  | cwu_16 | `CreateWorldUI -[customRulesHelpButton:]` | 162 | 1 | 5 | read |
  | cwu_17 | `CreateWorldUI -[dealloc]` | 434 | 0 | 31 | census-lite |
  | cwu_18 | `CreateWorldUI -[delayedVerifyWorldWithAppReceipt]` | 22 | 0 | 1 | read |
  | cwu_19 | `CreateWorldUI -[dismissAlertViews]` | 224 | 0 | 12 | read |
  | cwu_20 | `CreateWorldUI -[endTouch:]` | 563 | 34 | 18 | census-lite |
  | cwu_21 | `CreateWorldUI -[expertModeControl:]` | 31 | 0 | 1 | read |
  | cwu_22 | `CreateWorldUI -[expertModeSelection]` | 15 | 0 | 0 | read |
  | cwu_23 | `CreateWorldUI -[finalCancelButton:]` | 3537 | 181 | 66 | census |
  | cwu_24 | `CreateWorldUI -[finalCreateButton:]` | 12536 | 507 | 279 | census |
  | cwu_25 | `CreateWorldUI -[imagePickerFinishedWithImage:]` | 280 | 5 | 15 | read |
  | cwu_26 | `CreateWorldUI -[imageWithImage:scaledToSize:]` | 116 | 7 | 9 | read |
  | cwu_27 | `CreateWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:]` | 2035 | 46 | 63 | census |
  | cwu_28 | `CreateWorldUI -[locationHelpButton:]` | 162 | 1 | 5 | read |
  | cwu_29 | `CreateWorldUI -[moveTouch:]` | 563 | 34 | 18 | census-lite |
  | cwu_30 | `CreateWorldUI -[nickNameButton:]` | 200 | 0 | 10 | read |
  | cwu_31 | `CreateWorldUI -[picButton:]` | 80 | 2 | 4 | read |
  | cwu_32 | `CreateWorldUI -[privacyControl:]` | 31 | 0 | 1 | read |
  | cwu_33 | `CreateWorldUI -[privacyHelpButton:]` | 162 | 1 | 5 | read |
  | cwu_34 | `CreateWorldUI -[privacySelection]` | 15 | 0 | 0 | read |
  | cwu_35 | `CreateWorldUI -[productsRequest:didReceiveResponse:]` | 317 | 11 | 17 | census-lite |
  | cwu_36 | `CreateWorldUI -[renderFrame:projectionMatrix:]` | 3688 | 26 | 36 | census |
  | cwu_37 | `CreateWorldUI -[showFinalOnlineCreateAlertView]` | 236 | 1 | 7 | read |
  | cwu_38 | `CreateWorldUI -[startNewSession]` | 1170 | 38 | 36 | census |
  | cwu_39 | `CreateWorldUI -[startTouch:]` | 773 | 51 | 18 | census-lite |
  | cwu_40 | `CreateWorldUI -[state]` | 15 | 0 | 0 | read |
  | cwu_41 | `CreateWorldUI -[textField:shouldChangeCharactersInRange:replacementString:]` | 165 | 6 | 10 | read |
  | cwu_42 | `CreateWorldUI -[textFieldShouldReturn:]` | 33 | 0 | 1 | read |
  | cwu_43 | `CreateWorldUI -[timeControl:]` | 31 | 0 | 1 | read |
  | cwu_44 | `CreateWorldUI -[timeHelpButton:]` | 167 | 1 | 5 | read |
  | cwu_45 | `CreateWorldUI -[timeSelection]` | 15 | 0 | 0 | read |
  | cwu_46 | `CreateWorldUI -[updatePriceViewsForInitialWorldCredit]` | 575 | 21 | 29 | census-lite |
  | cwu_47 | `CreateWorldUI -[userName]` | 17 | 0 | 0 | read |
  | cwu_48 | `CreateWorldUI -[userPhoto]` | 17 | 0 | 0 | read |
  | cwu_49 | `CreateWorldUI -[verifyWorldWithReceipt:transactionID:]` | 250 | 0 | 12 | read |
  | cwu_50 | `CreateWorldUI -[windowInfoChanged:]` | 5758 | 255 | 104 | census |
  | cwu_51 | `CreateWorldUI -[worldNameButton:]` | 235 | 0 | 12 | read |
  | cwu_52 | `CreateWorldUI -[worldSizeControl:]` | 122 | 5 | 5 | read |

- **The heavy bodies**:

  | body | method | words | branches | calls |
  |---|---|---|---|---|
  | cwu_01 | `CreateWorldUI -[alertView:didDismissWithButtonIndex:]` | 369 | 9 | 20 |
  | cwu_17 | `CreateWorldUI -[dealloc]` | 434 | 0 | 31 |
  | cwu_20 | `CreateWorldUI -[endTouch:]` | 563 | 34 | 18 |
  | cwu_23 | `CreateWorldUI -[finalCancelButton:]` | 3537 | 181 | 66 |
  | cwu_24 | `CreateWorldUI -[finalCreateButton:]` | 12536 | 507 | 279 |
  | cwu_27 | `CreateWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:]` | 2035 | 46 | 63 |
  | cwu_29 | `CreateWorldUI -[moveTouch:]` | 563 | 34 | 18 |
  | cwu_35 | `CreateWorldUI -[productsRequest:didReceiveResponse:]` | 317 | 11 | 17 |
  | cwu_36 | `CreateWorldUI -[renderFrame:projectionMatrix:]` | 3688 | 26 | 36 |
  | cwu_38 | `CreateWorldUI -[startNewSession]` | 1170 | 38 | 36 |
  | cwu_39 | `CreateWorldUI -[startTouch:]` | 773 | 51 | 18 |
  | cwu_46 | `CreateWorldUI -[updatePriceViewsForInitialWorldCredit]` | 575 | 21 | 29 |
  | cwu_50 | `CreateWorldUI -[windowInfoChanged:]` | 5758 | 255 | 104 |

- **Monolithic bodies are real**: every >1000w body has exactly one `push {..lr}` prologue and one `pop {..pc}` epilogue in-range (checked programmatically, 0 embedded prologues), and 0 in-range dynsym FUNC symbols - the exidx bound really is one compiler function. The tsv-gap size of `finalCreateButton:` (14.5K words to the next IMP) is inflated; the received listing is 12536 words and that is the body.
- **The whole-class state machine** (pinned by the endTouch/moveTouch/startTouch/router bodies and the title switches): `state` (+0x14) gates every touch/router/render path. state==0 is the location screen (locationControl/locationHelpButton/final buttons). states 1,2 = the form pages (worldName/size/nickName/pic; state==1 additionally routes nickNameButton+picButton), 3 = privacy/time, 4/7 = expertMode, 5/8 = customRules, 6/9 = createCustomOptionsUI. `customRulesControlSelection` (+0xc4)==0 with state==8 retitles finalCreateButton to 'CREATE WORLD' (ready) vs 'CREATE WORLD...' (waiting); cloudCreateWorldFailed/VerificationFailed map code 8 -> worldNameButton: and 2/3/4 -> nickNameButton: self-actions.
- **The create-world chain (cwu_00..cwu_11, cwu_18, cwu_37, cwu_49)**: finalCreateButton: builds `onlineWorldCreationWaitingForIAPDict` (+0xcc) and `createCloudWorldWithReceiptData:transactionID:` (cwu_11) or `verifyWorldWithReceipt:transactionID:` (cwu_49, isVerificationOnly=YES, records `verificationUsedCachedReciept` (+0xd0)) hand 8 named keys + receipt to [cloudInterface createOrVerfiyCloudWorldWithName:userName:userPhoto:size:privacy:initialTimeSelection:customRulesDict:expertMode:receipt:transactionID:isVerificationOnly:delegate:]. Success (cwu_07) -> [delegate cloudWorldWasCreatedWithID:..] + [cloudInterface connectToWorldWithID:userName:delegate:] + [[delegate appDatabase] removeDataForKey:'last_receipt']. VerifySucceeded (cwu_10): the cached receipt path runs the plist through NSPropertyListSerialization (helper 0xb3265c -> 0xb331c0) then objectForKey:'receiptData'/'transactionID'; the fresh path logs 'No SDKProduct found for timeSelection' when timeSelection>1, else [SKPayment paymentWithProduct:creditProducts[timeSelection]] -> [delegate iapStarted] -> [[SKPaymentQueue defaultQueue] addPayment:]. ReturnedUsedReceipt (cwu_09) removes 'last_receipt' and re-runs `delayedVerifyWorldWithAppReceipt` via performSelector:withObject:afterDelay: 0.1 (double at 0xb32828). UseReceipt (cwu_00) is a guarded forward. The cloud connection callbacks (cwu_02..cwu_05) and the cancel/failure callbacks (cwu_06/cwu_08) all fall back to [delegate multiplayerGameSelectCancelled].
- **IAP products**: App Store product ids '7dayscredit'/'30dayscredit' (SKProductsRequest in the ctor, fill of `creditProducts[2]` (+0x1c) in `productsRequest:didReceiveResponse:` cwu_35, price display in `updatePriceViewsForInitialWorldCredit` cwu_46: NSNumberFormatter currency style, locale from [product priceLocale], [product price]; the two MJImageView price views re-created from [timeControl frame] with the -64.0f seed; state==3 + missing product disables the create button).
- **The layout monoliths**: finalCreateButton: (cwu_24), finalCancelButton: (cwu_23), windowInfoChanged: (cwu_50) and startNewSession (cwu_38) contain the layout (and, in cwu_24/cwu_50, the lazy view construction) inline: repeated blocks computing each frame from windowInfo float fields with the 415.0f (0x19f) / 160.0f (0xa0) height gates, window-relative 40.0f/226.0f/-113.0f terms, and CGRect make helper 0xb0ec58 (a second copy 0xb2d808 is used 8x in cwu_24 and in cwu_26/cwu_31 for draw/picker rects). The CGRect('{x,y,w,h} from r1,r2,r3,[sp]') and CGSize (0xb0f5a0) builders are non-ObjC helpers, as is the predicate 0xb0ec14 (x in {1,2}).
- **Strings pinned (extracted from the static CFString structs, flags 0x7c8/0x7d0)**: 'WORLD NAME:', 'WORLD SIZE:', 'YOUR ALIAS:', 'YOUR NICKNAME:', 'YOUR PIC:', 'PRIVACY:', 'INITIAL WORLD CREDIT:', 'OFFLINE', 'ONLINE', 'NORMAL', 'EXPERT MODE', 'SURVIVAL', 'CUSTOM RULES', 'PUBLIC', 'SEARCHABLE', 'PRIVATE', '7 DAYS', '30 DAYS', '1/16'/'1/4'/'1x'/'4x'/'16x', 'CREATE WORLD', 'CREATE WORLD...', '<- BACK', 'OK', 'CANCEL', '?', 'textEntry.png', 'avatar.png', 'InventoryButtonBackground(.Green/.Selected/.SelectedGreen/30/30Selected).png'; alert texts: 'CUSTOM RULES' + long custom-rules text, 'OFFLINE VS ONLINE' + long text, 'PRIVACY' + long text, 'WORLD CREDIT' + worldCreditHelpMessage ('Online worlds require credit...'), 'Your Nickname'/'World Name' + 'Cancel'/'Done', the public-world policy text, and the final-online format "You're just one step away from creating

'%@'!"; keys 'joinUserName' (NSUserDefaults), 'gdprStatus', 'last_receipt'/'receiptData'/'transactionID' (appDatabase plist), log 'No SDKProduct found for timeSelection'/'no products found'.
- **The alert family** (cwu_16/28/33/44/37/30/51 + the prompt views): single-shot help alerts stored in `helpAlertView` (+0x9c, guarded by nil, message = [long text uppercaseString], 'OK' cancel + block, show); the text-entry UIAlertViews (style 2) for world name / nickname share one ivar `textEntryAlertView` (+0xa4) with `textEntryIsEditingNickName` (+0xa8); completion in `alertView:didDismissWithButtonIndex:` (cwu_01) sets either userName (+'joinUserName' defaults write) or createWorldName; `textFieldShouldReturn:` (cwu_42) dismisses with index 1; `textField:shouldChangeCharactersInRange:...` (cwu_41) caps at 16 chars and auto-uppercases lowercase insertions via stringByReplacingCharactersInRange:withString:.
- **The touch trio is one machine**: `startTouch:` (cwu_39), `moveTouch:` (cwu_29), `endTouch:` (cwu_20) share the same 9-state forward table (identical branch skeletons, 18 call rows each); `startTouch:` ORs each subview result into a BOOL and returns it.
- **Field state**: `privacySelection`/`timeSelection`/`customRulesControlSelection` are int ivars set from [sender selectedIndex] (cwu_32/43/15); `expertModeSelection` is a char (cwu_21/22); the atomic getters carry the dmb ish barrier (cwu_12/13/34/40/45/47/48).

## Boundaries

- cwu_24 / cwu_50 / cwu_23 / cwu_36 / cwu_38 / cwu_27 are census-grade: per-block binding is summarized from call histograms, the constant/pool tables, extracted strings and head/tail + targeted windows; they are not instruction-by-instruction reads. In cwu_24 and cwu_50 the exact order in which the per-state view sections run is approximated (the branch skeleton + cell census pin which views are built/framed, not every ordering edge).
- cwu_23: 38 CGRect builds produce ~15 frame variants; which branch feeds which final view is recorded at block level only. The b1b200 (state==2) and b1b8f0 (other states) tail paths are delimited by branch targets, not fully register-traced to the epilogue.
- cwu_36: the 34 forward sends are the `bl loc.imp.objc_msgSend` route; the tracer resolves the selector cells (5 duplicated `renderFrame:projectionMatrix:` cells) but the per-send receiver binding is at the common-call level. The tail loop over `timeControlPriceViews` is pinned instruction-by-instruction.
- cwu_46: the price-view rect ladder is reported with its constants (-64.0f seed, x2/x10 height steps) but the exact float field mapping (frame x/y vs the +0xc windowInfo term) is at expression level, not numeric value level.
- The `EXIDX` body bounds are taken from the listing header; the finalCreateButton: tsv-gap (to the next IMP, 0xb2da8c) is 14.5K words while the received body is 12536 words - the listing is authoritative per batch convention.
- Block literals (help-alert OK handlers, confirm buttons) are stack block descriptors pointing at anonymous functions right after each method; their bodies are out of the 53-body set and were not decoded.
- Helper classification (non-ObjC): 0xb0ec58/0xb2d808 = CGRect{dst,f,f,f,f} maker; 0xb0f5a0 = CGSize maker; 0xb0ec14 = predicate x in {1,2}; 0xb3265c -> 0xb331c0 = [NSPropertyListSerialization propertyListWithData:options:format:error:] wrapper (resolved through the classref/selector cells); getRandomWorldName__ (0xb2bba0) = C random world-name generator.
- Static only: no runtime values; UIKit/MJ* semantics beyond the call-site level and the extracted literals are not claimed.
- ivar offsets in the semantics strings are the class_metadata.json CreateWorldUI entries (+0x4 delegate .. +0xd0 verificationUsedCachedReciept, instance_size 209); Apportable offset-cell reads resolve through the OBJC_IVAR symbols.
