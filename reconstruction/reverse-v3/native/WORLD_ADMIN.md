# World administration and moderation line (E109)

The World admin/moderation line: the custom-rules sync loop, the BlockAlertView kick/ban/report alerts and the per-save mute list. 9 bodies, 2575 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wa_00 | World -[verifyClientCustomRulesData:] | 0x005d70b4 | 440 | 3 | 2 | 2 | 0 | 6 | 53 |
| wa_01 | World -[customRuleDictRecievedFromNet:] | 0x005d5b10 | 284 | 6 | 3 | 3 | 1 | 14 | 9 |
| wa_02 | World -[setCustomRule:forOptionNamed:] | 0x005d5710 | 256 | 8 | 2 | 5 | 3 | 11 | 5 |
| wa_03 | World -[kickOrBanPlayerFromButtonIsBan:withName:] | 0x005d0410 | 303 | 10 | 8 | 1 | 2 | 11 | 1 |
| wa_04 | World -[setPlayerMuted:withID:] | 0x005cfea4 | 162 | 7 | 2 | 3 | 0 | 6 | 3 |
| wa_05 | World -[initMuteList] | 0x005cfa88 | 222 | 7 | 3 | 3 | 3 | 10 | 7 |
| wa_06 | World -[reportUserWithName:reporterName:reporterMessage:reportedAvatarImagePath:] | 0x005d0e54 | 353 | 11 | 10 | 2 | 3 | 16 | 14 |
| wa_07 | World -[reportButtonTappedForPlayer:] | 0x005d218c | 239 | 10 | 6 | 2 | 1 | 8 | 1 |
| wa_08 | World -[alertView:didDismissWithButtonIndex:] | 0x005d1aa4 | 316 | 11 | 5 | 3 | 2 | 12 | 4 |

## The custom-rules sync pair (wa_00 / wa_01 / wa_02)

`setCustomRule:forOptionNamed:` (256w) is the admin-side writer: plist serialize
(NSPropertyListSerialization dataWithPropertyList:format:options:error:) →
gzipDeflate → sendDataToServer:reliable: (constants 0x40/0x64/0x42, isAdmin
gate). `customRuleDictRecievedFromNet:` (284w) is the receive side: dictionary
enumeration with key merge into customRulesDict and the customRulesChanged
notification (0x10/0x20/0x40, helper 0x559f78). `verifyClientCustomRulesData:`
(440w) is the verifier: gzipInflate + getBytes:length: with a nine-bailout
guard chain (helper 0x5d7794, stack-check pair). The three bodies form the
custom-rules loop: set → ship → verify → merge → notify.

## The moderation alerts (wa_03 / wa_07 / wa_08)

Three BlockAlertView flows share one shape: kick/ban confirmation
(kickOrBanPlayerFromButtonIsBan:withName:, 303w — destructive + cancel block
pair, uppercaseString title), report button (reportButtonTappedForPlayer:,
239w, reportedPlayerName capture) and the dismissal router
(alertView:didDismissWithButtonIndex:, 316w — message-entry textFieldAtIndex:/
text → reportUserWithName:... → confirm alert rebuild). The report payload
(reportUserWithName:reporterName:reporterMessage:reportedAvatarImagePath:,
353w) sanitizes strings (stringByReplacingOccurrencesOfString:withString:),
gzip-packs and sends through sendDataToServer:reliable: (helper 0x55468c,
constant 0x37).

## The mute list (wa_04 / wa_05)

initMuteList (222w) loads the per-save mute list into the mutedPlayers array
(NSSearchPathForDirectoriesInDomains path + dataWithContentsOfFile: +
initWithArray:; helper 0x559f54, constant 0xe) and setPlayerMuted:withID:
(162w) toggles it (containsObject:/addObject:/removeObject:) with the saveQueue
addOperationWithBlock: persist and the userMuteChanged: broadcast.

## Boundaries

- All nine bodies fully read (max 440w); no census members.
- The BlockAlertView / NSPropertyListSerialization / gzip helpers are asserted
  at the selector level; the server-side moderation endpoints are outside this
  batch.
- The 0x55468c helper (E103/E107/E108) recurs here in the report sender, and
  the 0x559f54/0x559f78 pair again as in E106.
