# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 35474 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| bs_00 | BHServer -[addPlayerDictToAllPlayersEver:] | 0x00533cbc | 307 | 12 | 8 | 3 | 3 | 17 | 3 |
| bs_01 | BHServer -[adminList] | 0x00551938 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| bs_02 | BHServer -[blackList] | 0x005518b0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| bs_03 | BHServer -[bootAllClientsDueToNoCredit] | 0x00531d90 | 345 | 11 | 3 | 3 | 3 | 15 | 5 |
| bs_04 | BHServer -[bootPlayer:wasBan:] | 0x005317e0 | 133 | 6 | 1 | 0 | 2 | 5 | 0 |
| bs_05 | BHServer -[bootPlayerNamed:wasBan:] | 0x005322f4 | 406 | 7 | 5 | 2 | 0 | 19 | 22 |
| bs_06 | BHServer -[cleanup] | 0x005336cc | 227 | 6 | 2 | 3 | 1 | 10 | 6 |
| bs_07 | BHServer -[clearList:] | 0x00547acc | 261 | 8 | 10 | 1 | 2 | 12 | 15 |
| bs_08 | BHServer -[clientDisconnected:wasKick:] | 0x00531370 | 53 | 2 | 1 | 2 | 0 | 2 | 0 |
| bs_09 | BHServer -[clientFinishedAwaySimulation:] | 0x00543a4c | 189 | 5 | 2 | 1 | 0 | 8 | 7 |
| bs_10 | BHServer -[connectedClientIDs] | 0x00551a48 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| bs_11 | BHServer -[credit] | 0x00550088 | 51 | 2 | 1 | 1 | 0 | 2 | 2 |
| bs_12 | BHServer -[dealloc] | 0x00532cb8 | 235 | 2 | 2 | 15 | 1 | 16 | 0 |
| bs_13 | BHServer -[delayedDisconnectPlayerDueToKickWithID:] | 0x00531444 | 231 | 7 | 1 | 3 | 0 | 10 | 10 |
| bs_14 | BHServer -[delayedDisconnectPlayerDueToNoCreditWithID:] | 0x005319f4 | 231 | 7 | 1 | 3 | 0 | 10 | 10 |
| bs_15 | BHServer -[delayedSendUpdatedPlayerListToClients] | 0x00544c00 | 313 | 9 | 2 | 5 | 2 | 14 | 7 |
| bs_16 | BHServer -[doRepairForTileAtPos:] | 0x005517fc | 28 | 1 | 0 | 1 | 0 | 1 | 0 |
| bs_17 | BHServer -[finishBulkTransaction] | 0x00551794 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| bs_18 | BHServer -[full] | 0x00534ec0 | 85 | 2 | 1 | 3 | 0 | 3 | 3 |
| bs_19 | BHServer -[fullPlayerInformationNowAvailableForPlayer:] | 0x00535014 | 451 | 15 | 6 | 5 | 0 | 24 | 13 |
| bs_20 | BHServer -[getDebugLog] | 0x0054fe7c | 105 | 4 | 4 | 2 | 1 | 5 | 0 |
| bs_21 | BHServer -[getRecentPlayerNamesForOwnershipSign] | 0x00550664 | 679 | 10 | 7 | 2 | 2 | 31 | 25 |
| bs_22 | BHServer -[handleCommand:issueClient:] | 0x0054a448 | 5773 | 85 | 88 | 14 | 9 | 302 | 393 |
| bs_23 | BHServer -[infoArrived:forPlayer:] | 0x00535720 | 58 | 3 | 2 | 0 | 1 | 3 | 0 |
| bs_24 | BHServer -[initWithDelegate:match:netNodeType:saveID:maxPlayers:] | 0x0052eb80 | 2370 | 47 | 28 | 17 | 14 | 137 | 42 |
| bs_25 | BHServer -[isCloudMatch] | 0x00550020 | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| bs_26 | BHServer -[isWaitingForMultiPartCommandResponse] | 0x005505e4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bs_27 | BHServer -[match:connectionWithPlayerFailed:withError:] | 0x00533a58 | 153 | 6 | 2 | 4 | 0 | 8 | 1 |
| bs_28 | BHServer -[match:didFailWithError:] | 0x00533678 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| bs_29 | BHServer -[match:didReceiveData:fromPlayer:] | 0x005379e8 | 11490 | 237 | 64 | 37 | 32 | 619 | 407 |
| bs_30 | BHServer -[match:player:didChangeState:] | 0x00534188 | 846 | 28 | 9 | 8 | 5 | 39 | 29 |
| bs_31 | BHServer -[match:shouldReinvitePlayer:] | 0x00542f3c | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| bs_32 | BHServer -[modList] | 0x0055197c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| bs_33 | BHServer -[modifyListForPlayerOrIP:isAdded:listType:] | 0x00547ee0 | 37 | 1 | 1 | 0 | 0 | 1 | 0 |
| bs_34 | BHServer -[modifyListForPlayerOrIP:isAdded:listType:banUDID:] | 0x00547f74 | 1759 | 35 | 24 | 10 | 5 | 82 | 95 |
| bs_35 | BHServer -[playerIsAdminWithAlias:] | 0x00537044 | 176 | 4 | 1 | 1 | 0 | 7 | 12 |
| bs_36 | BHServer -[playerIsAdminWithID:] | 0x00536f68 | 55 | 3 | 2 | 0 | 0 | 3 | 0 |
| bs_37 | BHServer -[playerIsBannedWithID:] | 0x00536160 | 246 | 9 | 1 | 1 | 2 | 12 | 11 |
| bs_38 | BHServer -[playerIsBlackListedWithInfo:] | 0x00535808 | 354 | 7 | 5 | 1 | 0 | 17 | 20 |
| bs_39 | BHServer -[playerIsCloudWideAdminWithAlias:] | 0x00536ae4 | 151 | 3 | 1 | 1 | 0 | 6 | 8 |
| bs_40 | BHServer -[playerIsCloudWideInvisibleAdminWithAlias:] | 0x00536d40 | 138 | 2 | 1 | 1 | 0 | 5 | 8 |
| bs_41 | BHServer -[playerIsConnectedWithInfo:] | 0x0053788c | 87 | 3 | 3 | 1 | 0 | 4 | 1 |
| bs_42 | BHServer -[playerIsModWithAlias:] | 0x00537304 | 151 | 3 | 1 | 1 | 0 | 6 | 8 |
| bs_43 | BHServer -[playerIsOwnerWithAlias:] | 0x00536930 | 109 | 4 | 1 | 1 | 0 | 5 | 5 |
| bs_44 | BHServer -[playerIsWhiteListedWithInfo:] | 0x0053655c | 245 | 5 | 3 | 1 | 0 | 11 | 13 |
| bs_45 | BHServer -[playerListToSendIncludingPhotosForClients:sendClient:] | 0x00543d40 | 777 | 18 | 13 | 2 | 3 | 42 | 27 |
| bs_46 | BHServer -[playerNameForPlayerWithIDIncludingOldPlayers:] | 0x00550258 | 99 | 3 | 2 | 0 | 0 | 5 | 6 |
| bs_47 | BHServer -[playerUpdate] | 0x005519c0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| bs_48 | BHServer -[privacyString] | 0x00550430 | 109 | 4 | 4 | 1 | 1 | 4 | 8 |
| bs_49 | BHServer -[recentPlayers] | 0x0055186c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| bs_50 | BHServer -[reloadLists] | 0x005450e4 | 2682 | 41 | 14 | 18 | 6 | 168 | 92 |
| bs_51 | BHServer -[removeCurseWordsFromBlockheadName:] | 0x0054a0a4 | 233 | 5 | 1 | 1 | 1 | 10 | 9 |
| bs_52 | BHServer -[replaceCurseWordsForMessage:client:] | 0x00549af0 | 365 | 10 | 5 | 2 | 3 | 15 | 13 |
| bs_53 | BHServer -[saveAllPlayersArray] | 0x0053294c | 51 | 1 | 2 | 2 | 0 | 2 | 1 |
| bs_54 | BHServer -[saveResetList] | 0x00532a18 | 168 | 6 | 2 | 2 | 3 | 7 | 4 |
| bs_55 | BHServer -[savedPlayerInfoDataForPlayer:] | 0x00535d90 | 244 | 8 | 4 | 3 | 2 | 12 | 2 |
| bs_56 | BHServer -[sendChatMessage:displayNotification:sendToClients:] | 0x00542f60 | 699 | 21 | 13 | 4 | 5 | 35 | 17 |
| bs_57 | BHServer -[sendInitialPlayerListToClient:] | 0x00544964 | 131 | 6 | 1 | 1 | 2 | 7 | 1 |
| bs_58 | BHServer -[sendNetworkData:toPeers:reliable:] | 0x00542d70 | 115 | 2 | 1 | 2 | 0 | 3 | 6 |
| bs_59 | BHServer -[sendPlayerChangedNotifcationToDelegate] | 0x00550600 | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| bs_60 | BHServer -[sendPortalChestAcknowledgementIfNeededForClient:] | 0x005512b8 | 285 | 11 | 3 | 2 | 4 | 14 | 2 |
| bs_61 | BHServer -[sendUpdatedPlayerListToClients] | 0x00544b70 | 36 | 2 | 1 | 1 | 0 | 1 | 0 |
| bs_62 | BHServer -[serverDatabase] | 0x00551a04 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| bs_63 | BHServer -[serverPlayerID] | 0x005503e4 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| bs_64 | BHServer -[setWorld:] | 0x00533064 | 389 | 14 | 2 | 3 | 1 | 17 | 9 |
| bs_65 | BHServer -[startBulkTransaction] | 0x0055172c | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| bs_66 | BHServer -[updateCredit:] | 0x00550154 | 65 | 3 | 1 | 1 | 0 | 3 | 1 |
| bs_67 | BHServer -[updatePlayer:] | 0x00537560 | 45 | 2 | 1 | 1 | 0 | 2 | 0 |
| bs_68 | BHServer -[updatePlayers] | 0x00537614 | 158 | 3 | 1 | 3 | 1 | 5 | 3 |
| bs_69 | BHServer -[whiteList] | 0x005518f4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |

# BHServer multiplayer server object (E133)

The 70 remaining uncovered BHServer bodies in the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).
BHServer is the client-side object that <em>runs</em> a multiplayer session (Game Center
`GKMatch` transport): connections, join/auth, chat commands, moderation lists, player
bookkeeping, the save database, boot/kick, the receive pump and the heartbeat/idle
watcher. **70 bodies / 35,474 instruction words / 1382 in-body branches /
1829 call rows.**

Method: batch listings `bs_00..bs_69` (r2 + GNU objdump cross-check) under this work
dir; a per-body digest resolved every pool cell through the offset-cell model
(selectors/imports/ivars/classes) with a light register-tag tracker for objc dispatch,
ivar read/write direction and CFString literals (read straight from the ELF data
segment); then 65 bodies were read line-by-line (register-spill pairs elided) and the
five >1000w bodies (bs_22/24/29/34/50) got census passes (full call histograms, constant
pools, section maps, spot windows). Semantics: `semantics_bhserver.json`.

## Findings (E133)

### The object and its ivar map (offset-cell oracle)

- **BHServer : BHNetNode** — the class adds 27 ivars over BHNetNode's
  `delegate@0x04`, `match@0x08`, `livePlayerInfos@0x10`. The `dealloc` release wall
  (bs_12, 15 releases) releases exactly the retained collections, giving the full
  layout below. Every getter reads its slot through an Apportable offset-cell
  (`ldr off,[cell]; ldr off,[off]; add self+off`) behind a `dmb ish`.
- The server reaches its transport only through `self.match` (0x08): `isCloudMatch`,
  `credit`/`setCredit:`, `privacy`/`setPrivacy:`, `ownerName`, `localPlayerName`,
  `serverPassword`, `sendData:toPlayers:withDataMode:error:` and the GKMatch
  delegate callbacks all dispatch on it (20 ivar reads of match in bs_29 alone).

| off | ivar |
|---|---|
| 0x04 | BHNetNode.delegate  (inherited) |
| 0x08 | BHNetNode.match  (inherited) |
| 0x10 | BHNetNode.livePlayerInfos  (inherited) |
| 0x1c | world |
| 0x20 | saveID |
| 0x24 | unapprovedClients |
| 0x28 | connectedClients |
| 0x2c | chatHistory |
| 0x30 | recentPlayers |
| 0x34 | blackList |
| 0x38 | curseList |
| 0x3c | whiteList |
| 0x40 | adminList |
| 0x44 | cloudWideAdminList |
| 0x48 | cloudWideInvisibleAdminList |
| 0x4c | modList |
| 0x50 | resetList |
| 0x54 | repairSet |
| 0x58 | maxPlayers |
| 0x5c | cachedPlayerImages |
| 0x60 | cachedPlayerBanned |
| 0x64 | needsToSendUpdatedListToClients |
| 0x6c | clientsConnectedWithPhotosUnsent |
| 0x70 | tradePortalTransactions |
| 0x74 | playerUpdate |
| 0x78 | playerUpdateTimer |
| 0x80 | lastPlayerUpdate |
| 0x88 | rulesChangedTime |
| 0x90 | serverDatabaseEnvironment |
| 0x94 | serverDatabase |

### The wire protocol

- **bs_29 `match:didReceiveData:fromPlayer:`** (11490w, census-grade) is the receive
  pump: it first runs `[self updatePlayers]` (idle tick), reads the type byte as
  `data.bytes[0]`, drops packets from senders not in `connectedClients` **unless the
  type is 0x1f**, then runs a **45-entry type if-chain** in this order:
  `0x1f, 3, 0x1f, 5, 0x17, 0xd, 0xe, 0x10, 0x11, 0x3a, 0x29, 0x2a, 0x19, 0x12, 0x14, 0xa, 0xb, 0x45, 0xc, 0x15, 0x16, 0x18, 0x44, 0x1a, 0x2c, 0x2d, 0x1b, 0x20, 0x21, 0x2e, 0x30, 0x34, 0x35, 0x37, 0x38, 0x39, 0x3b, 0x3e, 0x40, 0x24, 0x42, 0x48, 0x4c, 0x49, 0x4b`
  (45 compare sites; the leading `0x1f/3/0x1f` triplet are the admission-order
  specials before the main lanes). Confirmed handlers:
  **0x17 -> `heartbeatDataRecieved:fromPeer:`** (E103's heartbeat type code 23),
  **0xd -> `remoteBlockRemoved:byClient:`**. Inside the chain: the remote world-op
  family (`remoteFillRequest:placedByClient:`, `remoteRemoveRequest:fromClient:`,
  `remoteRemoveBackWallRequest:fromClient:`, `remotePaintRequest:fromClient:`,
  `remoteProjectileRequest:`, `remoteBlockheadDamageRequest:requestedByClientName:`),
  the join/auth path (`playerIsBlackListedWithInfo:` / `playerIsWhiteListedWithInfo:` /
  `requiresPlayerAuthentication` / `clientApprovedWithInfo:` /
  `'Kicking player %@ due to likely cheating.'`), chat + photo messages, and the
  cloud plumbing. Notable per-body strings: `'%@_lastPortalChestAck'`, `'mode1'/'mode2'`.
- **Server -> client packets** build a 1-byte type header + plist payload:
  **0x26** = boot/kick (bs_04 `bootPlayer:wasBan:`, bs_03 `bootAllClientsDueToNoCredit`
  with worldName/worldID header, delayed disconnect 2.0s/4.0s), **0x3f** =
  portal-chest acknowledgement (bs_60), **0x1e** frames the initial player list (bs_57).
- **Payload engine = property lists.** C helpers: **0x531204** =
  `NSPropertyListSerialization dataWithPropertyList:format:options:error:` wrapper
  (@try/@catch + NSLog), **0x531098** = `propertyListWithData:options:format:error:`
  wrapper, **0x536538** = 1-arg decode wrapper, **0x531088** = `lrand48` wrapper.
  Used by 15+ bodies (net payloads and *all* DB blobs are plists).
- **Send spine**: `sendNetworkData:toPeers:reliable:` (bs_58) = one method, two
  `sendData:toPlayers:withDataMode:error:` sites (mode by the reliable flag);
  `sendData:toPlayers:withDataMode:error:` also used directly for per-client pushes
  (bs_15/57).

### Permissions ladder and moderation

- **Roles**: owner (bs_43: `match.ownerName` compare + GameCenter
  `usesGameCenterPlayerInformation`/`localPlayerName` fallback) -> admin (bs_35:
  adminList, falls back to cloudWideAdmin) -> cloudWideAdmin (bs_39, falls back to
  cloudWideInvisibleAdmin bs_40) -> mod (bs_42: modList, falls back to admin).
  ID-based: `playerIsAdminWithID:` (bs_36), `playerIsBannedWithID:` (bs_37, memoized
  in `cachedPlayerBanned` @0x60, resolves through `savedPlayerInfoDataForPlayer:`
  when the player is offline).
- **Blacklist** (bs_38): mods are exempt; entries match `'alias'`, `'ip'`,
  `'udidNew'` (file lines are `alias \ ip` token pairs split on `' \'`).
  **Whitelist** (bs_44): empty list passes; mods bypass; a non-empty whitelist forces
  the privacy setting to SEARCHABLE (`CLOUD:SETTING:WHITELISTED:ON` +
  `[match setPrivacy:]`) and boots non-whitelisted connected clients (bs_50).
- **The four list files**: `blacklist.txt` / `whitelist.txt` / `adminlist.txt` /
  `modlist.txt` under `'%@/saves/%@/'`, plus cloud-side
  `cloudWideOwnedAdminlist.txt` / `cloudWideInvisibleAdminlist.txt` / `curseList.txt`
  under `'%@/'` (bs_50 loads all seven; every file drops its first line as a header).
  The header texts are literal in the binary, e.g. blacklist:
  `'Usernames or IP addresses in this file will not be able to connect. ...'`;
  admin: `'Usernames in this file will be able to issue all server commands via chat,
  and pick up and remove all objects. ...'` (bs_07 writes template files with these
  headers via `writeToFile:atomically:encoding:error:` then `reloadLists`).
- **The list editor** (bs_34, census): add/remove with status replies
  `'%@ was already on the %@'` / `'%@ has been added to the %@'` /
  `'%@ has been removed from the %@'` / `'%@ was not on the %@'`, file rewrite +
  reloadLists, then live-apply: `setIsAdmin:` on the connected client's server
  record for admin-list changes, `dynamicWorld userBanChanged:isBanned:` for the
  blacklist, and `sendUpdatedPlayerListToClients` (a `makeIntpair` call appears in
  the notify block).

### The chat-command surface (bs_22, census)

`handleCommand:issueClient:` (5773w / 393 branches) is the in-game `/command`
router, gated on `[self.match usesGameCenterPlayerInformation]`. It parses the
message (`componentsSeparatedByString:@" "`, `rangeOfString:`, `substringToIndex:`,
`uppercaseString`) and if-chains ~50 commands:

`set-credit / set-owner / remove-owner / set-salt / set-privacy / set-password /
remove-password / help / players / stop / pvp-on / pvp-off / load-lists / clear /
clear-blacklist / clear-whitelist / clear-adminlist / clear-modlist / debug-log /
list-blacklist / list-whitelist / list-adminlist / list-modlist / kick / ban /
ban-no-device / unban / whitelist / unwhitelist / admin / unadmin / mod / unmod /
repair / reset-owner`

with permission gates (`playerIsOwner/Admin/Mod/CloudWideAdminWithAlias`, 16x
`modifyListForPlayerOrIP:..., 2x the banUDID variant), cloud replies
(`CLOUD:SETTING:PRIVACY:*`, `CLOUD:SETTING:PASSWORD:ON/OFF`, `CLOUD:SETTING:PVP:*`,
`CLOUD:STAT:PLAYERS:*`), and chat responses via `chatMessageRecieved:displayNotification:`.
Notable operator strings: `'Password set.'`, `'There are %ld players connected:%@'`,
`'Repair mode is now enabled. Tapping any non-solid tile will now remove any contents
within. ...'`, `'CLOUD:SETTING:PRIVACY:SEARCHABLE'` on whitelist transitions.

### Player bookkeeping, boot/kick, idle timeout

- `recentPlayers` is capped at **0x80 (128)** (bs_00, `removeLastObject` past the cap)
  and scanned with a **50-entry** window in the sign/name lists (bs_19/21,
  `cmp 0x32`).
- **Boot/kick**: `bootPlayer:wasBan:` (bs_04) builds the 0x26 packet; alias search
  `bootPlayerNamed:` (bs_05) scans connectedClients then recentPlayers (cap 64),
  logging `'Kicking player:%@'` / `'No player found named %@'`;
  `delayedDisconnectPlayerDueToKickWithID:` (bs_13) vs
  `...DueToNoCreditWithID:` (bs_14) are **instruction-identical twins differing only
  in the `wasKick` flag constant (1 vs 0)**.
- **Idle tick** (bs_68 `updatePlayers`): per `playerUpdate` entry the elapsed
  `timeIntervalSinceReferenceDate` delta is `clamp_float(_, 0, 5)`d; expired players
  get a randomized grace (`lrand48` +1.0 scale, constants 10/50) and a delayed kick.
  `sendUpdatedPlayerListToClients` (bs_61) coalesces via
  `performSelector:...afterDelay: 2.0`; bs_15 flushes when the dirty byte is set.
- **GKMatch lifecycle**: bs_30 `match:player:didChangeState:` - Connected sends the
  join/auth dict (ownerName/requiresPassword/worldID/serverPassword/saveID) and
  records the player in `unapprovedClients`; Disconnected logs
  `'%@ - Player Disconnected %@'`, removes the client from
  connectedClients/unapprovedClients/tradePortalTransactions and refreshes everyone.
  bs_27 `connectionWithPlayerFailed:` drops the player + logs; bs_28 `didFailWithError:`
  -> `cleanup` (bs_06: notifies clients, clears both client sets, `[super cleanup]`).
- **Player info paths**: bs_46 name lookup (live peerID -> `'alias'`, else
  `savedPlayerInfoDataForPlayer:` + plist decode); bs_55 the dual-source saved-info
  accessor (kvs `'%@_info'` after `hasFinishedDatabaseMigrationTo17`, else
  `playerInfo.plist` file); bs_41 `playerIsConnectedWithInfo:` (`'local'` flag or
  connectedClients contains `'playerID'`); bs_19 the full-info arrival (log line
  `'%@ - Player Connected %@ | %@ | %@'` with `'IP hidden'` substitution, recentPlayers
  insert + `addPlayerDictToAllPlayersEver:` + `saveAllPlayersArray` +
  `sendInitialPlayerListToClient:`); bs_23 super-bridge.
- bs_21 builds the ownership-sign name list (`name`/`id` dicts from connectedClients +
  recentPlayers, `arrayByAddingObjectsFromArray:`, sorted by comparators).

### Chat and profanity

- bs_56 `sendChatMessage:displayNotification:sendToClients:` = the broadcast: builds
  the SERVER entry (`alias/message/date/playerID` + owner/mod flags), keeps
  `chatHistory` capped at **20** (`cmp 0x14`), resolves avatars through
  `cachedPlayerImages` (paths with `'GameResources/'`, `'photo_image'`,
  `'noGCAvatar.png'`), plist-encodes and sends, then displays locally.
- Curse filters (bs_51/52) scan `curseList` with `rangeOfString:` under the
  `objc_msgSend_stret` calling convention guarded by **NSNotFound = 0x7fffffff**;
  bs_52 warns the sender: `'Cursing/swearing is not allowed on public servers. Your
  message was modified to %@.'` and broadcasts the modified message.
- bs_12 dealloc + bs_07 clearList + bs_50 reloadLists complete the moderation loop.

### Database, construction, misc

- **bs_24** `initWithDelegate:match:netNodeType:saveID:maxPlayers:` (census) is the
  full construction: super-init; `serverDatabase` on `'%@/saves/%@/server_db/'`
  (`initWithPath:maxDatabases:maxMapSizeInMB:` + `initWithEnvironment:name:`);
  capacity arrays; `reloadLists`; two file migrations with NSLog markers
  (`'Upgrading players list from 1.4 format to 1.5.0...'` - strip
  photo/voiceConnected/micOrSpeakerOn/connected and rewrite `allPlayers.plist`;
  `'...1.5 format to 1.5.1...'` - move per-player files into
  `'%@/saves/%@/players/.../playerInfo.plist'` + `recentPlayers.plist`); loads
  `recentPlayers` + `resetList`; when cloud, sends `CLOUD:SETTING:PRIVACY:%@`
  (uppercased `privacyString`, default `'PUBLIC'`) and `CLOUD:STAT:PLAYERS:0`.
  The debug log (bs_20) reports **`'server version:1.7.3'`** - the server protocol
  version string carried by this client build.
- `saveAllPlayersArray` (bs_53) stores the plist under `'recentPlayers'` in the kvs
  DB; `saveResetList` (bs_54) writes `resetList.plist` (XML format 100) or removes
  the file when empty; bs_17/bs_65 are the `serverDatabaseEnvironment`
  bulk-transaction pair; bs_16 forwards `doRepairForTileAtPos:` to the world;
  bs_63 `serverPlayerID` -> `[self localPlayerID]`; bs_18 `full` =
  `max([world serverClients count], [connectedClients count]) >= maxPlayers || >= 32`.
- **bs_26 returns constant NO** (`isWaitingForMultiPartCommandResponse`;
  commands complete synchronously); **bs_31 returns constant YES**
  (`match:shouldReinvitePlayer:`).

### Per-body index (words / branches / static-call sites / objc dispatch sites / ivar touches)

| body | selector | words | br | bl | objc | ivar |
|---|---|---|---|---|---|---|
| bs_00 | `-addPlayerDictToAllPlayersEver:` | 307 | 3 | 1 | 16 | 6 |
| bs_01 | `-adminList` | 17 | 0 | 0 | 0 | 1 |
| bs_02 | `-blackList` | 17 | 0 | 0 | 0 | 1 |
| bs_03 | `-bootAllClientsDueToNoCredit` | 345 | 5 | 3 | 12 | 3 |
| bs_04 | `-bootPlayer:wasBan:` | 133 | 0 | 0 | 5 | 0 |
| bs_05 | `-bootPlayerNamed:wasBan:` | 406 | 22 | 6 | 13 | 2 |
| bs_06 | `-cleanup` | 227 | 6 | 2 | 8 | 5 |
| bs_07 | `-clearList:` | 261 | 15 | 1 | 11 | 1 |
| bs_08 | `-clientDisconnected:wasKick:` | 53 | 0 | 0 | 2 | 2 |
| bs_09 | `-clientFinishedAwaySimulation:` | 189 | 7 | 2 | 6 | 2 |
| bs_10 | `-connectedClientIDs` | 17 | 0 | 0 | 0 | 1 |
| bs_11 | `-credit` | 51 | 2 | 0 | 2 | 1 |
| bs_12 | `-dealloc` | 235 | 0 | 0 | 16 | 15 |
| bs_13 | `-delayedDisconnectPlayerDueToKickWithID:` | 231 | 10 | 2 | 8 | 4 |
| bs_14 | `-delayedDisconnectPlayerDueToNoCreditWithID:` | 231 | 10 | 2 | 8 | 4 |
| bs_15 | `-delayedSendUpdatedPlayerListToClients` | 313 | 7 | 4 | 10 | 7 |
| bs_16 | `-doRepairForTileAtPos:` | 28 | 0 | 1 | 0 | 1 |
| bs_17 | `-finishBulkTransaction` | 26 | 0 | 0 | 1 | 1 |
| bs_18 | `-full` | 85 | 3 | 0 | 3 | 3 |
| bs_19 | `-fullPlayerInformationNowAvailableForPlayer:` | 451 | 13 | 3 | 21 | 7 |
| bs_20 | `-getDebugLog` | 105 | 0 | 0 | 5 | 2 |
| bs_21 | `-getRecentPlayerNamesForOwnershipSign` | 679 | 25 | 6 | 25 | 2 |
| bs_22 | `-handleCommand:issueClient:` | 5773 | 393 | 116 | 186 | 45 |
| bs_23 | `-infoArrived:forPlayer:` | 58 | 0 | 0 | 3 | 0 |
| bs_24 | `-initWithDelegate:match:netNodeType:saveID:maxP` | 2370 | 42 | 44 | 92 | 1 |
| bs_25 | `-isCloudMatch` | 26 | 0 | 0 | 1 | 1 |
| bs_26 | `-isWaitingForMultiPartCommandResponse` | 7 | 0 | 0 | 0 | 0 |
| bs_27 | `-match:connectionWithPlayerFailed:withError:` | 153 | 1 | 1 | 7 | 5 |
| bs_28 | `-match:didFailWithError:` | 21 | 0 | 0 | 1 | 0 |
| bs_29 | `-match:didReceiveData:fromPlayer:` | 11490 | 407 | 81 | 537 | 142 |
| bs_30 | `-match:player:didChangeState:` | 846 | 29 | 4 | 35 | 16 |
| bs_31 | `-match:shouldReinvitePlayer:` | 9 | 0 | 0 | 0 | 0 |
| bs_32 | `-modList` | 17 | 0 | 0 | 0 | 1 |
| bs_33 | `-modifyListForPlayerOrIP:isAdded:listType:` | 37 | 0 | 0 | 1 | 0 |
| bs_34 | `-modifyListForPlayerOrIP:isAdded:listType:banUD` | 1759 | 95 | 12 | 68 | 11 |
| bs_35 | `-playerIsAdminWithAlias:` | 176 | 12 | 2 | 5 | 1 |
| bs_36 | `-playerIsAdminWithID:` | 55 | 0 | 0 | 3 | 0 |
| bs_37 | `-playerIsBannedWithID:` | 246 | 11 | 1 | 11 | 5 |
| bs_38 | `-playerIsBlackListedWithInfo:` | 354 | 20 | 2 | 15 | 2 |
| bs_39 | `-playerIsCloudWideAdminWithAlias:` | 151 | 8 | 2 | 4 | 1 |
| bs_40 | `-playerIsCloudWideInvisibleAdminWithAlias:` | 138 | 8 | 2 | 3 | 1 |
| bs_41 | `-playerIsConnectedWithInfo:` | 87 | 1 | 0 | 4 | 1 |
| bs_42 | `-playerIsModWithAlias:` | 151 | 8 | 2 | 4 | 1 |
| bs_43 | `-playerIsOwnerWithAlias:` | 109 | 5 | 0 | 5 | 3 |
| bs_44 | `-playerIsWhiteListedWithInfo:` | 245 | 13 | 2 | 9 | 2 |
| bs_45 | `-playerListToSendIncludingPhotosForClients:send` | 777 | 27 | 2 | 40 | 2 |
| bs_46 | `-playerNameForPlayerWithIDIncludingOldPlayers:` | 99 | 6 | 1 | 4 | 0 |
| bs_47 | `-playerUpdate` | 17 | 0 | 0 | 0 | 1 |
| bs_48 | `-privacyString` | 109 | 8 | 0 | 4 | 2 |
| bs_49 | `-recentPlayers` | 17 | 0 | 0 | 0 | 1 |
| bs_50 | `-reloadLists` | 2682 | 92 | 18 | 149 | 36 |
| bs_51 | `-removeCurseWordsFromBlockheadName:` | 233 | 9 | 7 | 3 | 1 |
| bs_52 | `-replaceCurseWordsForMessage:client:` | 365 | 13 | 7 | 8 | 2 |
| bs_53 | `-saveAllPlayersArray` | 51 | 1 | 1 | 1 | 2 |
| bs_54 | `-saveResetList` | 168 | 4 | 1 | 6 | 3 |
| bs_55 | `-savedPlayerInfoDataForPlayer:` | 244 | 2 | 6 | 6 | 3 |
| bs_56 | `-sendChatMessage:displayNotification:sendToClie` | 699 | 17 | 1 | 34 | 12 |
| bs_57 | `-sendInitialPlayerListToClient:` | 131 | 1 | 1 | 6 | 1 |
| bs_58 | `-sendNetworkData:toPeers:reliable:` | 115 | 6 | 0 | 3 | 4 |
| bs_59 | `-sendPlayerChangedNotifcationToDelegate` | 25 | 0 | 0 | 1 | 1 |
| bs_60 | `-sendPortalChestAcknowledgementIfNeededForClien` | 285 | 2 | 1 | 13 | 5 |
| bs_61 | `-sendUpdatedPlayerListToClients` | 36 | 0 | 0 | 1 | 1 |
| bs_62 | `-serverDatabase` | 17 | 0 | 0 | 0 | 1 |
| bs_63 | `-serverPlayerID` | 19 | 0 | 0 | 1 | 0 |
| bs_64 | `-setWorld:` | 389 | 9 | 2 | 15 | 6 |
| bs_65 | `-startBulkTransaction` | 26 | 0 | 0 | 1 | 1 |
| bs_66 | `-updateCredit:` | 65 | 1 | 0 | 3 | 2 |
| bs_67 | `-updatePlayer:` | 45 | 0 | 0 | 2 | 2 |
| bs_68 | `-updatePlayers` | 158 | 3 | 2 | 3 | 4 |
| bs_69 | `-whiteList` | 17 | 0 | 0 | 0 | 1 |

(The five census bodies carry "census-grade" in their semantics entry: bs_22 5773w,
bs_24 2370w, bs_29 11490w, bs_34 1759w,
bs_50 2682w; the other 65 bodies were read line-by-line.)

## Boundaries

- **Census-grade, not per-instruction**: bs_29, bs_22, bs_50, bs_24, bs_34 (the five
  >1000w bodies). Their semantics rest on full call histograms + resolved constant
  pools + section maps + spot windows; bs_29's type->handler mapping was validated by
  windows only for types 0x1f/3/5/0x17/0xd - the other 40 lanes are not individually
  attributed. No per-instruction walkthrough exists for these five.
- **Helper names are inferred** from each helper's own callee selector
  (`0x531204`/`0x531098`/`0x536538`/`0x531088` are local labels, not dynsym symbols).
- **Unresolved items**: the role bitmask constants `0xa8f4`/`0x4d83` in bs_64; the
  comparator blocks in bs_21/others (2 + 1 + 1 + 2 dispatch sites reported as '?');
  exact curse-word replacement text (bs_51/52) - the rebuild path is described from
  structure, the substituted string was not extracted; bs_22's remaining `?` sites.
- **Reading method**: the 65 read bodies were examined in denoised form (pure
  register-spill `ldr/str [sp/fp-]` pairs elided); every raw line was nevertheless
  processed by the digest tracker, so the call/branch/ivar counts cover the full
  bodies. Constant-pool words were re-read directly from the ELF (not from
  listing text).
- **Static analysis only** - no runtime validation in this batch; packet payload
  structure is evidenced by type bytes + plist framing (the key names are the
  literals, not confirmed wire contract). Cross-check against the Linux server
  binary (dwarf/protocol line) is left open.
- bs_29/22 string literals are decoded from the CFString structs (`strptr` at
  struct+8); r2's pool-comment byte renderings were not used as evidence.
