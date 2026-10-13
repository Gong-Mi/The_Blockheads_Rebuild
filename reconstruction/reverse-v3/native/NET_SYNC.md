# DynamicWorld net-sync + blockhead-load cluster — E21

The multiplayer-sync cluster of the world line: the dirty-tile flush, the 65-slot
network reconciliation loop, the per-object packet sender, the disconnected-client
restore, the client inventory receiver and the client blockhead-data loader.
**6 bodies, 10076 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_net_sync.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/net_sync.json`.

| body | imp | words | content |
|---|---|---:|---|
| updateNetObjects | 0x008c4c20 | 3313 | 65-slot reconciliation (create/update/remove + FreeBlock sounds) |
| loadAnyBlockheadsForDisconnectedClients | 0x008c9cac | 2040 | disconnected-client blockhead restore |
| loadClientBlockheadsDataForPlayerID: | 0x008fbe90 | 1880 | client blockhead-data restore on the server |
| sendNetDataIfNeededForObject:isCreation: | 0x008c7fe4 | 1495 | per-object packet builder/sender (server + client) |
| clientBlockheadInventoryRecievedForPlayerID:blockheadID:data: | 0x008fb288 | 770 | inventory snapshot receiver |
| saveAndSendOnlyBlocksThatNeedToBeSent | 0x008b49f8 | 578 | dirty-macro-tile flush |

## Load-bearing findings

- **Flush** (`saveAndSendOnlyBlocksThatNeedToBeSent`): server-gated; two queues
  (worldChangedMacroPositions / worldChangedSendUnreliablyMacroPositions) of macro
  positions; per entry `macroTileAtMacroPostion` then
  `savePhysicalBlockForMacroTile:sendReliably:{1 then 0} dontSend:0 onlySaveIfClientsNeedIt:1`;
  success erases the entry via the libc++ vector-erase path.
- **Reconciliation** (`updateNetObjects`): over 65 slots, four phases —
  (A) netCreateDynamicObjects enum with `getBytes:length:8` ID reads and
  `addIndex:` bookkeeping into netRemoveDynamicObjects, plus the **FreeBlock (slot
  0xe) branch** with the creation-sound ladder (4-second recency window,
  `freeBlockSoundDelay` < 1.0, per-type MJSoundManager sounds);
  (B) netUpdateCreationDataDynamicObjects -> **netBlockheads 24-byte records** ->
  `remoteCreationDataUpdate:`; (C) netUpdateDynamicObjects -> `remoteUpdate:`;
  (D) the phase-A index set applies **`setNeedsRemoved: 1`**; buffers clear with
  `removeAllObjects`.
- **Sender** (`sendNetDataIfNeededForObject:`): needs-flag gate
  (needsNetDataToBeSent / creationDataNeedsToBeSent / update/unreliableUpdate /
  needsRemoved). Server: `macroPosForWorldPos` + worldWidthMacro index, per connected
  client wire/unwire checks, removal packets (`addRemovalObjectDataToSend:`), creation
  (`addCreationObjectDataToSend:` + `wireDynamicObject:`), updates reliable/unreliable
  (`addUpdateObjectDataToSend:...reliable:`), creation-data updates
  (`creationNetDataForClient:` -> `addCreationDataUpdateObjectDataToSend:`).
  Client: type whitelist (0x18, interaction objects, 0xa/0x1b/0x3b/0xb/0xc/...),
  gzip packet via `gzipDeflate` + the shared helper `0x8b84c8` +
  `sendDataToServer:reliable:` with packet markers 0xa/0xb/0x45/0xc; **needs flags
  cleared after send** (`setUpdateNeedsToBeSent:0` etc.).
- **Disconnected restore**: per save-dir name the payload comes from worldDatabase
  `dataForKey:` (gzip) or the file (migration gate + substringWithRange path); entries
  are matched by ID; `setClientID:` vs `addObject:`; counterpart find via uniqueID with
  `blockheadWillBeUnloaded:` + restore-dict helpers (getSaveDictIncludingWorkbenchOrInterationObject:,
  stopRiding, stopInteracting...), `customRules[+0x32]==4 -> die`; second phase attaches
  client names via `playerInfoForPeerID:`.
- **Inventory receiver**: liveServerClientBlockheadInventories bootstrap, gzipInflate +
  propertyListWithData decode, 8-slot InventoryItem rebuild (`initWithSaveData:`,
  `updateSubItemSlot:atIndex:`), re-encode via `gzipDeflate` +
  `dataWithPropertyList:format:options:error:`.
- **Client-data loader**: per-client save decode (parser `0x8b1db0` + plist), the
  keyed-archive read/write pairing (`initForWritingWithMutableData:` /
  `encodeObject:forKey:` / `finishEncoding` and `initForReadingWithData:` /
  `decodeObjectForKey:` / `finishDecoding`), `welcomeBackEventsMessageForClientID:`,
  the 8-slot inventory loop into liveServerClientBlockheadInventories, NSLog mismatch
  strings (0xfff341a4/0xfff34204/0xfff34214/0xfff34224).

## Boundaries (honest)

- Wire-format markers (0xa/0xb/0x45/0xc) and the type whitelist are read from
  immediates; the protocol line owns their meanings.
- The NSLog key strings (0xfff33df4/0xfff33e44/0xfff340e4/0xfff340f4/0xfff34104/
  0xfff34114/0xfff341a4/0xfff34204/0xfff34214/0xfff34224 and the sound strings
  0xfff34074/0x84/0x94/0xa4/0xb4) are pinned by address, not decoded to text.
- The C++ container member layouts behind the slice offsets (+0xa8/+0x168, the
  65-slot arrays) and the 12-byte-padded macro-position records are observed.
- `bl 0x8b84c8` is the shared packet-append helper outside these bodies; the
  blockhead restore's cleanup-call ordering is read where visible and pinned by
  selector cells elsewhere.
