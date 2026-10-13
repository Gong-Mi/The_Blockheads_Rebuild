# World ownership-signs line (E111)

The World ownership-signs line: the sign placement/sync writer pair, the area overlay rebuild and the per-client lit-tile probe. 7 bodies, 1542 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wo_00 | World -[updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:] | 0x005d35cc | 527 | 15 | 7 | 2 | 4 | 28 | 16 |
| wo_01 | World -[ownershipSignWasPlacedOrChangedAtPos:withLandOwner:widthRadius:heightRadius:wasRemoved:] | 0x005d4144 | 373 | 9 | 7 | 3 | 3 | 18 | 6 |
| wo_02 | World -[signOwnershipModificationRecievedFromServer:] | 0x005d3e08 | 207 | 4 | 7 | 0 | 0 | 14 | 2 |
| wo_03 | World -[displayOwnershipAreas] | 0x005d53b0 | 97 | 4 | 1 | 3 | 1 | 4 | 2 |
| wo_04 | World -[signOwnershipPlayerListRecievedFromServer:] | 0x005d3538 | 37 | 2 | 1 | 1 | 0 | 2 | 0 |
| wo_05 | World -[ownershipSignUIDisplayed] | 0x005daa14 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wo_06 | World -[tileIsLitForClient:atPos:tile:] | 0x005c88b0 | 286 | 4 | 1 | 3 | 0 | 10 | 18 |

## The ownership-sign write path (wo_00 / wo_01 / wo_02)

`ownershipSignWasPlacedOrChangedAtPos:...:wasRemoved:` (373w) is the event
entry: it applies `updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:...`
locally and then ships the change - dictionary + numberWithInt:/numberWithBool:
packet, gzipDeflate, dataWithBytes:length:, sendNetworkData:toPeers:reliable:
(helper **0x55468c — fifth appearance**, constant 0x3d = 61).
`updateLocalOwnershipSignsDueToSignPlacedOrChangedAtPos:...` (527w) is the
writer: macroPosForWorldPos resolution, per-cell reads/writes into the
**ownershipSignPositions** dictionary (numberWithInt: keys, stringWithFormat:
owner strings, per-cell NSMutableArray lists with addObject:/
removeObjectForKey:/removeObjectAtIndex:) and the displayOwnershipAreas
refresh. `signOwnershipModificationRecievedFromServer:` (207w) is the
server-side intake (objectForKey:/boolValue/intValue, constant 0xf).

This is the writer side of the map that E110's
tileIsProtectedAtPos:againstClient: enumerates — the protection policy's data
source now has both directions in evidence.

## The overlay and the lit probe (wo_03 / wo_04 / wo_06)

displayOwnershipAreas (97w) rebuilds the overlay via
OwnershipAreaRenderer initWithWorld:cache: (ownershipAreaRenderer slot);
signOwnershipPlayerListRecievedFromServer: (37w) forwards the player list to
uiManager signOwnershipUI; ownershipSignUIDisplayed (15w) is the bare getter.
`tileIsLitForClient:atPos:tile:` (286w) is the per-client visibility probe:
macroTileAtWorldPostion + lightBlockIndex +
`loadLightBlockForClientLightBlockIndex:intoPhysicalBlock:` (the light-block
sync loader pair) with the worldWidthMacro wrap (__aeabi_idiv x2) - the check
the E107 zoom chain and E109's net core consult.

## Boundaries

- All seven bodies fully read (max 527w); no census members.
- The OwnershipAreaRenderer / uiManager contracts are asserted at the selector
  level; the renderer implementation is a separate class outside this batch.
- wo_05 listing trimmed at the next IMP; header keeps the extracted end.
