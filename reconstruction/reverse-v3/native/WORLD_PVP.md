# World PVP, projectile and tips line (E112)

The World PVP/projectile/tips line: the damage wire pair, the projectile fire/request pair, the PVP toggle and the shared tip notification channel. 11 bodies, 1782 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wp_00 | World -[remoteBlockheadDamageRequest:requestedByClientName:] | 0x005c9b54 | 321 | 10 | 2 | 3 | 0 | 14 | 15 |
| wp_01 | World -[sendAndDisplayAirTimeTipWithDistance:] | 0x005cb08c | 305 | 9 | 4 | 2 | 3 | 12 | 7 |
| wp_02 | World -[setPVPEnabled:displayNotifciation:] | 0x005cb550 | 248 | 7 | 3 | 3 | 2 | 8 | 9 |
| wp_03 | World -[sendDamage:forNetBlockhead:recoil:] | 0x005c97dc | 222 | 7 | 1 | 2 | 2 | 7 | 7 |
| wp_04 | World -[fireProjectileFrom:to:at:fireItemType:firer:] | 0x005c937c | 221 | 5 | 1 | 3 | 1 | 9 | 5 |
| wp_05 | World -[remoteTipNotification:] | 0x005cba90 | 104 | 7 | 0 | 0 | 2 | 9 | 0 |
| wp_06 | World -[sendSetPVPEnabledToServer:] | 0x005cb930 | 88 | 2 | 3 | 2 | 0 | 2 | 4 |
| wp_07 | World -[remoteProjectileRequest:] | 0x005c96f0 | 59 | 2 | 0 | 1 | 0 | 4 | 0 |
| wp_08 | World -[currentTipText] | 0x005c19b4 | 105 | 4 | 2 | 2 | 1 | 4 | 6 |
| wp_09 | World -[currentTipColor] | 0x005c1b58 | 94 | 3 | 1 | 0 | 1 | 6 | 4 |
| wp_10 | World -[pvpEnabled] | 0x005cf334 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |

## The damage and projectile pair (wp_00 / wp_03 / wp_04 / wp_07)

The combat wire format is a symmetric pair. Server side:
`remoteBlockheadDamageRequest:requestedByClientName:` (321w) decodes
getBytes:length:, walks allBlockheadsIncludingNet behind the uniqueID /
isSimulating / isClientBlockheadBeingControlledByServer gates and delivers
`sufferDamage:isSimulation:recoil:` (the blockhead-side method) with
playerNameForPlayerWithIDIncludingOldPlayers: resolution. Client/sender side:
`sendDamage:forNetBlockhead:recoil:` (222w) packs appendBytes:/dataWithBytes:
length: with uniqueID/clientID and routes via sendNetworkData:toPeers:reliable:
(server) or sendDataToServer:reliable: (client); constants 0x2a (42).
`fireProjectileFrom:to:at:fireItemType:firer:` (221w) reads the from/to/at
Vector2s (operator float* x4) into its packet (0x29 = 41) and
`remoteProjectileRequest:` (59w) is the intake that calls it after decoding
two Vector2s; projectileManager holds the fired set.

## The PVP toggle and the tip channel (wp_01 / wp_02 / wp_05 / wp_06 / wp_08 / wp_09)

`setPVPEnabled:displayNotifciation:` (248w) flips pvpEnabled, shows the
notification through TipManager displayTip:withTimeOut:displayEvenIfDisabled:
tipColor: (0xa/1.0f/0x2d) and broadcasts; `sendSetPVPEnabledToServer:` (88w)
is the client entry that also announces via sendChatMessage:sendToClients:.
The same tip channel carries air-time: sendAndDisplayAirTimeTipWithDistance:
(305w, local display + network relay, constants 0xa/1.0f/0x2d) and
remoteTipNotification: (104w, the receiver decoding via initWithBytes:length:
encoding: on a __wrap_malloc buffer). currentTipText (105w) and currentTipColor
(94w) read the TipManager state for the HUD; pvpEnabled (15w) is the getter.

## Boundaries

- All eleven bodies fully read (max 321w); no census members.
- The TipManager / blockhead sufferDamage: contracts are asserted at the
  selector level; their implementations live in other classes outside this
  batch.
- The wire layouts are recorded as cell tables; field-level decoding is not
  re-derived here.
