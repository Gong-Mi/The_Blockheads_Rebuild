# World store, repair and idle-timer line (E110)

The World store/repair/idle line: the time-crystal button and repair engine, the tile-protection policy, the double-time prompt and the idle-timer keeper. 14 bodies, 2645 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wu_00 | World -[timeCrystalButtonTapped] | 0x005b5b54 | 517 | 13 | 1 | 10 | 0 | 25 | 13 |
| wu_01 | World -[doRepairForTileAtPos:] | 0x005d8f78 | 489 | 8 | 0 | 3 | 1 | 24 | 42 |
| wu_02 | World -[tileIsProtectedAtPos:againstClient:] | 0x005d4718 | 764 | 7 | 7 | 5 | 1 | 28 | 59 |
| wu_03 | World -[showDoubleTimePromptIfGoodTime] | 0x005c6898 | 390 | 14 | 1 | 5 | 1 | 23 | 19 |
| wu_04 | World -[updateIdleTimerDisabled] | 0x005bde9c | 268 | 7 | 1 | 6 | 1 | 10 | 16 |
| wu_05 | World -[doubleTimeRestoreTapped] | 0x005c28e4 | 49 | 3 | 1 | 0 | 1 | 3 | 0 |
| wu_06 | World -[tileIsProtectedAtPos:againstBlockhead:] | 0x005d5308 | 42 | 2 | 0 | 0 | 0 | 2 | 0 |
| wu_07 | World -[setRepairMode:] | 0x005d971c | 26 | 0 | 0 | 2 | 0 | 0 | 0 |
| wu_08 | World -[timeCrystalCloseButtonTapped] | 0x005d790c | 25 | 1 | 1 | 1 | 0 | 1 | 0 |
| wu_09 | World -[resetPauseIdleTimer] | 0x005ac350 | 20 | 0 | 0 | 1 | 0 | 0 | 0 |
| wu_10 | World -[startCloudTopup] | 0x005d3260 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| wu_11 | World -[doubleTimeUnlocked] | 0x005d9e8c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wu_12 | World -[repairMode] | 0x005d9784 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wu_13 | World -[cloudTopupFailed:] | 0x005d3248 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |

## The time-crystal and repair pair (wu_00 / wu_01)

`timeCrystalButtonTapped` (517w) is the store entry point: it counts the
blockheads, gates on requiresMotionEvents/activeBlockhead, looks up the active
workbench, centers the camera on it (Vector2 operator float* x6 over the
translationGoal/pinchScale/accurateTranslation fields with __aeabi_idiv x2)
and opens the UI (craftUI workbenchTapped:hasCancel:, setSelectedIndex:,
showTimeCrystalUITapped). `doRepairForTileAtPos:` (489w) is the repair engine:
five tile probes behind tileIsWater x4 /
**tileIsNotUnminedBlockSoCanBeRemovedOnRepair** / **backWallRemovesWithRepairTool** /
tileIsAir / tileIsSolid, then WorldHelper
placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:
placedByClientName:, surface reload (loadSnowSurfaceBlockAtPos:/
loadSurfaceBlockAtPos:), relight (updateSunLightForTile:atPos:world:) and the
worldChangedAtPos:sendReliably: broadcast; tile-code constants
0x2f/0x19/0x21-0x25.

## The protection policy (wu_02 / wu_06)

`tileIsProtectedAtPos:againstClient:` (764w) is the largest body: admin check
(playerIsAdminWithID:), customRules read, then the ownershipSignPositions
enumeration - per-sign stringWithFormat:/safeCaseInsensitiveCompare:/intValue
against the client's identity - resolving the macro pos via makeIntpair +
macroPosForWorldPos + worldWidthMacro. The blockhead variant (42w) forwards
with localNetID. This is the gate the E104/E105 interaction flows keep calling.

## Store, prompts and idle timer (wu_03 / wu_04 / wu_05 / wu_10 / wu_13)

`showDoubleTimePromptIfGoodTime` (390w) gates on every UI surface before
showing the double-time prompt (helper 0x564c54, TipManager);
`doubleTimeRestoreTapped` (49w) calls SKPaymentQueue restoreCompletedTransactions
+ iapStarted; startCloudTopup (19w)/cloudTopupFailed: (6w) are the cloud
top-up stubs. `updateIdleTimerDisabled` (268w) keeps the screen awake:
UIApplication setIdleTimerDisabled: gated on gameBlockingUIDisplayed and the
blockheads/serverClients enumeration. setRepairMode:/repairMode (26w/15w),
timeCrystalCloseButtonTapped (25w), resetPauseIdleTimer (20w) and
doubleTimeUnlocked (15w) close the line.

## Boundaries

- All fourteen bodies fully read (max 764w); no census members.
- The StoreKit / UIApplication contracts are asserted at the selector level;
  the IAP server flow is outside this batch (E108 covered purchaseDoubleTime).
- wu_08 listing trimmed at the next IMP; header keeps the extracted end.
