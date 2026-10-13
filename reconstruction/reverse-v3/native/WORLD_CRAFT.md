# World craft-interaction chain (E105)

The World-side workbench interaction completion chain: the craft-completion and warp-in giants (census-grade), the craft/configure router and the dynamic-object tap family. 10 bodies, 5444 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| cb_00 | World -[warpInBlockhead:atWorkbench:withBlockhead:] | 0x005bbdd0 | 1583 | 37 | 14 | 6 | 6 | 91 | 65 |
| cb_01 | World -[craftItemFinished:atWorkbench:allFinished:blockhead:] | 0x005b6fa8 | 1218 | 28 | 12 | 7 | 2 | 61 | 64 |
| cb_02 | World -[craftOrConfigureItem:atWorkbench:withBlockhead:count:] | 0x005b88f8 | 461 | 10 | 1 | 2 | 0 | 33 | 29 |
| cb_03 | World -[craftItem:atWorkbench:withBlockhead:count:] | 0x005b83d0 | 330 | 9 | 1 | 4 | 0 | 20 | 11 |
| cb_04 | World -[craftAbortedForWorkbench:withBlockhead:] | 0x005b82b0 | 72 | 3 | 1 | 2 | 0 | 3 | 2 |
| cb_05 | World -[teleportToWorkbench:withBlockhead:craftableItemObject:] | 0x005bb634 | 487 | 14 | 4 | 2 | 2 | 31 | 12 |
| cb_06 | World -[useDynamicObjectTappedAtDynamicObject:selectedOption:] | 0x005b9368 | 682 | 10 | 1 | 2 | 5 | 43 | 27 |
| cb_07 | World -[removeDynamicObjectTappedAtDynamicObject:withBlockhead:] | 0x005bd68c | 290 | 7 | 1 | 2 | 5 | 16 | 15 |
| cb_08 | World -[addFuelTappedAtInteractionObject:withBlockhead:] | 0x005bdb14 | 151 | 7 | 2 | 2 | 1 | 9 | 4 |
| cb_09 | World -[blockheadReachedInteractionObjectDestination:pathExtraData:] | 0x005b90c0 | 170 | 9 | 2 | 2 | 0 | 9 | 7 |

## The craft-completion and warp-in giants

`warpInBlockhead:atWorkbench:withBlockhead:` (1583w) is the warp-in-a-new-blockhead
flow at a workbench: 37 selector cells covering the unique-ID request
(`requestUniqueIDFromServerWithDict:`), the blockhead spawn
(`createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:
hovers:playSound:priorityBlockhead:` + `loadNewBlockheadAtPos:craftableItemObject:
uniqueID:` + `setActiveBlockhead:dontFollow:`), the store payment cluster
(`CrystalManager` instance + amount/amountString/setCountWatcher:), the product
strings (`stringWithFormat:`/`stringFromMD5`/`isEqualToString:`) and the
achievement/ads/UI tail (reportAchievementWithIdentifier:,
selectBlockheadButtonAtIndex:, displayInterstitialForTag:). The load-bearing
constant 0xc350 (50000) is the same per-object ceiling seen in the E103
unique-ID grant; 0x7c appears as well.

`craftItemFinished:atWorkbench:allFinished:blockhead:` (1218w) is the
craft-completion handler: it upgrades the workbench (upgradeToNextLevel),
re-arms it (setWorkbench:blockhead:), records (addExpectedCraftItem:,
freeBlockCreationItemSaveDict), spawns (createFreeBlockAtPosition:), runs the
same new-blockhead family (unique-ID request + spawn + setActiveBlockhead:)
and updates the progress UI (craftProgressUI setDisplayed:). Both giants are
census-grade: per-instruction walkthroughs are not claimed.

## The craft/configure router and the tap family

craftOrConfigureItem:atWorkbench:withBlockhead:count: (461w) is the tap
router: `itemTypeIsPainting` + `itemTypeCanBeColored` pick the paint path,
`showTimeCrystalUITapped` the store path, and the workbenchChoiceUI / craftUI /
paintMixUI `setDisplayed:` calls flip the option panels. craftItem:atWorkbench:
withBlockhead:count: (330w) then queues the blockhead walk
(queueActionWithGoalPos:...) behind the interaction-type and protection gates;
craftAbortedForWorkbench:withBlockhead: (72w) is the abort cleanup.

useDynamicObjectTappedAtDynamicObject:selectedOption: (682w) is the
dynamic-object tap router: Workbench / InteractionObject / Boat / TrainCar /
NPC arms, each building the queueAction record behind the protection gates,
with showUIForTappedWorkbench: (the workbench UI) on the Workbench arm.
removeDynamicObjectTappedAtDynamicObject:withBlockhead: (290w) is its
remove-flow sibling (NPC / Boat / TrainCar / Sign / Painting chain),
addFuelTappedAtInteractionObject:withBlockhead: (151w) the fuel-tap flow with
a Workbench class gate (NSLog miss path), and
blockheadReachedInteractionObjectDestination:pathExtraData: (170w) the
arrival handler deciding between startInteractionWithBlockhead:,
showUIForActiveBlockheadReachingInteractionObject: and stopInteracting.

teleportToWorkbench:withBlockhead:craftableItemObject: (487w) is the store
teleport flow: CrystalManager amount/amountString product strings,
teleportBlockhead:toWorkbench:, setCountWatcher:, worldUI
modify:modifyString: and displayInterstitialForTag:.

## Boundaries

- cb_00 and cb_01 are census-grade (call histogram + selector/ivar/class
  tables + constants); the per-branch logic inside them is not claimed
  instruction by instruction.
- The CrystalManager / Workbench / blockhead message contracts are asserted at
  the selector level (forwarding calls); their implementations live in other
  classes and are outside this batch.
- The store strings (stringWithFormat:/stringFromMD5) are recorded as cells;
  the product-ID string literals are constants inside tap-family bodies of
  other batches and are not re-derived here.
