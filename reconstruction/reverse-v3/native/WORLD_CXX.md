# World internals pair (E113)

The World internals pair: the compiler-generated C++ member constructor (the member-layout oracle) and the physical-block streaming loader. 2 bodies, 1346 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wc_00 | World -[.cxx_construct] | 0x005dab64 | 324 | 0 | 0 | 12 | 0 | 10 | 0 |
| wc_01 | World -[loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:] | 0x005b4a00 | 1022 | 6 | 4 | 7 | 2 | 36 | 45 |

## The C++ member constructor (wc_00)

`.cxx_construct` (324w) is the compiler-generated member initializer: it
constructs exactly **Vector2 x6 + Vector x3 + one std::__1::__tree<int,
unsigned char> (std::map<int, uint8>)** through the ivar-offset slots recorded
in the artifact (lastPinchPanTranslation / touchStartTranslation /
translationGoal / accurateTranslation / roundedTranslation / dayColor /
sunDirection / latestMapData / freePhysicalBlocks / usedPhysicalBlocks /
longTermAveragedAcceleration / lastDistanceTravelledThisDPadMovement). Note
the real exidx bound is 324w - the 4096w figure that circulated in earlier
scans was a next-IMP gap artifact (the skill's tsv-gap warning).

## The physical-block streaming loader (wc_01)

`loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:`
(1022w) is the loader that feeds the block registry E110's decommission pass
prunes: **macroTileAtMacroPostion x16** walks the surrounding macro tiles,
each block goes through `loadPhysicalBlock:atXPos:yPos:createIfNotCreated:`,
lights are booked with
`addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:`, and the
client-side miss path calls `requestBlockFromServerAtPos:createIfNotCreated:`
through clientTileLoader. Bookkeeping: free/usedPhysicalBlocks hash-table
insert x2 + erase (via __wrap_calloc x2), makeIntpair, constants
0xc0/0x400/0x40, an NSException raise:format: error path and NSLog; 45 branches
carry the surrounding/recursion logic.

## Boundaries

- Both bodies read in full (324w / 1022w); no census-only members.
- The std::container constructors are asserted at the symbol level; the
  member types beyond the ctor calls are not re-derived.
- The ServerClient.timeSinceLastHeartbeatRequest slot appears among the
  ctor-touched offsets; its role is recorded as-is (cross-class cell), not
  interpreted here.
