# DynamicObject base class (E116)

The DynamicObject base class closure: the ctor triad, the position updater, the removal-permission check, the dirty-flag pairs and the base-class hook stubs. 66 bodies, 2523 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| dob_00 | DynamicObject -[initDerivedStuff:loadPhysicalBlockIfNeeded:] | 0x00839508 | 242 | 7 | 1 | 4 | 0 | 9 | 10 |
| dob_01 | DynamicObject -[removeFromMacroBlock] | 0x008398d0 | 75 | 4 | 1 | 3 | 0 | 4 | 2 |
| dob_02 | DynamicObject -[initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:] | 0x00839a18 | 56 | 1 | 0 | 0 | 0 | 1 | 2 |
| dob_03 | DynamicObject -[initWithWorld:dynamicWorld:atPosition:cache:] | 0x00839af8 | 289 | 4 | 2 | 6 | 1 | 8 | 10 |
| dob_04 | DynamicObject -[initWithWorld:dynamicWorld:cache:netData:] | 0x0083a3c0 | 224 | 6 | 2 | 7 | 1 | 8 | 6 |
| dob_05 | DynamicObject -[dealloc] | 0x0083a740 | 27 | 1 | 1 | 0 | 1 | 1 | 0 |
| dob_06 | DynamicObject -[dynamicObjectNetData] | 0x0083aabc | 89 | 1 | 0 | 4 | 0 | 1 | 2 |
| dob_07 | DynamicObject -[update:accurateDT:isSimulation:] | 0x0083ac20 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_08 | DynamicObject -[updatePosition:] | 0x0083ae78 | 439 | 11 | 2 | 6 | 0 | 20 | 21 |
| dob_09 | DynamicObject -[requiresPhysicalBlock] | 0x0083b554 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_10 | DynamicObject -[worldChanged:] | 0x0083b570 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_11 | DynamicObject -[shouldSaveEveryChangeInPosition] | 0x0083b588 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_12 | DynamicObject -[worldContentsChanged:] | 0x0083b5a4 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| dob_13 | DynamicObject -[waterContentChanged:] | 0x0083b5f8 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| dob_14 | DynamicObject -[creationNetDataForClient:] | 0x0083b64c | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_15 | DynamicObject -[updateNetDataForClient:] | 0x0083b66c | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_16 | DynamicObject -[remoteUpdate:] | 0x0083b68c | 73 | 3 | 1 | 3 | 0 | 3 | 1 |
| dob_17 | DynamicObject -[remoteCreationDataUpdate:] | 0x0083b7b0 | 73 | 3 | 1 | 3 | 0 | 3 | 1 |
| dob_18 | DynamicObject -[shouldAddToMacroBlock] | 0x0083b8d4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_19 | DynamicObject -[setFloatPosAndUpdatePosition:] | 0x0083b8f0 | 53 | 1 | 0 | 1 | 0 | 4 | 0 |
| dob_20 | DynamicObject -[staticGeometryDrawCubeCount] | 0x0083b9c4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_21 | DynamicObject -[staticGeometryDrawCubeCountTrans] | 0x0083b9e0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_22 | DynamicObject -[addDrawCubeData:fromIndex:] | 0x0083b9fc | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_23 | DynamicObject -[addDrawCubeDataTrans:fromIndex:] | 0x0083ba20 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_24 | DynamicObject -[staticGeometryDrawQuadCountForMacroPos:] | 0x0083ba44 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_25 | DynamicObject -[staticGeometryForegroundDrawQuadCountForMacroPos:] | 0x0083ba68 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_26 | DynamicObject -[addDrawQuadData:fromIndex:forMacroPos:] | 0x0083ba8c | 14 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_27 | DynamicObject -[addForegroundDrawQuadData:fromIndex:forMacroPos:] | 0x0083bac4 | 14 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_28 | DynamicObject -[staticGeometryDrawItemQuadCount] | 0x0083bafc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_29 | DynamicObject -[addDrawItemQuadData:fromIndex:] | 0x0083bb18 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_30 | DynamicObject -[lightGlowQuadCount] | 0x0083bb3c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_31 | DynamicObject -[staticGeometryCylinderCount] | 0x0083bb58 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_32 | DynamicObject -[addCylinderData:fromIndex:] | 0x0083bb74 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_33 | DynamicObject -[staticGeometryCylinderCountTrans] | 0x0083bb98 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_34 | DynamicObject -[addCylinderDataTrans:fromIndex:] | 0x0083bbb4 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_35 | DynamicObject -[staticGeometryDodoEggCount] | 0x0083bbd8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_36 | DynamicObject -[addDodoEggDrawQuadData:fromIndex:] | 0x0083bbf4 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_37 | DynamicObject -[blockheadUnloaded:] | 0x0083c890 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_38 | DynamicObject -[blockheadsLoaded] | 0x0083c8a8 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_39 | DynamicObject -[isDownlight] | 0x0083c960 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_40 | DynamicObject -[isUplight] | 0x0083c97c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_41 | DynamicObject -[needsNetDataToBeSent] | 0x0083c9dc | 47 | 0 | 0 | 3 | 0 | 0 | 2 |
| dob_42 | DynamicObject -[occupiesForegroundContents] | 0x0083ca98 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_43 | DynamicObject -[occupiesNormalContents] | 0x0083cab4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_44 | DynamicObject -[occupiesBackgroundContents] | 0x0083cad0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_45 | DynamicObject -[ownerID] | 0x0083caec | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_46 | DynamicObject -[mayOnlyBeRemovedByOwner] | 0x0083cb28 | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_47 | DynamicObject -[canBeRemovedByBlockhead:] | 0x0083cb7c | 200 | 10 | 1 | 3 | 0 | 10 | 10 |
| dob_48 | DynamicObject -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:] | 0x0083ce9c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_49 | DynamicObject -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline] | 0x0083ceb8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_50 | DynamicObject -[renderPos] | 0x0083ced4 | 34 | 1 | 0 | 0 | 0 | 2 | 2 |
| dob_51 | DynamicObject -[freeblockCreationItemType] | 0x0083cf5c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_52 | DynamicObject -[freeBlockCreationSaveDict] | 0x0083cf78 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_53 | DynamicObject -[freeBlockCreationDataA] | 0x0083cf94 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_54 | DynamicObject -[freeBlockCreationDataB] | 0x0083cfb0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dob_55 | DynamicObject -[needsRemoved] | 0x0083d0f0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_56 | DynamicObject -[setNeedsRemoved:] | 0x0083d12c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_57 | DynamicObject -[updateNeedsToBeSent] | 0x0083d170 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_58 | DynamicObject -[setUpdateNeedsToBeSent:] | 0x0083d1ac | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_59 | DynamicObject -[creationDataNeedsToBeSent] | 0x0083d1f0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_60 | DynamicObject -[setCreationDataNeedsToBeSent:] | 0x0083d22c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_61 | DynamicObject -[unreliableUpdateNeedsToBeSent] | 0x0083d270 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_62 | DynamicObject -[setUnreliableUpdateNeedsToBeSent:] | 0x0083d2ac | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_63 | DynamicObject -[isNet] | 0x0083d2f0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_64 | DynamicObject -[macroTileOwner] | 0x0083d32c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| dob_65 | DynamicObject -[.cxx_construct] | 0x0083d370 | 72 | 0 | 0 | 1 | 0 | 3 | 0 |

## What this batch closes

The DynamicObject base class - **66/66 refs-covered with this batch** - the
archetype every dynamic object (Workbench, Torch, SteamTrain, the plants, the
animals) specializes:

- The **ctor triad**: the plain ctor (289w - getNextDynamicObjectID uniqueID,
  floatPos/pos seeding, worldWidthMacro wrap), the save-ctor forwarder (56w)
  and the **net ctor** (224w - isNet flag + getBytes:length: decode) - all
  ending in initDerivedStuff:loadPhysicalBlockIfNeeded:, which attaches the
  object to its macro tile through the E113 loader
  (loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:).
- **updatePosition:** (439w) - the macro-tile migration: wrap + add/remove
  behind shouldAddToMacroBlock, setNeedsRemoved: when leaving and the
  shouldSaveEveryChangeInPosition dirty path.
- **canBeRemovedByBlockhead:** (200w) - the removal permission check (isNet /
  isAdmin / isClientBlockheadBeingControlledByServer + playerIsAdminWithID:/
  clientID/server + mayOnlyBeRemovedByOwner) - the sibling of the World
  protection policy (E110).
- The dirty-flag pairs (needsRemoved / updateNeedsToBeSent /
  creationDataNeedsToBeSent / unreliableUpdateNeedsToBeSent + isNet +
  macroTileOwner), the needsNetDataToBeSent fold (47w) and ownerID (15w).
- The net forwarders (remoteUpdate:/remoteCreationDataUpdate: 73w each,
  isServer-gated) and dynamicObjectNetData (89w).
- The **base-class hook stubs** (the long tail, 5-22w each): requiresPhysicalBlock,
  worldChanged:, shouldSaveEveryChangeInPosition, creationNetDataForClient:,
  updateNetDataForClient:, the draw-count accessors and addDraw*/addCylinder*/
  addDodoEgg* geometry hooks, occupies*Contents, isDownlight/isUplight,
  freeBlockCreation* item hooks, blockheadUnloaded:/blockheadsLoaded,
  clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline (original
  spelling), addArtificialLightContributionForPhysicalBlockLoadedAtXPos:...
- **.cxx_construct** (72w, real bound; the 4096w in scans was a gap artifact):
  Vector2 ctor + **cosf + sinf** - the rotation basis, the same pattern as
  DonkeyLike's constructor (E97).

## Boundaries

- All 66 bodies read in full (max 439w); the sub-22w hooks carry
  stub-template semantics (default-return override points).
- The concrete subclass overrides are covered by their own batches
  (Workbench E75-E84, Torch E72, plants E85-E95, animals E96-E98).
