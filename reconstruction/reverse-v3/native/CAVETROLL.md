# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 49828 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| cw_00 | CaveTroll -[.cxx_construct] | 0x00d853c0 | 227 | 0 | 0 | 6 | 0 | 12 | 0 |
| cw_01 | CaveTroll -[addRider:] | 0x00d84ee8 | 64 | 1 | 1 | 2 | 1 | 2 | 1 |
| cw_02 | CaveTroll -[blockheadCanRide:usingItem:] | 0x00d850f4 | 58 | 1 | 1 | 2 | 0 | 1 | 2 |
| cw_03 | CaveTroll -[blockheadUnloaded:] | 0x00d846a8 | 117 | 2 | 2 | 4 | 1 | 3 | 2 |
| cw_04 | CaveTroll -[cameraPosForBlockhead:] | 0x00d84ccc | 35 | 1 | 0 | 0 | 0 | 2 | 2 |
| cw_05 | CaveTroll -[canBeCapturedByBlockhead:withItemType:] | 0x00d84898 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_06 | CaveTroll -[canCrawl] | 0x00d84080 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_07 | CaveTroll -[canFly] | 0x00d8487c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_08 | CaveTroll -[cantBeCapturedTipStringForBlockhead:withItemType:] | 0x00d848bc | 57 | 2 | 2 | 0 | 1 | 2 | 2 |
| cw_09 | CaveTroll -[captureRequiredItemType] | 0x00d52c24 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_10 | CaveTroll -[caveTrollUpdateDataForClient:] | 0x00d54378 | 163 | 1 | 0 | 8 | 0 | 3 | 2 |
| cw_11 | CaveTroll -[controlIsLocal] | 0x00d56338 | 74 | 1 | 1 | 2 | 0 | 1 | 3 |
| cw_12 | CaveTroll -[creationDataStructSize] | 0x00d54908 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_13 | CaveTroll -[creationNetDataForClient:] | 0x00d54604 | 134 | 4 | 1 | 0 | 1 | 8 | 4 |
| cw_14 | CaveTroll -[crouching] | 0x00d83ae0 | 34 | 0 | 0 | 1 | 0 | 0 | 1 |
| cw_15 | CaveTroll -[currentAnimationType] | 0x00d52ae4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_16 | CaveTroll -[currentInteractionType] | 0x00d55038 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_17 | CaveTroll -[currentTraverseToKeyFrame] | 0x00d552b8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_18 | CaveTroll -[dealloc] | 0x00d54e2c | 131 | 2 | 2 | 7 | 1 | 8 | 0 |
| cw_19 | CaveTroll -[die:] | 0x00d56190 | 106 | 4 | 2 | 3 | 2 | 4 | 2 |
| cw_20 | CaveTroll -[diesOfLowFullness] | 0x00d52b70 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_21 | CaveTroll -[diesOfOldAge] | 0x00d52b54 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_22 | CaveTroll -[doRemoteUpdate:] | 0x00d55720 | 299 | 0 | 0 | 16 | 0 | 4 | 3 |
| cw_23 | CaveTroll -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00d7e358 | 4333 | 12 | 2 | 24 | 0 | 153 | 13 |
| cw_24 | CaveTroll -[falling] | 0x00d83b68 | 47 | 1 | 1 | 2 | 0 | 1 | 1 |
| cw_25 | CaveTroll -[foodItemType] | 0x00d52bbc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_26 | CaveTroll -[getNamesArray] | 0x00d52bd8 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_27 | CaveTroll -[getNamesArrayCount] | 0x00d52c08 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_28 | CaveTroll -[hitWithForce:blockhead:] | 0x00d842ac | 255 | 6 | 3 | 8 | 1 | 11 | 15 |
| cw_29 | CaveTroll -[infoForPathRecalculation] | 0x00d83320 | 436 | 3 | 6 | 5 | 2 | 24 | 7 |
| cw_30 | CaveTroll -[initSubDerivedStuffStuff] | 0x00d52c40 | 611 | 8 | 21 | 12 | 3 | 24 | 1 |
| cw_31 | CaveTroll -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] | 0x00d535f8 | 181 | 2 | 1 | 8 | 1 | 3 | 2 |
| cw_32 | CaveTroll -[initWithWorld:dynamicWorld:cache:netData:] | 0x00d53f2c | 275 | 4 | 2 | 14 | 1 | 5 | 6 |
| cw_33 | CaveTroll -[isHeadingForSquare:] | 0x00d55074 | 145 | 4 | 2 | 3 | 0 | 5 | 8 |
| cw_34 | CaveTroll -[jumpsOnSwipe] | 0x00d851dc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_35 | CaveTroll -[maxAge] | 0x00d52b20 | 13 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_36 | CaveTroll -[maxHealth] | 0x00d83c24 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_37 | CaveTroll -[namePos] | 0x00d849a0 | 43 | 1 | 0 | 0 | 0 | 4 | 2 |
| cw_38 | CaveTroll -[nextPos] | 0x00d85268 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| cw_39 | CaveTroll -[npcType] | 0x00d535dc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_40 | CaveTroll -[pathNeedsRecalculated] | 0x00d852c8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_41 | CaveTroll -[preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00d5f4b8 | 30803 | 11 | 2 | 95 | 4 | 466 | 494 |
| cw_42 | CaveTroll -[reactToBeingFed] | 0x00d84a4c | 136 | 4 | 3 | 3 | 2 | 7 | 0 |
| cw_43 | CaveTroll -[reactToBeingHit] | 0x00d84118 | 101 | 3 | 1 | 5 | 1 | 4 | 1 |
| cw_44 | CaveTroll -[remoteCreationDataUpdate:] | 0x00d55ef4 | 129 | 3 | 1 | 0 | 1 | 3 | 0 |
| cw_45 | CaveTroll -[remoteUpdate:] | 0x00d55bcc | 202 | 5 | 2 | 4 | 1 | 5 | 6 |
| cw_46 | CaveTroll -[removeRider:] | 0x00d84fe8 | 67 | 1 | 1 | 2 | 1 | 2 | 1 |
| cw_47 | CaveTroll -[renderPos] | 0x00d8409c | 31 | 0 | 0 | 1 | 0 | 2 | 0 |
| cw_48 | CaveTroll -[rideDirection] | 0x00d84df0 | 62 | 0 | 0 | 2 | 0 | 2 | 4 |
| cw_49 | CaveTroll -[riderBodyYRotationForBlockhead:] | 0x00d84d58 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_50 | CaveTroll -[riderDPadShouldAllowUpDown] | 0x00d85214 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_51 | CaveTroll -[riderDPadShouldGiveDiscreteValues] | 0x00d8524c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_52 | CaveTroll -[riderPosForBlockhead:] | 0x00d84c6c | 24 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_53 | CaveTroll -[riderRidesWithArmsDown] | 0x00d851f8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_54 | CaveTroll -[selectedToolIndex] | 0x00d85348 | 14 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_55 | CaveTroll -[setNoLongerWaitingForPath] | 0x00d83a64 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_56 | CaveTroll -[setPath:type:goalInteraction:extraData:] | 0x00d82ccc | 393 | 9 | 2 | 11 | 0 | 13 | 20 |
| cw_57 | CaveTroll -[setPathNeedsRecalculated:] | 0x00d85304 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_58 | CaveTroll -[setSelectedToolIndex:] | 0x00d85380 | 16 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_59 | CaveTroll -[setTargetVelocity:] | 0x00d84d9c | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_60 | CaveTroll -[setWaitingForPathToPos:] | 0x00d839f0 | 29 | 0 | 0 | 2 | 0 | 0 | 0 |
| cw_61 | CaveTroll -[speciesName] | 0x00d52b8c | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| cw_62 | CaveTroll -[startInteractingWithTileAtIndex:tile:interactionType:] | 0x00d552f4 | 137 | 4 | 1 | 6 | 1 | 5 | 1 |
| cw_63 | CaveTroll -[stopInteracting] | 0x00d55518 | 130 | 3 | 1 | 7 | 0 | 3 | 1 |
| cw_64 | CaveTroll -[tapIsWithinBodyRadius:] | 0x00d83c40 | 272 | 1 | 0 | 3 | 0 | 20 | 11 |
| cw_65 | CaveTroll -[tileIsLitForSelf:atPos:] | 0x00d56160 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_66 | CaveTroll -[update:accurateDT:isSimulation:] | 0x00d56460 | 9034 | 60 | 19 | 105 | 4 | 250 | 581 |
| cw_67 | CaveTroll -[updateGatherSpeedAndAnimationForCurrentInterationAndItem] | 0x00d560f8 | 26 | 0 | 0 | 1 | 0 | 0 | 1 |
| cw_68 | CaveTroll -[updateNetDataForClient:] | 0x00d5481c | 59 | 2 | 1 | 0 | 1 | 3 | 2 |
| cw_69 | CaveTroll -[waitingForPath] | 0x00d83aa4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| cw_70 | CaveTroll -[worldChanged:] | 0x00d832f0 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| cw_71 | CaveTroll -[worldContentsChanged:] | 0x00d83308 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |

## Findings (E129)

**Batch: CaveTroll, 72 bodies / 49,828 words** (listings cw_00..cw_71, all class
CaveTroll). CaveTroll is the hostile animal NPC of the Donkey/Yak family
(NPC -> DynamicObject base; npcType = 6). Three census-tier bodies carry 88.6% of
the batch (44,170 of 49,828 words): `cw_41 preDrawUpdate:...` (30,803w), `cw_66 update:accurateDT:isSimulation:`
(9,034w) and `cw_23 draw:...` (4,333w); `cw_30 initSubDerivedStuffStuff` (611w),
`cw_29 infoForPathRecalculation` (436w) and `cw_56 setPath:type:goalInteraction:extraData:`
(393w) are census-lite.

- **The class ivar map is now fully pinned** (ELF class_metadata,
  `OBJC_IVAR_$_CaveTroll.*`): `state` struct @208 = {interacting c@0,
  interactionType i@4, goalInteractionTypeWhileWalking i@8, interactingSquare
  {x,y}@12, interactionTimer f@20, drownFraction f@24, animationType i@28,
  subAnimationType i@32}; 4 Cube/Texture pairs (head@252/256, body@260/264,
  arms@268/272, legs@276/280) + shader@244 / renderShader@248; walk/pose floats
  (walkTimer@284, bodyRotation@288, bodyZRotation@292, bodyTwistRotation@296,
  headXRotation@300, headYRotation@304); the traverse system (path@308,
  travelSpeed@312, traverseType@316, traverseFrom/ToKeyFrame@320/324,
  terrainDifficulty@328, fromSquare@332/toSquare@340/finalGoalSquare@348/
  defendSquare@356, returnToDefense@364, cannotReturn@365, fromTile@368,
  toTile@372, lastPathWasFalling@376, interactingTile@380, tappedNPC@384,
  chasingNPC@388, lastKnownNPCPosition@392, travelFraction@400(+Normalized@404),
  pathNeedsRecalculated@408, pathRecalculationIsFallPath@409, idleTimer@412,
  randomIdleWait@416, randomAnimationValueA/B/C@420/424/428); the six
  _GLKMatrix4 part matrices (mbody@432, mhead@496, mleftArm@560, mrightArm@624,
  mleftLeg@688, mrightLeg@752); light colors (lightColor@816, daylightColor@832,
  artificialLightColor@848); waitingForPath@864 + waitingPathGoalPos@868,
  footstepPingPong@876, renderPos@880, pathExtraData@888, recoilTimer@892,
  recoilDirection@896, prevGoalRotationType@900, randomAIWait@904,
  waitingBeforeRetaliationBlockhead@908, wasLit@912, riderTargetVelocity@916,
  riderPosition@924, currentMovementWasInitiatedByRider@940,
  currentNetQueueSize@944; the 4-deep action queues (nextToSquare[4]@948,
  nextTerrainDifficulty[4]@980, nextTraverseType[4]@996,
  nextTraverseToKeyFrame[4]@1012, nextInteracting[4]@1028,
  nextInteractionSquare[4]@1032, nextInteractionType[4]@1064,
  nextAnimationType[4]@1080, nextSubAnimationType[4]@1096); hasHadRemoteUpdate
  @1112, noRemoteActionTimer@1116, _selectedToolIndex@1120.

- **The master tick** `update:accurateDT:isSimulation:` (cw_66): 580 branches /
  194 calls / sinf x27 / __wrap_powf x2 / linearInterpolate x4 / __aeabi_idiv x14;
  it drives the audited movement chain (`checkCanEnterTile` with the full
  PathUserDynamicObject signature x1, `dpadFindPath` x1,
  `tileAtWorldPositionLoaded` x9, `worldWidthMacro` wrap x28, tileIsWater x3 /
  tileIsSolid x2), the state machine (state struct ~102 accesses), the 4-deep
  next* queues, traverse keyframe state, footstep sounds ('snowStep.wav',
  'punch.wav', 'troll.wav' with setPitch:/setVolume:/playAtPosition:), particles
  (addParticleAtPos:velocity:color:gravityType:life:scale:), door interaction
  (setDoorAtPos:toOpen:direction:), feeding (checkCurrentPositionForFood),
  damage/death (sufferDamage:isSimulation:recoil:, hitWithForce:blockhead: x2,
  die: x2, maxHealth x3), the retaliation clock
  (waitingBeforeRetaliationBlockhead@908 x9, randomAIWait@904), rider control
  (rider x13, riderTargetVelocity) and net sync (isNet, updateNeedsToBeSent,
  currentNetQueueSize). 0x1869f (99999) full-age sentinel present.

- **Attack/retaliation contract** (cw_28 `hitWithForce:blockhead:`): forwards to
  super first, early-outs (dead, force<=0, nil blockhead, isNet, already chasing
  the tapped NPC), then arms retaliation gated by the World customRules struct
  (skip only when byte0 != 0 && byte0x17 == 3): releases/stores
  waitingBeforeRetaliationBlockhead, randomAIWait = 0.2 + 0.6*rand01 (RNG helper
  0xd535cc / 2^31), stopInteracting, setPath:nil type:2 goal:0, waitingForPath=0.
  Also `reactToBeingHit` (recoilTimer=5.0f, recoilDirection=rand01,
  'trollOuch.wav') and `reactToBeingFed` ('crunch.wav' + 'troll.wav',
  currentNetQueueSize=0).

- **Animation engine** (cw_41, census): sinf x98 + atan2f + fmodf x6 + powf x2 +
  61 memcpy matrix block copies; walk cycle = walkTimer/travelFractionNormalized/
  traverse keyframes into the six part matrices; recoil (recoilTimer/recoilDirection),
  light colors from world daylight, renderPos interpolation fromSquare->toSquare;
  fused local subroutines (0xd7d860 x111, 0xd7d678 x23, 0xd7dbf8 x17) + sound
  ('trollFound.wav', 'splash.wav') and dayColorForPosition: handles.

- **Render** (cw_23, census): per-part draw with 12x glUniformMatrix4fv,
  9x glActiveTexture (GL_TEXTURE0/1 = 0x84c0/0x84c1) + 9x glBindTexture
  (GL_TEXTURE_2D = 0xde1), shader 'program' + uniformLocations dictionary
  (objectAtIndex:/intValue x5), glUniform4f x3 / 3f / 1f / 1i x2, NPC.visible
  gate. Scene setup (cw_30) builds the 4 'DrawCube's from '%@head_ct.png' /
  '%@body_ct.png' / '%@arms_ct.png' / '%@legs_ct.png' + 'ShadedWorldObjectMultiTexture'
  shader (uniforms mvp_matrix/normal_matrix/texture/textureB/daylight/
  artificalLight [sic]/lightPosition/reflectivity/artificialLightDirection);
  randomIdleWait = 5.0 + rand01.

- **Pathfinder / queues**: cw_24 falling = (path count != 0) && traverseType ==
  0x11; cw_33 isHeadingForSquare: compares finalGoalSquare or the world pos of
  path[0]'s "index"; cw_29 infoForPathRecalculation builds
  {pathUser,pathType,goalInteraction,goalX,goalY} (chasingNPC -> pathType 3 /
  goalInteraction 10 / lastKnownNPCPosition; returnToDefense -> pathType 1 /
  goalInteraction 0 / defendSquare; else pathType 5 / defendSquare; guarded by
  pathNeedsRecalculated); cw_56 setPath:... = release/retain transaction +
  mutableCopy + flags (pathNeedsRecalculated=0, cannotReturn, lastPathWasFalling
  = (type==5), goalInteractionTypeWhileWalking = (type==1 ? 0 : arg)) + queue
  setup; cw_10/cw_22/cw_32/cw_44/cw_45/cw_68 carry the net record round trip.

- **Net records pinned**: creationDataStructSize = 0x88 = npcCreationNetDataForClient:
  (0x48) ++ caveTrollUpdateDataForClient: (0x40, warpacked: NPCUpdateNetData 0x18,
  fromSquare/toSquare/interactingSquare as 6 ints, traverseType/From/ToKeyFrame,
  dead, terrainDifficulty (strh), interacting/interactionType/animationType/
  subAnimationType bytes); remoteCreationDataUpdate: slices offset 0x48 and calls
  doRemoteUpdate:; remoteUpdate: reads via getBytes:length:0x40 and applies it
  (dead path: travelFraction < 1.0 && !dynamicWorld.isClient -> needsRemoved=0);
  updateNetDataForClient: wraps the 0x40 struct as NSData.

- **Capture / ride surface**: canBeCaptured = NO; captureRequiredItemType =
  0x12e (302); cantBeCapturedTipString = "YOU DIDN'T SERIOUSLY THINK
YOU COULD
  CAGE A %@?!" when itemType == 302; speciesName = 'CAVE TROLL'; maxAge = 86400.0f
  (1 day); maxHealth = 256; foodItemType = 0xa7 (167); getNamesArray -> 'Trollface'
  table, count = 35. Ridden-troll DPad: allow up/down YES, discrete YES, arms
  down NO; rideDirection = sign(riderTargetVelocity.x, +/-0.2 deadband); addRider/
  removeRider/blockheadUnloaded clear or zero riderTargetVelocity.

- **Temperature/fire note (per E124 cross-check)**: no temperature or fire logic
  appears anywhere in this batch's own bodies - CaveTroll never reads
  NPC.currentTemperature@148 / temperatureCheckTimer@156, and has no
  tileIsBurnable/heat checks; consistent with the E124 reading that the CaveTroll
  NPC type takes 0 high-temperature damage. Snow-surface footsteps
  ('snowStep.wav') are the only cold-world trace.

## Boundaries

- **Census tier (not instruction-by-instruction)**: cw_41 (30,803w), cw_66
  (9,034w) and cw_23 (4,333w) were decoded via full call/selector/ivar/constant
  censuses plus targeted windows - the full branch trees are in the listings;
  cw_30 / cw_29 / cw_56 are census-lite (structure + key seams verified, not every
  argument shuffle traced).
- **cw_41 region is fused**: the exidx region 0xd7d604.. contains preDrawUpdate
  plus a family of local animation/sound subroutines (helpers 0xd7d860 x111 etc.)
  - some selector/sound/particle references belong to those fused functions, not
  to the preDrawUpdate straight-line body.
- **cw_23 region is fused** likewise (a helper block with name/instance/dictionary/
  mutableCopy idioms at 0xd826xx, plus helper 0xd8270c called 12x).
- **cw_00 region is fused**: .cxx_construct's straight-line body ends at 0xd854bc;
  three rotation-matrix helpers follow in the same listing.
- **cw_64 y-window**: the code materializes floatPos.y-5 then re-adds 5 before the
  lower compare, and the upper bound is floatPos.y+5+1; recorded as (fp.y, fp.y+6)
  in the semantics - the exact intent of the +/-5/+1 fudge is not further resolved
  from this listing.
- **cw_29 pathUser slot**: the dictionary's first entry (pathUser) value form was
  not byte-level traced in all three branches; pathType/goalInteraction/goal
  sources are verified. cw_29's guard requires pathNeedsRecalculated != 0 to
  return non-nil.
- **cw_10 tail bytes**: the record's last C byte (+0x3a) and the [5C] array
  (+0x3b..0x3f) are not populated by caveTrollUpdateDataForClient:.
- **cw_30 details**: the exact per-part argument ordering across the four DrawCube
  constructors and the mapping of 0.504/0.404/0.252 to individual part dimensions
  are census-grade (dimension/offset float set verified, per-ctor assignment not
  byte-traced); one extra '%@..._ct.png'-family literal (0xfff4ec04) failed to
  resolve to a printable string.
- **cw_56 mid-body**: the path[0] index -> world pos -> finalGoalSquare flow and
  the type in {0,1,3,4} state writes are verified; some interleaved queue writes
  in the census-lite middle were read as structure, not per-instruction.
- **cw_22 applies a 72-byte arg struct** (types string) - the semantics summarize
  the target fields (makeIntpair x4 into the queue arrays) rather than every
  field assignment.
- **Selected constant gates**: 0xc3..0xc6 (~197) movw family and 0x1869f sentinel
  appear in cw_66; their exact role assignments beyond the sentinel are not
  individually traced.
- All selector strings, ivar cell attributions and CFString contents were
  resolved against the pinned ELF (sha256 733d8210...) directly (spot-checked:
  autorelease/reactToBeingFed/addRider:/setPath:.../removeRider:/remoteUpdate:/
  getBytes:length:/doRemoteUpdate:/isClient and the string literals).
