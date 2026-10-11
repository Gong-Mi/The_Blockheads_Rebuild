# Dodo (E141)

The Dodo animal class lands: the AI tick, motion/render frames and the egg sequence. 46 bodies, 13936 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| dd_00 | Dodo -[.cxx_construct] | 0x00a80aa0 | 152 | 0 | 0 | 0 | 0 | 0 | 34 |
| dd_01 | Dodo -[addRider:] | 0x00a805c8 | 92 | 1 | 1 | 7 | 1 | 1 | 1 |
| dd_02 | Dodo -[blockheadCanRide:usingItem:] | 0x00a80814 | 94 | 2 | 1 | 3 | 0 | 2 | 4 |
| dd_03 | Dodo -[blockheadUnloaded:] | 0x00a809a8 | 55 | 1 | 1 | 2 | 1 | 1 | 1 |
| dd_04 | Dodo -[breedString] | 0x00a7ff88 | 67 | 1 | 3 | 1 | 1 | 3 | 2 |
| dd_05 | Dodo -[cameraPosForBlockhead:] | 0x00a803d4 | 25 | 1 | 0 | 0 | 1 | 1 | 0 |
| dd_06 | Dodo -[canBeCapturedByBlockhead:withItemType:] | 0x00a80094 | 57 | 2 | 1 | 0 | 0 | 2 | 5 |
| dd_07 | Dodo -[cantBeCapturedTipStringForBlockhead:withItemType:] | 0x00a80178 | 90 | 4 | 2 | 0 | 1 | 4 | 5 |
| dd_08 | Dodo -[captureRequiredItemType] | 0x00a6a49c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_09 | Dodo -[capturedItemType] | 0x00a6a480 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_10 | Dodo -[createItemDropsForDeath] | 0x00a776ec | 220 | 1 | 0 | 6 | 0 | 6 | 8 |
| dd_11 | Dodo -[creationDataStructSize] | 0x00a6c88c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_12 | Dodo -[creationNetDataForClient:] | 0x00a6bd3c | 131 | 4 | 1 | 0 | 1 | 8 | 4 |
| dd_13 | Dodo -[dealloc] | 0x00a6c034 | 105 | 2 | 2 | 5 | 1 | 6 | 0 |
| dd_14 | Dodo -[die:] | 0x00a76fc8 | 174 | 5 | 3 | 4 | 2 | 6 | 4 |
| dd_15 | Dodo -[doRemoteUpdate:] | 0x00a6c1d8 | 238 | 3 | 1 | 8 | 0 | 6 | 9 |
| dd_16 | Dodo -[dodoUpdateNetDataForClient:] | 0x00a6bb80 | 111 | 1 | 0 | 4 | 0 | 2 | 3 |
| dd_17 | Dodo -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00a6c940 | 9339 | 31 | 8 | 47 | 2 | 272 | 83 |
| dd_18 | Dodo -[foodItemType] | 0x00a6a464 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_19 | Dodo -[getNamesArray] | 0x00a6a4b8 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_20 | Dodo -[getNamesArrayCount] | 0x00a6a4e8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_21 | Dodo -[getRandomDirection] | 0x00a6c8a8 | 38 | 0 | 0 | 0 | 0 | 1 | 2 |
| dd_22 | Dodo -[hitWithForce:blockhead:] | 0x00a7f76c | 99 | 1 | 1 | 5 | 1 | 2 | 2 |
| dd_23 | Dodo -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] | 0x00a6b664 | 94 | 2 | 1 | 0 | 1 | 2 | 2 |
| dd_24 | Dodo -[initWithWorld:dynamicWorld:cache:netData:] | 0x00a6b904 | 128 | 3 | 2 | 4 | 1 | 3 | 2 |
| dd_25 | Dodo -[jumpAndCluck] | 0x00a77280 | 283 | 5 | 5 | 11 | 1 | 8 | 13 |
| dd_26 | Dodo -[jumpsOnSwipe] | 0x00a8098c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_27 | Dodo -[loadDerivedStuff] | 0x00a6a508 | 961 | 8 | 21 | 27 | 2 | 32 | 3 |
| dd_28 | Dodo -[maxAge] | 0x00a6a404 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_29 | Dodo -[maxHealth] | 0x00a7f11c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_30 | Dodo -[npcType] | 0x00a6a3e8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_31 | Dodo -[reactToBeingFed] | 0x00a7f98c | 247 | 5 | 4 | 7 | 2 | 9 | 2 |
| dd_32 | Dodo -[reactToBeingHit] | 0x00a7f56c | 128 | 4 | 2 | 3 | 1 | 5 | 3 |
| dd_33 | Dodo -[remoteCreationDataUpdate:] | 0x00a6c724 | 90 | 3 | 1 | 0 | 1 | 3 | 0 |
| dd_34 | Dodo -[remoteUpdate:] | 0x00a6c590 | 101 | 3 | 1 | 1 | 1 | 3 | 1 |
| dd_35 | Dodo -[removeRider:] | 0x00a80738 | 55 | 1 | 1 | 2 | 1 | 1 | 1 |
| dd_36 | Dodo -[renderPos] | 0x00a7f8f8 | 37 | 0 | 0 | 3 | 0 | 2 | 0 |
| dd_37 | Dodo -[rideDirection] | 0x00a804e0 | 58 | 0 | 0 | 2 | 0 | 0 | 4 |
| dd_38 | Dodo -[riderBodyYRotationForBlockhead:] | 0x00a80438 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| dd_39 | Dodo -[riderPosForBlockhead:] | 0x00a802e0 | 61 | 1 | 0 | 0 | 0 | 7 | 2 |
| dd_40 | Dodo -[riderRidesWithArmsDown] | 0x00a80a84 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| dd_41 | Dodo -[setTargetVelocity:] | 0x00a8047c | 25 | 0 | 0 | 1 | 0 | 1 | 0 |
| dd_42 | Dodo -[speciesName] | 0x00a6a434 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| dd_43 | Dodo -[successfulTame] | 0x00a7fd68 | 136 | 5 | 3 | 2 | 2 | 6 | 2 |
| dd_44 | Dodo -[tapIsWithinBodyRadius:] | 0x00a7f138 | 269 | 2 | 0 | 2 | 0 | 24 | 13 |
| dd_45 | Dodo -[updateNetDataForClient:] | 0x00a6bf48 | 59 | 2 | 1 | 0 | 1 | 3 | 2 |

## Findings (E141)

- **The Dodo batch lands**: 46 bodies / 13,936 words / 217 branches / 432 call rows of `Dodo` (NPC subclass, instance_size 369; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). Implementation span 0xa6a3e8..0xa80aa0; body order = pinned ObjC method-table order; roster names dd_00..dd_45 are collision-free (0 collisions reported by gen_listings). 1 body >1000w [census], 1 body 300-1000w [census-lite], 44 bodies <=300w fully read. Mechanical layer regenerated this run: gen_listings.py (46 reports, entrypoint-warning lines only) + build_specs.py (46 bodies, 432 call rows, 41 routes).

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | dd_00 | `Dodo -[.cxx_construct]` | 152 | 34 | 0 | read |
  | dd_01 | `Dodo -[addRider:]` | 92 | 1 | 1 | read |
  | dd_02 | `Dodo -[blockheadCanRide:usingItem:]` | 94 | 4 | 2 | read |
  | dd_03 | `Dodo -[blockheadUnloaded:]` | 55 | 1 | 1 | read |
  | dd_04 | `Dodo -[breedString]` | 67 | 2 | 3 | read |
  | dd_05 | `Dodo -[cameraPosForBlockhead:]` | 25 | 0 | 1 | read |
  | dd_06 | `Dodo -[canBeCapturedByBlockhead:withItemType:]` | 57 | 5 | 2 | read |
  | dd_07 | `Dodo -[cantBeCapturedTipStringForBlockhead:withItemType:]` | 90 | 5 | 4 | read |
  | dd_08 | `Dodo -[captureRequiredItemType]` | 7 | 0 | 0 | read |
  | dd_09 | `Dodo -[capturedItemType]` | 7 | 0 | 0 | read |
  | dd_10 | `Dodo -[createItemDropsForDeath]` | 220 | 8 | 6 | read |
  | dd_11 | `Dodo -[creationDataStructSize]` | 7 | 0 | 0 | read |
  | dd_12 | `Dodo -[creationNetDataForClient:]` | 131 | 4 | 8 | read |
  | dd_13 | `Dodo -[dealloc]` | 105 | 0 | 6 | read |
  | dd_14 | `Dodo -[die:]` | 174 | 4 | 6 | read |
  | dd_15 | `Dodo -[doRemoteUpdate:]` | 238 | 9 | 6 | read |
  | dd_16 | `Dodo -[dodoUpdateNetDataForClient:]` | 111 | 3 | 2 | read |
  | dd_17 | `Dodo -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 9339 | 83 | 272 | census |
  | dd_18 | `Dodo -[foodItemType]` | 7 | 0 | 0 | read |
  | dd_19 | `Dodo -[getNamesArray]` | 12 | 0 | 0 | read |
  | dd_20 | `Dodo -[getNamesArrayCount]` | 8 | 0 | 0 | read |
  | dd_21 | `Dodo -[getRandomDirection]` | 38 | 2 | 1 | read |
  | dd_22 | `Dodo -[hitWithForce:blockhead:]` | 99 | 2 | 2 | read |
  | dd_23 | `Dodo -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]` | 94 | 2 | 2 | read |
  | dd_24 | `Dodo -[initWithWorld:dynamicWorld:cache:netData:]` | 128 | 2 | 3 | read |
  | dd_25 | `Dodo -[jumpAndCluck]` | 283 | 13 | 8 | read |
  | dd_26 | `Dodo -[jumpsOnSwipe]` | 7 | 0 | 0 | read |
  | dd_27 | `Dodo -[loadDerivedStuff]` | 961 | 3 | 32 | census-lite |
  | dd_28 | `Dodo -[maxAge]` | 12 | 0 | 0 | read |
  | dd_29 | `Dodo -[maxHealth]` | 7 | 0 | 0 | read |
  | dd_30 | `Dodo -[npcType]` | 7 | 0 | 0 | read |
  | dd_31 | `Dodo -[reactToBeingFed]` | 247 | 2 | 9 | read |
  | dd_32 | `Dodo -[reactToBeingHit]` | 128 | 3 | 5 | read |
  | dd_33 | `Dodo -[remoteCreationDataUpdate:]` | 90 | 0 | 3 | read |
  | dd_34 | `Dodo -[remoteUpdate:]` | 101 | 1 | 3 | read |
  | dd_35 | `Dodo -[removeRider:]` | 55 | 1 | 1 | read |
  | dd_36 | `Dodo -[renderPos]` | 37 | 0 | 2 | read |
  | dd_37 | `Dodo -[rideDirection]` | 58 | 4 | 0 | read |
  | dd_38 | `Dodo -[riderBodyYRotationForBlockhead:]` | 17 | 0 | 0 | read |
  | dd_39 | `Dodo -[riderPosForBlockhead:]` | 61 | 2 | 7 | read |
  | dd_40 | `Dodo -[riderRidesWithArmsDown]` | 7 | 0 | 0 | read |
  | dd_41 | `Dodo -[setTargetVelocity:]` | 25 | 0 | 1 | read |
  | dd_42 | `Dodo -[speciesName]` | 12 | 0 | 0 | read |
  | dd_43 | `Dodo -[successfulTame]` | 136 | 2 | 6 | read |
  | dd_44 | `Dodo -[tapIsWithinBodyRadius:]` | 269 | 13 | 24 | read |
  | dd_45 | `Dodo -[updateNetDataForClient:]` | 59 | 2 | 3 | read |

- **What the class is**: Dodo is the rideable bird NPC. npcType = 1, maxAge = 7200.0f, maxHealth = 16, foodItemType = APPLE (0x15/21), speciesName = CFString "DODO" (obj 0xF97438, cstr 0xF5C2F6), captureRequiredItemType = 0x12E (CAGE), capturedItemType = 0x12F (CAGED DODO). Its name pool is a 244-entry CFString* table at 0x10524D8 (first entries Charlie, Angel, Skittles, Coco, Max, Sunny; last Sky), combined with the per-breed prefix via nameForDodoBreed (0xa7ffd0 -> prefixNameForDodoBreed @0x6a4b18): breedString = "PREFIX DODO" (or plain "DODO" when the prefix is nil). It is built from 5 textures + 1 optional wing texture + one or two shaders + 5 DrawCubes, walks with a peck/cluck state machine, is ridden by Blockheads, lays eggs, and syncs through the standard NPC creation/update blob pipeline.
- **The breed universe (mineral breed table recovered in full)**: createItemDropsForDeath consults itemTypeForDodoBreed (0xa77a5c), a lazily-initialized static std::map<DodoBreed, ItemType>; the entire 32-insert sequence is inline in the binary (0xa77b2c..0xa7813c) and was read out: breed 1..32 -> 1:STONE(1024), 2:LIMESTONE(1028), 3:SANDSTONE(1036), 4:MARBLE(1030), 5:RED MARBLE(1038), 6:LAPIS LAZULI(1054), 7:DIRT(1048), 8:COMPOST(1062), 9:WOOD(1049), 10:GRAVEL(1094), 11:SAND(1051), 12:BLACK SAND(1075), 13:GLASS(1042), 14:BLACK GLASS(1076), 15:CLAY(28), 16:RED BRICKS(1026), 17:FLINT(3), 18:COAL(51), 19:OIL(48), 20:FUEL(269), 21:COPPER ORE(31), 22:TIN ORE(36), 23:IRON ORE(32), 24:GOLD NUGGET(73), 25:TITANIUM ORE(279), 26:PLATINUM NUGGET(261), 27:AMETHYST SHARD(305), 28:SAPPHIRE SHARD(306), 29:EMERALD SHARD(307), 30:RUBY SHARD(308), 31:DIAMOND SHARD(309), 32:RAINBOW ESSENCE(329). The getter returns 0 for unknown breeds (map __count_unique guard).
- **Death drops (dd_10)**: age < 900.0f (vcmpe+bmi; note dd_02 uses <= for its own gate) or isNet -> nothing. Wild (breed==0 or >=33): always drops one RAW DODO MEAT (0x1d) and with 25% chance one DODO FEATHER (0x1e) (flag = lrand48() > 0x3fffffff). Bred (1..32): drops its breed item from the table above, dataA/dataB = (0x7f,0x7f) iff that item is sowable else (0,0) (none of the 32 values are in the 21-item sowable-seed set). All drops via createFreeBlockAtPosition:pos ofType:... playSound:YES priorityBlockhead:killBlockhead.
- **Egg-lay breed remap (dd_00 span)**: the .cxx_construct IMP is a 6-word empty O0 self-return stub; the rest of its exidx span is a u16->u16 32-arm jump-table helper @0xa80ab8 whose single caller is Dodo -[update:accurateDT:isSimulation:] @0xa7ea40 - the breed value is passed through it under an lrand48()<0.5 gate (the egg-lay path; update: also plays eggLay.wav). Full table: 1->0, 2->1, 3->11, 4->2, 5->4, 6->5, 7->0, 8->7, 9->0, 10->1, 11->10, 12->11, 13->3, 14->12, 15->7, 16->15, 17->7, 18->17, 19->18, 20->19, 21->1, 22->21, 23->22, 24->23, 25->24, 26->25, 27->1, 28->27, 29->28, 30->29, 31->30, 32->31.
- **The asset build (dd_27 loadDerivedStuff, 961w)**: two shaders - cache shaderNamed: "ShadedWorldObject" (attrs position/texCoord/normal, uniforms mvp_matrix/texture/light/normal_matrix) -> shader@208; breed path only: "DodoBreedBody" (extended uniform set incl. wing_texture/lightPosition/artificalLight/destruct_texture/daylight) -> nonStandardBodyShader@212. Textures: dodoBody/Neck/Head/Leg/Foot.png -> @216/@220/@224/@228/@232; breed path adds dodoWings.png -> breedWingTexture@236. Cubes: wild bodyCube@240 = DrawCube(0.4,0.4,0.4,calcNormals) 4-arg; bred bodyCube@240 = initMultiTexture(0.4,0.4,0.4, center 0.2,0.2,0.2, top/side/B texcoord blocks, calcNormals, useBoxTexCoordsForB) where the texcoord blocks come from texCoordsForImageIndex(imageTypeForDodoBreed(breed)) and imageTypeForDodoBreed (0xa6b40c) itself: breeds 1-14/16 map to imageTypeForItemType(itemTypeForDodoBreed(breed)) while 15/17-32 use direct image arms (667/666/670/668/669/112/113/115/85/190/672/697..702, default 741). Then neckCube@244 (1.0,0.4,1.0 @ .0625,0,.0625), headCube@248 (0.25,0.125,0.125 @ .25,.0625,.0625), legCube@252 (0.0625,0.275,0.0625 @ .03125,.15,.03125), footCube@256 (0.25,0.0625,0.125, 4-arg). Locomotion init: movementDirection = getRandomDirection(); fromSquare=toSquare=pos; travelFraction=1.0; randomTimeBetweenDirectionChanges=0.0; randomXOffset=randomXOffsetGoal=(lrand48()/2^31)*0.8-0.4; randomCluckNoiseTimer=(lrand48()/2^31)*100+20; peckTimer=1.0; nextPeckTimer=(lrand48()/2^31)*2+0.1; walkSpeed=(lrand48()/2^31+0.25)*2.
- **The render (dd_17 draw, 9,339w census)**: one method; ~11.7KB frame; 272 calls (58 objc, 16 glUniformMatrix4fv, 10 glBindTexture, 7 sinf, 4 glUniform1i, 4 glUniform4f, 4 glActiveTexture (GL_TEXTURE0-2 = 0x84c0/1/2), 2 glUseProgram, 2 glEnableVertexAttribArray + 1 glDisable, 12 memcpy(64B), 38 Vector/Vector2 math, 6 idiv, 5 lrand48, local matrix/emit helpers 0xa75ba0 x12 / 0xa76a08 x16 / 0xa75b2c / 0xa75d88 / 0xa76120 x2 / 0xa764b8 x2 / 0xa76670 x4). Flow: walk-state + worldWidthMacro seam math -> sinf bob animation matrix chain -> glUseProgram(shader@208) + glUniform1i + dayColor/light uniforms + ParticleEmitter splash particles + splash.wav sound (createSplashNextFrame@368 flag) -> EIGHT textured draw blocks (body/neck/head/leg/foot texture+cube cells; each block = matrix helpers + 2x glUniformMatrix4fv (mvp/normal) + glBindTexture(GL_TEXTURE_2D 0xde1) + cube-draw selector) + a tail pass with the second program (nonStandardBodyShader@212) + 5 binds + 4 glActiveTexture units (breed body pass with breedWingTexture@236).
- **Sounds (all pinned to CFStrings + wiring sites)**: die: -> dodoDie.wav; reactToBeingFed -> crunch.wav @0.1 then dodo2.wav @0.6; reactToBeingHit -> cluck.wav @0.1; jumpAndCluck -> dodoCluck1/2/3/4.wav (dodoCluck4 only when u<0.05 and age>900, then 0.4/0.7 splits); successfulTame -> dodoTame.wav @0.6. Every sound: [[MJSoundManager instance] multiSoundNamed:...] + setPitch:(age > 900.0f ? 1.0 : 3.0) (jumpAndCluck, reactToBeingFed, reactToBeingHit, successfulTame and die all share the age>900 pitch split; playAtPosition:floatPos afterDelay 0.1 (die/hit/fed-first) or 0.6 (cluck/tame/fed-second)).
- **Ride/capture gates**: blockheadCanRide:usingItem: = age > 900.0f && (!tamed || belongsToPlayerWithBlockhead:) && !dead && !needsRemoved (usingItem unused). canBeCapturedByBlockhead:withItemType: = itemType==0x12e (CAGE) && (!tamed || owner) - no age check. The refusal tip exists only for the owned-dodo case: a two-line "THAT %@ BELONGS TO / SOMEONE ELSE" format with speciesName (fmt @0xF97688).
- **Riders**: addRider: super + (if !beingControlled) riderTargetVelocity=(0,0) + remote-cache resets; removeRider: (arg==rider) -> super + riderTargetVelocity=(0,0); rideDirection = sign of riderTargetVelocity.x with +/-0.1 dead zone; riderPosForBlockhead: = renderPos + (0, +0.4, -0.75) Vector3 (blockhead arg unused; [self renderPos] read); riderBodyYRotation = bodyRotation; riderRidesWithArmsDown = YES; setTargetVelocity: writes only the x component into riderTargetVelocity@320; tapIsWithinBodyRadius: = !dead && a 1x1 square hit box centered at renderPos+(0,0.4) with map-seam wrap (worldWidthMacro msgSend, *32, /2 half-width, +/- wrap).
- **Net pipeline**: creation blob = 0x70 bytes = 0x48 [self npcCreationNetDataForClient:client] + 0x28 [self dodoUpdateNetDataForClient:client], wrapped via [NSData dataWithBytes:... length:0x70] + appendNPCCreationDataToData: (dd_12/45; creationDataStructSize = 0x70). DodoUpdateNetData (tsv {DodoUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIscc[3c]}): +0x18/+0x1c toSquare (2 ints), +0x20 (s16)(walkSpeed*255.0f), +0x22 (s8)movementDirection, +0x23 jump-flag (jumpAndCluckState != 0 -> flag=1 and state:=2). Reception: remoteUpdate: -> getBytes 0x28 -> doRemoteUpdate:; remoteCreationDataUpdate: -> getBytes 0x70 -> doRemoteUpdate: on the blob+0x48 sub-struct. doRemoteUpdate: (struct 0x28): local rider -> return; server: apply goal/remoteWalkSpeed/remoteMovementDirection + set walkSpeed/movementDirection + updateNeedsToBeSent; client: apply the three remote* fields + [self jumpAndCluck] when the flag byte is set. Net init = super + loadDerivedStuff + remoteGoalSquare=pos + remoteWalkSpeed=0 + remoteMovementDirection=0 + remoteCreationDataUpdate:.
- **State/lifecycle**: the 8-arg placement ctor = super + nil->nil + loadDerivedStuff (no water/temperature gate, unlike Shark); dealloc releases the 5 cubes then super (textures/shaders not released); blockheadUnloaded: zeroes riderTargetVelocity when the unloaded blockhead was the rider; hitWithForce: super + if (!dead && !isNet): direction +/-1 (50% split), walkSpeed=3.0, timer=5.0; getRandomDirection = u>0.75 -> 1 / u<0.25 -> -1 / else 0.

## Boundaries

- **Mechanical layer regenerated this run**: gen_listings.py reported zero collisions for the 46 dd_* names and bodies 46 words 13936; build_specs.py verified every body word-for-word (verify_disassembly) and wrote 46 bodies / 432 call rows / 41 routes. All constants were read straight out of the pinned ELF via python struct (file offset == vaddr); PIC base recomputed per body = 0x0105FAF4; the GNU listings here use 6-8 hex digit addresses (no leading-zero padding), so the parser matched 1-8 digits.
- **r2 immediate labels were wrong in several places; GNU objdump was used as truth** (the known trap): dd_21 read 7/2 in r2 but is 0.75/0.25; dd_22 read 5 but is 0.5; dd_27 read 5/2/1 as 0.5/0.25/0.125 (and one 20.0 read as 2); dd_39 read -7 but is -0.75; dd_44 read +/-5 but is +/-0.5; the pitch pairs 1.0/3.0 were confirmed. Where semantics depended on a VFP immediate the dd_NN_gl.txt annotation was quoted; where a bare literal was judged the raw ELF word was read directly (pools 0x44610000=900.0f, 0x4f000000=2^31, 0x437f0000=255.0f, 0x3ecccccd=0.4f, 0x3fb99999/0xa0000000 = (double)(float)0.1, 0x3fe33333/0x40000000 = (double)(float)0.6).
- **dd_00 boundary**: only the first 6 words are the real .cxx_construct (empty stub); the 146 remaining words are an adjacent C helper sharing the exidx entry (no own unwind record). Its reading as the egg-lay breed re-map rests on the single call site inside -[update:accurateDT:isSimulation:] (outside this batch; the call-site context was read only as far as needed to pin the gate: lrand48 wrapper 0xa6b654 + /2^31 against 0.5). The remap table is read raw from the 32 entry words; the domain assumption (breed 1..32, identity default) is what the code itself compares against.
- **dd_17 is census grade**: call histogram + constant pools + sampled windows define the semantics; the matrix-compose helper family (0xa75b2c/0xa75ba0/0xa75d88/0xa76120/0xa764b8/0xa76670/0xa76a08) stays opaque (matrix math inferred from call shape and the surrounding memcpy(64B)/glUniformMatrix4fv pattern, not byte-verified). The per-block cube/texture identity is pinned by first-use ivar cells (body 0xa70a44/4c, neck 0xa72cfc/d04, head 0xa72d0c/d10, leg 0xa72d14/d18, foot 0xa748c4/c8), but the exact block ORDER inside the 8-block run is inferred from cell order, not from per-block matrix contents. The tail breed pass is labelled from its cells (bodyCube@240 / nonStandardBodyShader@212 / breedWingTexture@236) and its 5 binds + 4 glActiveTexture units; the individual textures bound there are not enumerated.
- **dd_27 is census-lite**: cube argument tuples are read off the O0 spill map after GL-truth immediate correction; the topTexCoords/sideTexCoords float blocks passed to the multi-texture init come from texCoordsForImageIndex(imageTypeForDodoBreed(breed)) and their numeric values are not enumerated here. The 33-arm image table of imageTypeForDodoBreed (0xa6b458) is decoded as numbers; mapping those image indexes to atlas textures is outside this batch.
- **The breed->item map was recovered from the inline static-init sequence** (immediates in the map insert loop at 0xa77b2c..0xa7813c, cross-checked against the item-name table for all 32 values), not from runtime state. The getter returns 0 for breeds outside the map (count==0 guard); no claim is made about breeds > 32 or 0.
- **Wire-struct names are not enumerated**: DodoUpdateNetData field names are inferred from the tsv type string and the store/load pairs (offsets 0x18/0x1c toSquare, 0x20 walkSpeed*255 as s16, 0x22 movementDirection as s8, 0x23 jump flag); the 0x48 NPC sub-blob stays inside npcCreationNetDataForClient: (NPC base class, outside this batch).
- **Boundary trims** (recorded in roster.json): dd_04 trimmed at next IMP 0xa80094 (its listing also carries helper nameForDodoBreed), dd_08/dd_09/dd_18/dd_19/dd_42 trimmed at their next IMPs (tiny accessors sharing the 0xa6a508 exidx end), dd_40 trimmed at .cxx_construct 0xa80aa0. No body rows were dropped anywhere (rows == words for every body).
- **Null-guard oddity**: dd_12/dd_16/dd_39/dd_44 compile-time checks are against self (an O0 artifact of the struct-return path); the actual receivers are self/the stret buffer, and the blockhead argument of riderPosForBlockhead: is unused - stated as read, not as intent.
- Static level-A evidence only (r2 pD + GNU objdump + ELF struct reads + BL-caller scans): no runtime roundtrip, no device-side rendering or netplay claims; netcode pairing is demonstrated only as write/read offset equality across dd_16/dd_45 (writer) and dd_15/dd_33/dd_34 (reader).
