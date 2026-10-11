# Shark (E140)

The Shark animal class lands: the AI tick, motion/render frames and the capture data. 47 bodies, 15370 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| sh_00 | Shark -[.cxx_construct] | 0x007ddac0 | 31 | 0 | 0 | 2 | 0 | 2 | 0 |
| sh_01 | Shark -[addRider:] | 0x007dd6d0 | 64 | 1 | 1 | 2 | 1 | 2 | 1 |
| sh_02 | Shark -[blockheadCanRide:usingItem:] | 0x007dd90c | 88 | 2 | 1 | 3 | 0 | 2 | 3 |
| sh_03 | Shark -[blockheadUnloaded:] | 0x007dcee8 | 104 | 2 | 2 | 3 | 1 | 3 | 2 |
| sh_04 | Shark -[cameraPosForBlockhead:] | 0x007dd4dc | 25 | 1 | 0 | 0 | 1 | 1 | 0 |
| sh_05 | Shark -[canBeCapturedByBlockhead:withItemType:] | 0x007c72e8 | 71 | 2 | 1 | 1 | 0 | 2 | 6 |
| sh_06 | Shark -[cantBeCapturedTipStringForBlockhead:withItemType:] | 0x007c7404 | 171 | 4 | 4 | 1 | 1 | 8 | 8 |
| sh_07 | Shark -[captureRequiredItemType] | 0x007c72cc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_08 | Shark -[capturedItemType] | 0x007c72b0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_09 | Shark -[center] | 0x007dcd38 | 108 | 2 | 1 | 2 | 0 | 5 | 2 |
| sh_10 | Shark -[creationDataStructSize] | 0x007c90f0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_11 | Shark -[creationNetDataForClient:] | 0x007c8e30 | 176 | 5 | 1 | 2 | 1 | 8 | 6 |
| sh_12 | Shark -[dealloc] | 0x007c91f8 | 157 | 2 | 2 | 9 | 1 | 10 | 0 |
| sh_13 | Shark -[die:] | 0x007d6154 | 100 | 4 | 2 | 3 | 2 | 4 | 3 |
| sh_14 | Shark -[doRemoteUpdate:] | 0x007c9d50 | 272 | 2 | 1 | 10 | 0 | 6 | 8 |
| sh_15 | Shark -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x007ca3e0 | 10618 | 17 | 3 | 48 | 1 | 241 | 66 |
| sh_16 | Shark -[foodItemType] | 0x007c7248 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_17 | Shark -[getNamesArray] | 0x007c7264 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_18 | Shark -[getNamesArrayCount] | 0x007c7294 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_19 | Shark -[hitWithForce:blockhead:] | 0x007dca30 | 161 | 2 | 2 | 6 | 1 | 3 | 4 |
| sh_20 | Shark -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] | 0x007c83f8 | 328 | 7 | 1 | 3 | 1 | 14 | 13 |
| sh_21 | Shark -[initWithWorld:dynamicWorld:cache:netData:] | 0x007c8a40 | 125 | 3 | 2 | 3 | 1 | 3 | 4 |
| sh_22 | Shark -[isUnderLocalControl] | 0x007d62e4 | 99 | 1 | 1 | 2 | 0 | 2 | 4 |
| sh_23 | Shark -[jumpsOnSwipe] | 0x007dda6c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_24 | Shark -[loadDerivedStuff] | 0x007c76b0 | 845 | 6 | 17 | 27 | 2 | 29 | 5 |
| sh_25 | Shark -[maxAge] | 0x007c71b4 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_26 | Shark -[maxHealth] | 0x007dc4a8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_27 | Shark -[minFullness] | 0x007c71e4 | 13 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_28 | Shark -[minRidableAge] | 0x007dd8dc | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_29 | Shark -[namePos] | 0x007dd320 | 30 | 0 | 0 | 1 | 0 | 2 | 0 |
| sh_30 | Shark -[npcType] | 0x007c7198 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_31 | Shark -[reactToBeingFed] | 0x007dd088 | 166 | 4 | 3 | 5 | 2 | 8 | 0 |
| sh_32 | Shark -[reactToBeingHit] | 0x007dc93c | 61 | 3 | 1 | 2 | 1 | 3 | 1 |
| sh_33 | Shark -[remoteCreationDataUpdate:] | 0x007c946c | 569 | 13 | 3 | 13 | 2 | 19 | 31 |
| sh_34 | Shark -[remoteUpdate:] | 0x007ca190 | 148 | 4 | 2 | 4 | 1 | 4 | 5 |
| sh_35 | Shark -[removeRider:] | 0x007dd7d0 | 67 | 1 | 1 | 2 | 1 | 2 | 1 |
| sh_36 | Shark -[renderPos] | 0x007dccb4 | 33 | 0 | 0 | 2 | 0 | 2 | 0 |
| sh_37 | Shark -[rideDirection] | 0x007dd5d8 | 62 | 0 | 0 | 2 | 0 | 2 | 4 |
| sh_38 | Shark -[riderBodyYRotationForBlockhead:] | 0x007dd540 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| sh_39 | Shark -[riderDPadShouldAllowUpDown] | 0x007ddaa4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_40 | Shark -[riderPosForBlockhead:] | 0x007dd398 | 81 | 0 | 0 | 2 | 0 | 3 | 2 |
| sh_41 | Shark -[riderRidesWithArmsDown] | 0x007dda88 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sh_42 | Shark -[setTargetVelocity:] | 0x007dd584 | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| sh_43 | Shark -[sharkUpdateNetDataForClient:] | 0x007c8cb0 | 96 | 1 | 0 | 4 | 0 | 2 | 2 |
| sh_44 | Shark -[speciesName] | 0x007c7218 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| sh_45 | Shark -[tapIsWithinBodyRadius:] | 0x007dc4c4 | 286 | 1 | 1 | 4 | 0 | 18 | 15 |
| sh_46 | Shark -[updateNetDataForClient:] | 0x007c910c | 59 | 2 | 1 | 0 | 1 | 3 | 2 |

## Findings (E140)

- **The Shark batch lands**: 47 bodies / 15,370 words / 198 branches / 413 call rows of `Shark` (NPC subclass, instance_size 412; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). Implementation span 0x7c71b0..0x7dda88; body order = pinned ObjC method-table order; roster names sh_00..sh_46 are collision-free (0 collisions on the checked-in disasm_* set). 1 body >1000w [census], 3 bodies 300-1000w [census-lite], 43 bodies <=300w fully read. Mechanical layer regenerated this run: gen_listings.py (r2 pD bodies 47 words 15370, 47 entrypoint-warning lines only) + build_specs.py (47 bodies, 413 call rows, 41 routes, verify_disassembly passed for every body).

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | sh_00 | `Shark -[.cxx_construct]` | 31 | 0 | 2 | read |
  | sh_01 | `Shark -[addRider:]` | 64 | 1 | 2 | read |
  | sh_02 | `Shark -[blockheadCanRide:usingItem:]` | 88 | 3 | 2 | read |
  | sh_03 | `Shark -[blockheadUnloaded:]` | 104 | 2 | 3 | read |
  | sh_04 | `Shark -[cameraPosForBlockhead:]` | 25 | 0 | 1 | read |
  | sh_05 | `Shark -[canBeCapturedByBlockhead:withItemType:]` | 71 | 6 | 2 | read |
  | sh_06 | `Shark -[cantBeCapturedTipStringForBlockhead:withItemType:]` | 171 | 8 | 8 | read |
  | sh_07 | `Shark -[captureRequiredItemType]` | 7 | 0 | 0 | read |
  | sh_08 | `Shark -[capturedItemType]` | 7 | 0 | 0 | read |
  | sh_09 | `Shark -[center]` | 108 | 2 | 5 | read |
  | sh_10 | `Shark -[creationDataStructSize]` | 7 | 0 | 0 | read |
  | sh_11 | `Shark -[creationNetDataForClient:]` | 176 | 6 | 8 | read |
  | sh_12 | `Shark -[dealloc]` | 157 | 0 | 10 | read |
  | sh_13 | `Shark -[die:]` | 100 | 3 | 4 | read |
  | sh_14 | `Shark -[doRemoteUpdate:]` | 272 | 8 | 6 | read |
  | sh_15 | `Shark -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 10618 | 66 | 241 | census |
  | sh_16 | `Shark -[foodItemType]` | 7 | 0 | 0 | read |
  | sh_17 | `Shark -[getNamesArray]` | 12 | 0 | 0 | read |
  | sh_18 | `Shark -[getNamesArrayCount]` | 7 | 0 | 0 | read |
  | sh_19 | `Shark -[hitWithForce:blockhead:]` | 161 | 4 | 3 | read |
  | sh_20 | `Shark -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]` | 328 | 13 | 14 | census-lite |
  | sh_21 | `Shark -[initWithWorld:dynamicWorld:cache:netData:]` | 125 | 4 | 3 | read |
  | sh_22 | `Shark -[isUnderLocalControl]` | 99 | 4 | 2 | read |
  | sh_23 | `Shark -[jumpsOnSwipe]` | 7 | 0 | 0 | read |
  | sh_24 | `Shark -[loadDerivedStuff]` | 845 | 5 | 29 | census-lite |
  | sh_25 | `Shark -[maxAge]` | 12 | 0 | 0 | read |
  | sh_26 | `Shark -[maxHealth]` | 7 | 0 | 0 | read |
  | sh_27 | `Shark -[minFullness]` | 13 | 0 | 0 | read |
  | sh_28 | `Shark -[minRidableAge]` | 12 | 0 | 0 | read |
  | sh_29 | `Shark -[namePos]` | 30 | 0 | 2 | read |
  | sh_30 | `Shark -[npcType]` | 7 | 0 | 0 | read |
  | sh_31 | `Shark -[reactToBeingFed]` | 166 | 0 | 8 | read |
  | sh_32 | `Shark -[reactToBeingHit]` | 61 | 1 | 3 | read |
  | sh_33 | `Shark -[remoteCreationDataUpdate:]` | 569 | 31 | 19 | census-lite |
  | sh_34 | `Shark -[remoteUpdate:]` | 148 | 5 | 4 | read |
  | sh_35 | `Shark -[removeRider:]` | 67 | 1 | 2 | read |
  | sh_36 | `Shark -[renderPos]` | 33 | 0 | 2 | read |
  | sh_37 | `Shark -[rideDirection]` | 62 | 4 | 2 | read |
  | sh_38 | `Shark -[riderBodyYRotationForBlockhead:]` | 17 | 0 | 0 | read |
  | sh_39 | `Shark -[riderDPadShouldAllowUpDown]` | 7 | 0 | 0 | read |
  | sh_40 | `Shark -[riderPosForBlockhead:]` | 81 | 2 | 3 | read |
  | sh_41 | `Shark -[riderRidesWithArmsDown]` | 7 | 0 | 0 | read |
  | sh_42 | `Shark -[setTargetVelocity:]` | 21 | 0 | 0 | read |
  | sh_43 | `Shark -[sharkUpdateNetDataForClient:]` | 96 | 2 | 2 | read |
  | sh_44 | `Shark -[speciesName]` | 12 | 0 | 0 | read |
  | sh_45 | `Shark -[tapIsWithinBodyRadius:]` | 286 | 15 | 18 | read |
  | sh_46 | `Shark -[updateNetDataForClient:]` | 59 | 2 | 3 | read |

- **What the class is**: Shark is the water NPC creature (NPCType constant 5 -> 36; speciesName = CFString @"SHARK" @0xF90E88, cstring 0xF563B1). It is built from 8 textures + 8 DrawCubes + one shader, driven by a walk/bob animation, ridden by Blockheads, bites them, and syncs through the standard DynamicObject/NPC net pipeline (creation blob, update blob, doRemoteUpdate:).

- **The asset build** (sh_24 loadDerivedStuff, 845w): cache @32 builds shader = [cache shaderNamed:@"ShadedWorldObject" (0xF90EC8) attributes:[position,texCoord,normal] uniforms:[mvp_matrix,texture,light,normal_matrix]] -> shader @208; 8 textures via [cache textureNamed:]: sharkBodyFront.png->bodyFrontTexture@212, sharkBodyBack.png->@216, sharkHeadTop.png->@220, sharkHeadBottom.png->@224, sharkTopFin.png->@228, sharkSideFin.png->@232, sharkTailFinTop.png->@236, sharkTailFinBottom.png->@240; 8 cubes via [DrawCube alloc] initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals: (headTopCube uses the 4-arg variant): bodyFrontCube@244=(1.5,0.6,0.6, 0,0.3,0.3), bodyBackCube@248=(0.75,0.4,0.4, 0,0.2,0.2), headTopCube@252=(0.7,0.3,0.4), headBottomCube@256=(0.4,0.03,0.3, 0.6,0.075,0.03), topFinCube@260=(0.6,0.6,0.1, 0.3,0.3,0.05), sideFinCube@264=(0.3,0.06,0.6, 0.03,0.15,0.0), tailFinTopCube@268=(0.25,0.5,0.1, 0.125,0,0.05), tailFinBottomCube@272=(0.25,0.3,0.08, 0.125,0.3,0.04). Then: d=lrand48()/2^31f; movementDirection@276 = d>0.75?1:(d<0.25?-1:0); pos@16 copied to toSquare@288 and fromSquare@280; travelFraction@296=1.0f; randomTimeBetweenDirectionsChanges@300=0.0f; walkSpeed@324 = 0.1+0.2*lrand48()/2^31 (doubles 0.1/0.2 @0x7c82f0/0x7c82f8); goalRotation@308=bodyRotation@304 = (movementDirection==1 ? +pi/2f (0x7c83dc) : -pi/2f (0x7c83d0)). Note: GNU-objdump truth corrected several r2 immediate labels here (vmov.f32 s12=0.25, s1=0.125, s5=0.5, s16=0.75, s20=1.5; r2's comments read them as 2/1/5/7/1).

- **The render** (sh_15 draw:..., 10,618w census): one method draws everything. Frame ~11.7KB locals (vpush d8-d9 + 3 scratch arenas + a state-snapshot buffer holding a copy of the Shark fields). Call profile: 82 objc_msgSend, 18 glUniformMatrix4fv, 9 glBindTexture, 1 glUseProgram, 1 glUniform1i, 1 glUniform4f, 1 glEnable/glDisableVertexAttribArray(2), 3 sinf (swim/bob phases), 10 memcpy(64B), matrix helpers 0x7d5b94 x18 (opaque compose, 16+ args) / 0x7d4bf4 x10 / 0x7d5174 x9 / 0x7d4ddc x7 / 0x7d550c x4 / 0x7d5b58 / 0x7d58a4, 2x lrand48 wrapper 0x7c83e4 (bubbles), tileAtWorldPosition_MacroTile + tileIsSolid (ground/falling checks), 18x Vector::operator float*() / 9x Vector2::operator float*(). Flow: transform math -> glUseProgram([self.shader program]) -> glUniform1i([shader.uniformLocations objectAtIndex:1].intValue, 0) (texture unit 0) -> [world dayColor] -> bubble particles: 2 random vectors + [[ParticleEmitter instance] addParticleAtPos:velocity:color:gravityType:life:scale:] -> glUniform4f([uniformLocations[2].intValue], dayColor.rgb, 1.0f) -> glEnableVertexAttribArray(2) -> NINE draw blocks: the 8 cubes in order bodyFront -> bodyBack -> headTop -> headBottom -> topFin -> tailFinTop -> tailFinBottom, then sideFinCube@264 drawn TWICE (blocks 8 and 9 both use sideFinCube/sideFinTexture@232 - the two side fins); each block = matrix compose + glUniformMatrix4fv([uniformLocations[0].intValue], 1, 0, &mvp_matrix) + glUniformMatrix4fv([uniformLocations[3].intValue], 1, 0, &normal_matrix) + glBindTexture(GL_TEXTURE_2D=0xde1, [texture name]) + objc_msgSend(cube, 'draw') (the 'draw' selector cell is loaded once in block 1 and cached on the stack for blocks 2-8; block 9 reloads it) -> glDisableVertexAttribArray(2).

- **The stat family** (all read): maxAge = 27000.0f (triple-materialized 0x46D2F000 + int 0x6978 in r2), maxHealth = 0x19 (25), minFullness = -9000.0f (0xC60CA000), minRidableAge = 4500.0f (0x458CA000, int 0x1194), npcType = 5, foodItemType = 0x97 (151), captureRequiredItemType = 0x66 (102, the bucket), capturedItemType = 0x9f (159), creationDataStructSize = 0x78 (120), getNamesArrayCount = 0x40 (64); getNamesArray returns the 64-entry CFString pointer table @0x1051E88 (alphabetical: Alpha, Angel, Barney, Berty, Blade, Bob, Bowie, Brutus ... Trevor, Victoria, Weasel); jumpsOnSwipe = NO, riderDPadShouldAllowUpDown = YES, riderRidesWithArmsDown = NO.

- **The ride/capture gates**: blockheadCanRide:usingItem: (sh_02) = age > 4500.0f && [self belongsToPlayerWithBlockhead:blockhead] && !dead@56 && !needsRemoved@48 (the usingItem int arg is unused). canBeCapturedByBlockhead:withItemType: (sh_05) = itemType==102 && age<4500.0f && ( ![self tamed] || [self belongsToPlayerWithBlockhead:blockhead] ). The refusal tips (sh_06): itemType!=102 -> "%@S CAN ONLY BE CAPTURED
IN A BUCKET"; age>4500 -> "THAT %@ IS TOO BIG
TO BE CAPTURED"; tamed && !belongsToPlayer -> "THAT %@ BELONGS TO
SOMEONE ELSE"; otherwise nil (capturable). minRidableAge = 4500 is the shared threshold.

- **Riders**: addRider: (sh_01) = [super addRider:rider]; if (!NPC.beingControlled@128) riderTargetVelocity@388 = (0,0) Vector2. removeRider: (sh_35) = if (arg == self.rider@132) { [super removeRider:arg]; riderTargetVelocity = (0,0); }. rideDirection (sh_37) = 0 if no rider, else sign of riderTargetVelocity.x with a +-0.1f dead zone (pools 0x7dd6c0/0x7dd6c8). riderPosForBlockhead: (sh_40) = Vector3(namePosition.x, (namePosition.y - 1.0f) + 0.5f*min(age/9000.0f, 1.0f), -0.75f) (gl: d2=0.5, s2=-0.75; divisor 9000.0f @0x7dd4cc). riderBodyYRotationForBlockhead: (sh_38) = bodyRotation@304. namePos (sh_29) = namePosition@336 + (0,1). renderPos (sh_36) = DynamicObject.floatPos@24 + (xOffset@332, 0). setTargetVelocity: (sh_42) stores the by-value Vector2 straight into riderTargetVelocity@388.

- **Locomotion & reactions**: hitWithForce:blockhead: (sh_19) scales the force: t=(age/maxAge)*2.8+0.2 (pools 0x7dcc78/0x7dcc7c), force'=int(force/t), r=max(force',1), [super hitWithForce:r blockhead:blockhead], then if (!dead && !isNet) re-randomizes movementDirection = +1/-1 (lrand48()/2^31f > 0.5, gl d2=0.5; divisor 2^31 @0x7dccac), walkSpeed=3.0f, randomTimeBetweenDirectionChanges=5.0f. reactToBeingFed (sh_31) plays "crunch.wav" (0xF91038) @0.1 then "fishRun.wav" (0xF91028) @0.6 at floatPos and re-randomizes the same three fields plus updateNeedsToBeSent@49=1. reactToBeingHit (sh_32) plays "fishRun.wav" @0.1 if !dead. die: (sh_13) plays "fishDie.wav" (0xF90FD8) @0.1 (only when the kill arg != nil), travelFraction@296=0.0f, [super die:]. center (sh_09) = [self renderPos] + Vector2(((age/maxAge)*1.5 + 0.25) * (-bodyRotation/(pi/2)), 0) (gl d1=1.0 d2=0.25 d3=1.5; pi/2 double @0x7dcec8). tapIsWithinBodyRadius: (sh_45) = axis-aligned body rect: y in (floatPos.y, floatPos.y+1.0); x in (floatPos.x-0.5, floatPos.x+R) when movementDirection<0 else (floatPos.x-0.5-R, floatPos.x+0.5), R = 2.0*(0.25+1.5*age/maxAge); NO when dead.

- **The net family**: sharkUpdateNetDataForClient: (sh_43) builds the 0x28-byte SharkUpdateNetData: [0..0x18) = objc_msgSend_stret [self npcUpdateNetDataForClient:arg] (24 bytes), +0x18/+0x1c = DynamicObject.pos words, +0x20 = (short)(walkSpeed*255.0f) (pool 0x7c8e20=255.0), +0x22 = (short)age, +0x24 = (byte)movementDirection. updateNetDataForClient: (sh_46) = [NSData dataWithBytes:that length:0x28]. creationNetDataForClient: (sh_11) = 0x78-byte blob: [0..0x48) npcCreationNetDataForClient: + [0x48..0x70) sharkUpdateNetDataForClient: + [0x70..0x78) attackBlockhead.uniqueID (zero when nil or isNet), then [self appendNPCCreationDataToData:data]. remoteUpdate: (sh_34) = [super remoteUpdate:arg]; if (!dead) { [arg getBytes:buf length:0x28]; [self doRemoteUpdate:buf]; } else if (travelFraction<1.0f && ![dynamicWorld isClient]) needsRemoved=0. remoteCreationDataUpdate: (sh_33) = [super ...]; dead -> same dead-branch; else parse the 0x78 blob -> attack-target search by uid (fast enumeration of [dynamicWorld allBlockheadsIncludingNet], countByEnumeratingWithState:): on match retain + self.attackBlockhead = blockhead, play "jaws.wav" (0xF90FC8), biting@364=1, updateNeedsToBeSent@49=1, creationDataNeedsToBeSent@50=1, biteTimer@360=1.0f, walkSpeed@324=4.0f; a re-seen current attackBlockhead toggles found off (the stale one is released and nilled when uid==0 or different); always ends with [self doRemoteUpdate:blob+0x48]. doRemoteUpdate: (sh_14, struct by value 0x28 bytes): non-client: if (rider && [rider isNet]) { remoteGoalSquare@396={w6,w7}; walkSpeed=remoteWalkSpeed@404=(s16)w8/255.0f; movementDirection=remoteMovementDirection@408=(s8)w9; updateNeedsToBeSent=1; }; client: unless (rider && !rider.isNet), and unless (attackBlockhead && !attackBlockhead.isNet), sets the three remote* fields; finally self.age@88 = (float)(u16)struct[0x22]. isUnderLocalControl (sh_22): netObj -> (rider != 0 && ![rider isNet]); local -> !(rider && [rider isNet]).

- **The init gates**: initWithWorld:dynamicWorld:cache:netData: (sh_21) = [super ...]; nil->nil; [self loadDerivedStuff]; [self remoteCreationDataUpdate:netData]; goalRotation@308=bodyRotation@304=(movementDirection==1 ? +pi/2 : -pi/2). The 8-arg init (sh_20) = [super <8-arg selector>]; nil->nil; tile = tileAtWorldPositionLoaded(pos.x,pos.y,world) must be non-nil; unless wasPlaced, the tile must be water (tileIsWater) with tile byte[4] >= 0x7f; failure = [self removeFromMacroBlock] + [self release] + nil. Then (not wasPlaced): weather = [world getWeatherFractionForPos:pos]; dayNight = [world getDayNightFractionForX:(float)pos.x atWorldTime:[world worldTime]]; season = seasonForWorldX(pos.x, [world worldTime], world); temp = currentTemperatureForTileAtWorldPos(tile, pos, season, dayNight, weather, world). Spawn accepted iff temp >= 0.1f (pool 0x7c88f8) AND (age <= 0.1 (double pool 0x7c88d0) OR temp >= 2.0f), else the fail path. Success: [self loadDerivedStuff]; return self. blockheadUnloaded: (sh_03) releases self.attackBlockhead and zeroes riderTargetVelocity for the matching blockhead before [super blockheadUnloaded:]. .cxx_construct (sh_00) default-constructs the namePosition and riderTargetVelocity Vector2s; dealloc (sh_12) releases the 8 cubes + attackBlockhead, then [super dealloc] (textures/shader are not released).

## Boundaries

- **Mechanical layer regenerated this run**: gen_listings.py reported `existing worldtileloader listings: 3170`, zero collisions for the 47 sh_* names, `bodies 47 words 15370`; build_specs.py verified every body word-for-word (verify_disassembly) and wrote 47 bodies / 413 call rows / 41 routes. All constants were read straight out of the pinned ELF via python struct (file offset == vaddr); PIC base recomputed per body = 0x0105FAF4. Bodies re-derived mechanically are byte-anchored; the semantic layer below is what the listings support and nothing beyond it.
- **r2 immediate comments were wrong in several places; GNU objdump was used as truth**: sh_09 (d2=0.25 d3=1.5, not 2/1), sh_19/sh_31 d2=0.5 (not 5), sh_24 (vmov.f32 s12=0.25, s1=0.125, s5=0.5, s16=0.75, s20=1.5), sh_40 (d2=0.5; s2=-0.75, not -7), sh_45 (half-extents 0.5 and consts 2.0/0.25/1.5). Where semantics depended on a VFP immediate, the sh_NN_gl.txt annotation was quoted. Where a bare literal (non-VFP) was judged, the raw ELF word was read directly (e.g. pools 0x7dd4cc=9000.0f, 0x7c73ec=4500.0f, 0x7ca17c=255.0f, 0x7c8e20=255.0f, 0x46D2F000=27000.0f).
- **Census grades**: sh_15 is a structural summary (send table, call histogram, branch skeleton, literal/cell map, sampled windows: prologue, glUseProgram/glUniform1i, dayColor, ParticleEmitter/bubbles, one full cube block, block-2 post-bind, tail). Its matrix-compose helpers 0x7d5b94 / 0x7d4bf4 / 0x7d5174 / 0x7d4ddc / 0x7d550c / 0x7d5b58 / 0x7d58a4 stay opaque (matrix math inferred from call shape and the surrounding memcpy(64B)/glUniformMatrix4fv pattern, not byte-verified). The [sp,0xe3c]+0x34 ivar-offset indexing reads as a state-snapshot copy of the Shark fields; that framing is inferred. The per-block cube/texture identity was pinned by first-use cell addresses (bodyFront 0x7d05b4, bodyBack 0x7d0e0c, headTop 0x7d165c, headBottom 0x7d1ed0, topFin 0x7d2720, tailFinTop 0x7d2f70, tailFinBottom 0x7d37c0, sideFin 0x7d4024 + second sideFin 0x7d4958), but per-block matrix contents are not individually decoded; the two sideFin draws are labelled from the shared sideFinCube/sideFinTexture cells (the left/right reading is the plausible one, not proven).
- **census-lite grades**: sh_20's NPC-side helpers (tileAtWorldPositionLoaded, tileIsWater, seasonForWorldX, currentTemperatureForTileAtWorldPos, getWeatherFractionForPos:, getDayNightFractionForX:atWorldTime:) are pinned by cells and symbol names only - their bodies are outside this batch. sh_33's fast-enumeration loop was traced to all exit edges (found-flag semantics and the release/nil paths included) but side effects inside the Apple runtime enumeration itself are out of scope. sh_24's cube arg tuples are read off the O0 spilling map; the arg-to-field binding (w,h,d,cx,cy,cz,calculateNormals) follows the selector spelling.
- **Wire-struct naming**: SharkUpdateNetData field names are not enumerated; the observed byte offsets 0x18/0x1c (pos pair), 0x20 (s16 walkSpeed*255), 0x22 (u16 age), 0x24 (s8 movementDirection) are pinned by the store/load pair across sh_43 / sh_14 / sh_33 (255.0f multiplier and its inverse divisor both read from the ELF; age read back with ldrh vcvt.f32.u32, movementDirection with ldrsb, both from fp-0x1e/-0x20/-0x1c staging). The create-blob layout 0x48/0x28/8 is pinned the same way (sh_11 writes, sh_33 reads, length 0x78 both sides).
- **Boundary case**: sh_45's listing is trimmed at the next ObjC IMP 0x7dc93c (reactToBeingHit) while its ARM.exidx end is 0x7dca30 - recorded in roster.json boundary and noted in semantics. All other 46 bodies' boundaries come from the exidx/next-IMP rule with no trims; no body rows were dropped (47/47 rows == words for every body).
- **Strings** are quoted from the pinned ELF CFString objects (0xF90E98/0xF90EA8/0xF90EB8 tips, 0xF90EC8 shader, 0xF90EC8-0xF90FB8 texture pngs, 0xF90FC8 "jaws.wav", 0xF90FD8 "fishDie.wav", 0xF91028 "fishRun.wav", 0xF91038 "crunch.wav"); the 64-name table was walked to exactly 64 entries (last entry "Weasel"; the 0x40 count cross-checks sh_18). sh_40's 9000.0f divisor is what the pool cell holds - whether the source meant a different scale is not claimed.
- Static level-A evidence only (r2 pD + GNU objdump + ELF struct reads): no runtime roundtrip, no device-side rendering or netplay claims; the netcode roundtrip is demonstrated only as write/read pair equality of the byte offsets above.
