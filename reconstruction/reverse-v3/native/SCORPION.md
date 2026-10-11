# Scorpion (E143)

The Scorpion animal class lands: the AI tick, tail-strike/spit combat and the net round-trip. 42 bodies, 17765 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| sc_00 | Scorpion -[.cxx_construct] | 0x008ac49c | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_01 | Scorpion -[addRider:] | 0x008ac0b4 | 52 | 1 | 1 | 2 | 1 | 1 | 1 |
| sc_02 | Scorpion -[blockheadCanRide:usingItem:] | 0x008ac260 | 74 | 2 | 1 | 2 | 0 | 2 | 3 |
| sc_03 | Scorpion -[blockheadUnloaded:] | 0x008ac3a4 | 55 | 1 | 1 | 2 | 1 | 1 | 1 |
| sc_04 | Scorpion -[cameraPosForBlockhead:] | 0x008abeac | 25 | 1 | 0 | 0 | 1 | 1 | 0 |
| sc_05 | Scorpion -[canBeCapturedByBlockhead:withItemType:] | 0x008abb20 | 42 | 1 | 1 | 0 | 0 | 1 | 4 |
| sc_06 | Scorpion -[cantBeCapturedTipStringForBlockhead:withItemType:] | 0x008abbc8 | 124 | 4 | 3 | 0 | 1 | 6 | 7 |
| sc_07 | Scorpion -[captureRequiredItemType] | 0x008931bc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_08 | Scorpion -[capturedItemType] | 0x008931a0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_09 | Scorpion -[creationDataStructSize] | 0x00894820 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_10 | Scorpion -[creationNetDataForClient:] | 0x00894260 | 178 | 5 | 1 | 2 | 1 | 8 | 5 |
| sc_11 | Scorpion -[dealloc] | 0x00894614 | 131 | 2 | 2 | 7 | 1 | 8 | 0 |
| sc_12 | Scorpion -[die:] | 0x008a4448 | 106 | 4 | 2 | 3 | 2 | 4 | 2 |
| sc_13 | Scorpion -[doRemoteUpdate:] | 0x00895080 | 262 | 2 | 1 | 9 | 0 | 6 | 9 |
| sc_14 | Scorpion -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00895630 | 14029 | 13 | 3 | 31 | 0 | 255 | 63 |
| sc_15 | Scorpion -[foodItemType] | 0x00893184 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_16 | Scorpion -[getNamesArray] | 0x008931d8 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_17 | Scorpion -[getNamesArrayCount] | 0x00893208 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_18 | Scorpion -[hitWithForce:blockhead:] | 0x008ab644 | 133 | 2 | 2 | 7 | 1 | 3 | 2 |
| sc_19 | Scorpion -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] | 0x00893be0 | 94 | 2 | 1 | 0 | 1 | 2 | 2 |
| sc_20 | Scorpion -[initWithWorld:dynamicWorld:cache:netData:] | 0x00893e80 | 128 | 3 | 2 | 4 | 1 | 3 | 2 |
| sc_21 | Scorpion -[isUnderLocalControl] | 0x008ab4bc | 98 | 1 | 1 | 2 | 0 | 2 | 4 |
| sc_22 | Scorpion -[jumpsOnSwipe] | 0x008ac388 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_23 | Scorpion -[loadDerivedStuff] | 0x00893224 | 619 | 6 | 11 | 18 | 2 | 21 | 3 |
| sc_24 | Scorpion -[maxAge] | 0x00893124 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_25 | Scorpion -[maxHealth] | 0x008aaf70 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_26 | Scorpion -[npcType] | 0x00893108 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_27 | Scorpion -[reactToBeingFed] | 0x008ab8a0 | 160 | 4 | 3 | 5 | 2 | 7 | 0 |
| sc_28 | Scorpion -[reactToBeingHit] | 0x008ab3c8 | 61 | 3 | 1 | 2 | 1 | 3 | 1 |
| sc_29 | Scorpion -[remoteCreationDataUpdate:] | 0x0089483c | 529 | 9 | 2 | 11 | 1 | 15 | 32 |
| sc_30 | Scorpion -[remoteUpdate:] | 0x00895498 | 102 | 3 | 1 | 1 | 1 | 3 | 1 |
| sc_31 | Scorpion -[removeRider:] | 0x008ac184 | 55 | 1 | 1 | 2 | 1 | 1 | 1 |
| sc_32 | Scorpion -[renderPos] | 0x008ab858 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| sc_33 | Scorpion -[rideDirection] | 0x008abfb8 | 63 | 0 | 0 | 2 | 0 | 0 | 4 |
| sc_34 | Scorpion -[riderBodyYRotationForBlockhead:] | 0x008abf10 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| sc_35 | Scorpion -[riderPosForBlockhead:] | 0x008abdb8 | 61 | 1 | 0 | 0 | 0 | 7 | 2 |
| sc_36 | Scorpion -[riderRidesWithArmsDown] | 0x008ac480 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sc_37 | Scorpion -[scorpionUpdateNetDataForClient:] | 0x008940fc | 89 | 1 | 0 | 3 | 0 | 2 | 2 |
| sc_38 | Scorpion -[setTargetVelocity:] | 0x008abf54 | 25 | 0 | 0 | 1 | 0 | 1 | 0 |
| sc_39 | Scorpion -[speciesName] | 0x00893154 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| sc_40 | Scorpion -[tapIsWithinBodyRadius:] | 0x008aaf8c | 271 | 1 | 0 | 3 | 0 | 20 | 11 |
| sc_41 | Scorpion -[updateNetDataForClient:] | 0x00894528 | 59 | 2 | 1 | 0 | 1 | 3 | 2 |

## Findings (E143)

- **The Scorpion batch lands**: 42 bodies / 17,765 words / 164 branches / 386 call rows of `Scorpion` (NPC subclass, instance_size 360; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). Implementation span 0x893108..0x8ac4b4 (method order = pinned ObjC method-table order); roster names sc_00..sc_41, 0 collisions. Grades: 1 body >1000w [census] (sc_14 draw), 2 bodies 300-1000w [census-lite] (sc_23 loadDerivedStuff, sc_29 remoteCreationDataUpdate:), 39 bodies <=300w fully read. Mechanical layer regenerated this run: gen_listings.py (42 listings, entrypoint-warning lines only) + build_specs.py (42 bodies, 386 call rows, 31 routes).

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | sc_00 | `Scorpion -[.cxx_construct]` | 6 | 0 | 0 | read |
  | sc_01 | `Scorpion -[addRider:]` | 52 | 1 | 1 | read |
  | sc_02 | `Scorpion -[blockheadCanRide:usingItem:]` | 74 | 3 | 2 | read |
  | sc_03 | `Scorpion -[blockheadUnloaded:]` | 55 | 1 | 1 | read |
  | sc_04 | `Scorpion -[cameraPosForBlockhead:]` | 25 | 0 | 1 | read |
  | sc_05 | `Scorpion -[canBeCapturedByBlockhead:withItemType:]` | 42 | 4 | 1 | read |
  | sc_06 | `Scorpion -[cantBeCapturedTipStringForBlockhead:withItemType:]` | 124 | 7 | 6 | read |
  | sc_07 | `Scorpion -[captureRequiredItemType]` | 7 | 0 | 0 | read |
  | sc_08 | `Scorpion -[capturedItemType]` | 7 | 0 | 0 | read |
  | sc_09 | `Scorpion -[creationDataStructSize]` | 7 | 0 | 0 | read |
  | sc_10 | `Scorpion -[creationNetDataForClient:]` | 178 | 5 | 8 | read |
  | sc_11 | `Scorpion -[dealloc]` | 131 | 0 | 8 | read |
  | sc_12 | `Scorpion -[die:]` | 106 | 2 | 4 | read |
  | sc_13 | `Scorpion -[doRemoteUpdate:]` | 262 | 9 | 6 | read |
  | sc_14 | `Scorpion -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 14029 | 63 | 255 | census |
  | sc_15 | `Scorpion -[foodItemType]` | 7 | 0 | 0 | read |
  | sc_16 | `Scorpion -[getNamesArray]` | 12 | 0 | 0 | read |
  | sc_17 | `Scorpion -[getNamesArrayCount]` | 7 | 0 | 0 | read |
  | sc_18 | `Scorpion -[hitWithForce:blockhead:]` | 133 | 2 | 3 | read |
  | sc_19 | `Scorpion -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]` | 94 | 2 | 2 | read |
  | sc_20 | `Scorpion -[initWithWorld:dynamicWorld:cache:netData:]` | 128 | 2 | 3 | read |
  | sc_21 | `Scorpion -[isUnderLocalControl]` | 98 | 4 | 2 | read |
  | sc_22 | `Scorpion -[jumpsOnSwipe]` | 7 | 0 | 0 | read |
  | sc_23 | `Scorpion -[loadDerivedStuff]` | 619 | 3 | 21 | census-lite |
  | sc_24 | `Scorpion -[maxAge]` | 12 | 0 | 0 | read |
  | sc_25 | `Scorpion -[maxHealth]` | 7 | 0 | 0 | read |
  | sc_26 | `Scorpion -[npcType]` | 7 | 0 | 0 | read |
  | sc_27 | `Scorpion -[reactToBeingFed]` | 160 | 0 | 7 | read |
  | sc_28 | `Scorpion -[reactToBeingHit]` | 61 | 1 | 3 | read |
  | sc_29 | `Scorpion -[remoteCreationDataUpdate:]` | 529 | 32 | 15 | census-lite |
  | sc_30 | `Scorpion -[remoteUpdate:]` | 102 | 1 | 3 | read |
  | sc_31 | `Scorpion -[removeRider:]` | 55 | 1 | 1 | read |
  | sc_32 | `Scorpion -[renderPos]` | 18 | 0 | 0 | read |
  | sc_33 | `Scorpion -[rideDirection]` | 63 | 4 | 0 | read |
  | sc_34 | `Scorpion -[riderBodyYRotationForBlockhead:]` | 17 | 0 | 0 | read |
  | sc_35 | `Scorpion -[riderPosForBlockhead:]` | 61 | 2 | 7 | read |
  | sc_36 | `Scorpion -[riderRidesWithArmsDown]` | 7 | 0 | 0 | read |
  | sc_37 | `Scorpion -[scorpionUpdateNetDataForClient:]` | 89 | 2 | 2 | read |
  | sc_38 | `Scorpion -[setTargetVelocity:]` | 25 | 0 | 1 | read |
  | sc_39 | `Scorpion -[speciesName]` | 12 | 0 | 0 | read |
  | sc_40 | `Scorpion -[tapIsWithinBodyRadius:]` | 271 | 11 | 20 | read |
  | sc_41 | `Scorpion -[updateNetDataForClient:]` | 59 | 2 | 3 | read |

- **What the class is**: Scorpion is the desert scorpion NPC: npcType = 7, maxAge = 7200.0f, maxHealth = 20, foodItemType = 0x18 (24), speciesName = CFString "SCORPION" (obj 0xF93568). Capture economy: captureRequiredItemType = 0x12e (302), capturedItemType = 0x147 (327), creationDataStructSize = 0x80; capture gate = itemType==302 && belongsToPlayerWithBlockhead: (canBeCaptured...), tips from cantBeCapturedTip... ("%@S MUST BE TAMED
BEFORE YOU CAN CAPTURE THEM" / "THAT %@ BELONGS TO
SOMEONE ELSE"). It rides: addRider/removeRider zero riderTargetVelocity@340 (a scalar float, not Shark's Vector2), riderRidesWithArmsDown = 1 (true; cf. Shark 0), rideDirection = sign(riderTargetVelocity) with +/-0.1 dead zone, riderBodyYRotation = bodyRotation@276, riderPos = renderPos + (0, -0.15) at z=-0.25, renderPos = floatPos, cameraPos = pure super forward. Name pool = 22 entries (Muffet..Scorpio, table @0x01052148).
- **Combat model** (the scorpion-specific core): state ivars attackBlockhead@312 / attackDelay@316 / biting@320 / biteTimer@324 / spitting@328 / spitTimer@332 / provoked@336 mirror Shark's bite/attack idiom plus a spit channel. -[hitWithForce:blockhead:] runs on local control only: provoked=1; attackDelay=0; a lrand48 coin (r/2^31 > 0.5) picks movementDirection = 1 else -1; walkSpeed=3.0; randomTimeBetweenDirectionChanges=5.0; updateNeedsToBeSent=1. -[remoteCreationDataUpdate:] (census-lite) enumerates [world allBlockheadsIncludingNet] and re-binds attackBlockhead by uniqueID (keep/replace/release via retain), arming EXACTLY ONE timer from the wire's spitting byte (buf+0x78): spitting=1 & spitTimer=0, else biting=1 & biteTimer=0; non-net instances set updateNeedsToBeSent; walkSpeed = max(walkSpeed, 3.0); uid==0 clears attackBlockhead. -[reactToBeingFed] plays "scorpionFire.wav" (0.6s) + "crunch.wav" (0.1s) and stops (movementDirection=0, walkSpeed=0, randomGoalRotation=1.0, walkTimer=0); -[reactToBeingHit] plays "scorpionFire.wav" (0.1s); -[die:] plays "scorpionAttack.wav" (0.1s) and zeroes travelFraction before [super die:].
- **Net protocol**: scorpionUpdateNetData for the wire = 0x28 bytes: [0..0x18) npcUpdateNetData (NPC base), +0x18/+0x1c toSquare@260 pair, +0x20 (s16)(walkSpeed*255.0f), +0x22 (s8)movementDirection (sc_37 writer; sc_13/sc_30 reader). creationNetDataForClient: = 0x80 bytes: [0..0x48) npcCreationNetData, [0x48..0x70) scorpionUpdateNetData, [0x70..0x78) attackBlockhead.uniqueID qword, [0x78] spitting byte (only when attackBlockhead!=nil; no isNet guard). -[doRemoteUpdate:] (server branch) applies the pair to remoteGoalSquare@344 + walkSpeed/remoteWalkSpeed = w8/255 + movementDirection/remoteMovementDirection, and only under (rider && [rider isNet]); client branch requires (rider==nil || [rider isNet]) && (attackBlockhead==nil || [attackBlockhead isNet]) and updates remote mirrors only. -[remoteUpdate:] is a straight getBytes(0x28)+doRemoteUpdate forwarder; -[updateNetDataForClient:] wraps scorpionUpdateNetDataForClient: output in NSData. Scanner note: sc_13/sc_29/sc_30 pass the 0x28 struct as w0/w1 in r2/r3 + w2..w9 on the stack (AAPCS split; consistent across the three bodies).
- **init/dealloc**: both initializers delegate to super and then [self loadDerivedStuff] (8-arg initWith... additionally passes through nil-check only - no Shark-style terrain/temperature validation; initWithWorld:dynamicWorld:cache:netData: sets remoteGoalSquare=pos, remoteWalkSpeed=0, remoteMovementDirection=0 then remoteCreationDataUpdate:). dealloc releases the 7 DrawCubes (body, tailA-D, leg, arm) and nothing else - textures, shader and attackBlockhead are not released (cf. Shark dealloc releases attackBlockhead).
- **loadDerivedStuff (census-lite, 619w)**: shader "ShadedWorldObject" with attributes [position,texCoord,normal] and uniforms [mvp_matrix,texture,light,normal_matrix]; bodyTexture = scorpion.png, legTexture = scorpionLeg.png; DrawCube tuples (floats passed in GPRs per the tsv type strings): body (0.8,0.3,0.4,n) [4-arg], tailA (5.0,0.2,0.12, 0.0,0.1,0.175, n), tailB (0.4,0.15,0.3, 0.0,0.075,0.15, n), tailC (0.12,0.27,0.06, 0.0,0.135,0.35, n), tailD (5.0,0.1,0.1, 0.0,0.05,0.05, n), leg (0.1,0.3,0.1, 0.05,2.0,0.05, n), arm (0.4,0.15,0.3, 0.4,0.075,0.15, n). Movement seeds: movementDirection from lrand48()/2^31 > 0.75 -> 1, < 0.25 -> -1 else 0; fromSquare=toSquare=pos; travelFraction=1.0; rTBDC=0.0; walkSpeed = (lrand48()/2^31 + 2.0) * 2.0 (uniform [4,6)) - double 0.75/0.25 read from GL truth.
- **draw (census, 14029w / 63 br / 255 calls)**: enormous O0 frame (sub sp 0x8e0 + 0x3000, bic sp,#0xf; arenas at sp+0x1000/0x2000/0x3000/0x3400). Head does toroidal dx/dy wraps against worldWidthMacro*32 and several early-outs (target 0x8a3140, past glDisable) incl. tileAtWorldPosition ground probe; then matrix compose loops, 4 conditional 64B memcpys, 5 sinf (walk/tail sway phase) + 2 fmodf(angle,1.0)*4 wrap calls. GL: glUseProgram(shader.program); glUniform1i(uniformLocations[1],0); dayColor stret -> glUniform4f(uniformLocations[2], dayColor.rgb, 1.0); glEnableVertexAttribArray(2); glBindTexture(GL_TEXTURE_2D, bodyTexture). 12 cube blocks (matrix compose + memcpy64 + glUniformMatrix4fv(mvp) + glUniformMatrix4fv(normal_matrix) + [cube draw] = 26 glUniformMatrix4fv) with cube identity pinned by cell loads: B1 bodyCube, B2-B5 tailCubeA-D, B6 armCube (legTexture bound just before), B8 legCube; a tail sequence re-draws legCube (cell 0x8a3160, x2) and ends glDisableVertexAttribArray(2). vmov constants 0.5/1.0/-0.5/5.0/4.0 and movw/movt float bits 0.35/0.45/0.3/0.26/-0.25/etc; only 13 selector cells + 31 ivar cells + 3 import cells (most code uses base+offset against the spilled frame).

## Boundaries

- **sc_14 is census grade**: call histogram + constant scan + sampled windows define the semantics; the matrix-compose helper family (0x8a3e88/0x8a3908/0x8a31d8/0x8a3af0/0x8a3570/0x8a3164) stays opaque (matrix math inferred from call shape, arg counts and the surrounding memcpy(64B)/glUniformMatrix4fv pattern). The per-block cube identity is pixel-pinned only for blocks whose cube comes from a pool-cell load (bodyCube, tailCubeA-D, armCube, legCube); blocks B7/B9-B12 and the two tail draws reuse stack-spilled cube pointers, so their exact leg/arm repetition counts are read from draw-send counts, not per-block byte-verified. The exact per-block matrix arguments are not enumerated.
- **sc_23 is census-lite**: cube argument tuples are read off the O0 spill map (rows 144-167) after GL-truth correction of VFP immediates; the raw source of each spilled slot is a register copy from a function-head load, so tuples are reconstructed, not byte-verified per call. The 4-arg vs 8-arg initWith ABI (floats in GPRs) was pinned against the ObjC tsv type strings (@24@0:4f8f12f16c20 / @36@...c32). legCube cy=2.0 and tailCubeA/D W=5.0 are as-read from the spill slots (quirks of the O0 staging; values not cross-checked against the atlas).
- **sc_29 is census-lite**: the fast-enumeration plumbing (state buffer fp-0xd8 = 32B, mutation guard, loop re-entry at 0x894b14 / 0x894e34) is described structurally; the per-blockhead body is decoded fully (uid compare, attackBlockhead keep/replace/release, single timer arm, walkSpeed clamp, updateNeedsToBeSent gate). The uid==0 path and all loop-exit paths converge on doRemoteUpdate(buf+0x48). No break in the loop after a match (verified by the loop-continue edge at 0x894e3c-0x894e4c).
- **Wire struct field names are not enumerated**: ScorpionUpdateNetData layout is inferred from writer (sc_37) / readers (sc_13, sc_30, sc_29) offset equality; the 0x48/0x80 NPC blobs stay inside npcCreationNetDataForClient:/appendNPCCreationDataToData: (NPC base, outside this batch). w9 of the 0x28 struct (+0x24) is padding in this writer (sc_37 stores only up to +0x22).
- **r2 vs GNU truth**: VFP immediates in the r2 listings are systematically misleading (vmov.f64 d2,#5 really 0.5; vmov.f32 s0,-2 really -0.25; movw/movt pairs are truth for r-forms); all float thresholds quoted here (0.1/0.25/0.5/0.75/1.0/255/2^31) were read from _gl.txt or via ELF word reads. sc_18's `mvn` (not `mov`) was GL-verified (mvneq r7,#0 = -1).
- **sc_40 wrap thresholds**: the wrap constant W = worldWidthMacro*32 and the divisor 2 are as-read; the dead constant 5 (stored to fp-0x24/others) is unused by any comparison - noted as an O0 artifact, not intent. Note this method ignores movementDirection (Shark's version was direction-aware).
- **Boundary trims** (roster.json): the shared exidx ends span several methods, so 8 bodies were trimmed at the next IMP (boundary case 2): sc_07 -> 0x8931d8, sc_08 -> 0x8931bc, sc_15 -> 0x8931a0, sc_16 -> 0x893208, sc_39 -> 0x893184, sc_36 -> 0x8ac49c (.cxx_construct), sc_28 -> 0x8ab4bc (isUnderLocalControl), sc_40 -> 0x8ab3c8 (reactToBeingHit). No body rows were dropped anywhere (rows == words for every body).
- **Null-guard oddity**: sc_10/sc_29/sc_41 compile-time checks are against self (O0 struct-return artifact); the real receivers are self/stret buffers. sc_30's dead-branch (else) does nothing where Shark sh_34 cleared needsRemoved - stated as read.
- Static level-A evidence only (r2 pD + GNU objdump + ELF struct reads + BL-caller scans for helpers 0x893bd0=lrand48 wrapper and 0x8a3e88-family): no runtime roundtrip, no device-side rendering/netplay claims.
