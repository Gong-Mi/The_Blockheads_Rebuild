# Boat (E148)

The Boat vehicle lands: the mast/sail geometry emitters, the sailing physics and the remote-control round-trip. 35 bodies, 9565 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| bo_00 | Boat -[.cxx_construct] | 0x00977f2c | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_01 | Boat -[actionTitle] | 0x0097772c | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| bo_02 | Boat -[actsAsInteractionObject] | 0x00977da8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_03 | Boat -[addRider:] | 0x00976de8 | 267 | 8 | 1 | 7 | 0 | 9 | 9 |
| bo_04 | Boat -[blockheadCanRide:usingItem:] | 0x0096dc38 | 39 | 0 | 0 | 2 | 0 | 0 | 1 |
| bo_05 | Boat -[blockheadUnloaded:] | 0x00977dc4 | 83 | 1 | 1 | 4 | 0 | 1 | 1 |
| bo_06 | Boat -[blockheadsLoaded] | 0x0096be3c | 255 | 8 | 1 | 6 | 0 | 9 | 6 |
| bo_07 | Boat -[cameraPosForBlockhead:] | 0x00977568 | 107 | 2 | 0 | 2 | 0 | 6 | 2 |
| bo_08 | Boat -[creationNetDataForClient:] | 0x0096c674 | 200 | 7 | 2 | 3 | 2 | 9 | 4 |
| bo_09 | Boat -[dealloc] | 0x0096cb54 | 113 | 3 | 2 | 5 | 1 | 6 | 0 |
| bo_10 | Boat -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00970180 | 5837 | 17 | 2 | 15 | 0 | 156 | 44 |
| bo_11 | Boat -[freeblockCreationItemType] | 0x0096b510 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_12 | Boat -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:] | 0x0096b548 | 180 | 4 | 2 | 3 | 1 | 7 | 6 |
| bo_13 | Boat -[initWithWorld:dynamicWorld:cache:netData:] | 0x0096bab8 | 216 | 8 | 3 | 4 | 1 | 11 | 3 |
| bo_14 | Boat -[isDoubleHeight] | 0x0097775c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_15 | Boat -[jumpsOnSwipe] | 0x00977c80 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_16 | Boat -[loadDerivedStuff] | 0x0096aedc | 397 | 5 | 11 | 11 | 2 | 15 | 1 |
| bo_17 | Boat -[maxHealth] | 0x00976c00 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_18 | Boat -[remoteUpdate:] | 0x0096cd18 | 968 | 10 | 2 | 8 | 1 | 34 | 53 |
| bo_19 | Boat -[removeRider:] | 0x00977214 | 180 | 5 | 1 | 7 | 0 | 5 | 5 |
| bo_20 | Boat -[renderPos] | 0x00976c1c | 31 | 0 | 0 | 1 | 0 | 2 | 0 |
| bo_21 | Boat -[requiresFuel] | 0x00977d8c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_22 | Boat -[rideDirection] | 0x00977c9c | 60 | 0 | 0 | 2 | 0 | 0 | 4 |
| bo_23 | Boat -[riderBodyYRotationForBlockhead:] | 0x009774f8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| bo_24 | Boat -[riderBodyZRotation] | 0x0097753c | 11 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_25 | Boat -[riderDPadShouldAllowUpDown] | 0x00977f10 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_26 | Boat -[riderDPadShouldGiveDiscreteValues] | 0x00976dcc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_27 | Boat -[riderPosForBlockhead:] | 0x00976c98 | 48 | 0 | 0 | 1 | 0 | 3 | 0 |
| bo_28 | Boat -[setNeedsRemoved:] | 0x00977b78 | 66 | 2 | 2 | 2 | 1 | 2 | 2 |
| bo_29 | Boat -[setTargetVelocity:] | 0x00976d58 | 29 | 0 | 0 | 1 | 0 | 1 | 0 |
| bo_30 | Boat -[swipeUpGesture] | 0x009774e4 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| bo_31 | Boat -[tapIsWithinBodyRadius:] | 0x00977778 | 256 | 1 | 0 | 2 | 0 | 20 | 9 |
| bo_32 | Boat -[updateNetDataForClient:] | 0x0096cb00 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| bo_33 | Boat -[updatePosition:] | 0x0096dcd4 | 99 | 3 | 1 | 3 | 1 | 3 | 3 |
| bo_34 | Boat -[worldChanged:] | 0x00977714 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |

## Findings (E148)

- **The Boat batch lands**: 35 bodies / 9565 words / 300 call rows / 28 routes of `Boat` (DynamicObject subclass, `instance_size` 144; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). Implementation span 0x96aedc..0x977f44 (targets ordered by selector name, not address; the class's remaining methods -- `objectType`, `initWithWorld:dynamicWorld:saveDict:cache:`, `getSaveDict`, `update:accurateDT:isSimulation:` -- are NOT in this batch and sit between/after the batch IMPs). Roster names bo_00..bo_34, 0 name collisions (no pre-existing `disasm_*_bo_*` files). Mechanical layer regenerated this run: `gen_listings.py` ("bodies 35 words 9565", entrypoint warnings only) + `build_specs.py` (35 bodies, 300 call rows, 28 routes). Listing rows == word count for every body (verified programmatically: 0 mismatches). 6 bodies TRIMMED at the next IMP (bo_01, bo_11, bo_20, bo_21, bo_25, bo_27). Grades: **bo_10 [census]** (5837w); 2 [census-lite] (bo_16 397w, bo_18 968w); 32 bodies <=291w fully read.

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
| bo_00 | `-[.cxx_construct]` | 6 | 0 | 0 | read |
| bo_01 | `-[actionTitle]` | 12 | 0 | 0 | read |
| bo_02 | `-[actsAsInteractionObject]` | 7 | 0 | 0 | read |
| bo_03 | `-[addRider:]` | 267 | 9 | 9 | read |
| bo_04 | `-[blockheadCanRide:usingItem:]` | 39 | 1 | 0 | read |
| bo_05 | `-[blockheadUnloaded:]` | 83 | 1 | 1 | read |
| bo_06 | `-[blockheadsLoaded]` | 255 | 6 | 9 | read |
| bo_07 | `-[cameraPosForBlockhead:]` | 107 | 2 | 6 | read |
| bo_08 | `-[creationNetDataForClient:]` | 200 | 4 | 9 | read |
| bo_09 | `-[dealloc]` | 113 | 0 | 6 | read |
| bo_10 | `-[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 5837 | 44 | 156 | census |
| bo_11 | `-[freeblockCreationItemType]` | 7 | 0 | 0 | read |
| bo_12 | `-[initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:]` | 180 | 6 | 7 | read |
| bo_13 | `-[initWithWorld:dynamicWorld:cache:netData:]` | 216 | 3 | 11 | read |
| bo_14 | `-[isDoubleHeight]` | 7 | 0 | 0 | read |
| bo_15 | `-[jumpsOnSwipe]` | 7 | 0 | 0 | read |
| bo_16 | `-[loadDerivedStuff]` | 397 | 1 | 15 | census-lite |
| bo_17 | `-[maxHealth]` | 7 | 0 | 0 | read |
| bo_18 | `-[remoteUpdate:]` | 968 | 53 | 34 | census-lite |
| bo_19 | `-[removeRider:]` | 180 | 5 | 5 | read |
| bo_20 | `-[renderPos]` | 31 | 0 | 2 | read |
| bo_21 | `-[requiresFuel]` | 7 | 0 | 0 | read |
| bo_22 | `-[rideDirection]` | 60 | 4 | 0 | read |
| bo_23 | `-[riderBodyYRotationForBlockhead:]` | 17 | 0 | 0 | read |
| bo_24 | `-[riderBodyZRotation]` | 11 | 0 | 0 | read |
| bo_25 | `-[riderDPadShouldAllowUpDown]` | 7 | 0 | 0 | read |
| bo_26 | `-[riderDPadShouldGiveDiscreteValues]` | 7 | 0 | 0 | read |
| bo_27 | `-[riderPosForBlockhead:]` | 48 | 0 | 3 | read |
| bo_28 | `-[setNeedsRemoved:]` | 66 | 2 | 2 | read |
| bo_29 | `-[setTargetVelocity:]` | 29 | 0 | 1 | read |
| bo_30 | `-[swipeUpGesture]` | 5 | 0 | 0 | read |
| bo_31 | `-[tapIsWithinBodyRadius:]` | 256 | 9 | 20 | read |
| bo_32 | `-[updateNetDataForClient:]` | 21 | 0 | 1 | read |
| bo_33 | `-[updatePosition:]` | 99 | 3 | 3 | read |
| bo_34 | `-[worldChanged:]` | 6 | 0 | 0 | read |

- **What the class is**: Boat is the drivable sailboat (DynamicObject subclass). It stores five `DrawCube` geometry parts (frontBack@68, side@72, bottom@76, mast@80, sail@84), two textures (boat.png@60, sail.png@64), the `ShadedWorldObject` shader@56, and a small sailing-physics state: `bodyRotation@88`/`prevRotation@92` (float), `goalRotationType@96` (int), `targetXSpeed@100`/`actualXSpeed@104`/`ySpeed@108` (float), `beingControlled@112` (char), `rider@116` (Blockhead*), `savedBlockheadIndex@120` (int, -1 sentinel), `bobTimer@124`, `falling@128`, `remoteGoalPos@132` (intpair), `remoteSendControlEventTimer@140`.
- **Identity / constants**: `actionTitle` = static CFString **"EMBARK"** @0xF95848 (bo_01; hardcoded, not [self title]); `maxHealth` = **32** (bo_17); `freeblockCreationItemType` = **0x6f = 111** (bo_11); `actsAsInteractionObject` = **nil** (bo_02); `isDoubleHeight` = 0 (bo_14), `jumpsOnSwipe` = 0 (bo_15), `requiresFuel` = 0 (bo_21), `riderDPadShouldAllowUpDown` = 0 (bo_25), `riderDPadShouldGiveDiscreteValues` = 0 (bo_26); `swipeUpGesture` and `worldChanged:` are empty stubs (bo_30/bo_34); `.cxx_construct` is a no-op that returns self (bo_00).
- **Rider lifecycle (boarding)**: `blockheadCanRide:usingItem:` (bo_04) = `beingControlled ? NO : !needsRemoved` -- both arguments ignored, no super call. `addRider:` (bo_03) is the full boarding routine: a client-controlled-server rider is first stopRiding-ed and cleared; then `rider==self.rider` is a no-op; a `updateNeedsToBeSent` gate (set when `![dynamicWorld isClient] || (old rider non-net)`) precedes `self.rider=[rider retain]`, the `dynamicWorldChangedAtPos:objectType:` notification, and a second flag gate over the new rider; the tail sets `beingControlled=(rider!=nil)` and zeroes both speed ivars when unrider-ed (0.0f pool 0x977204). `removeRider:` (bo_19) mirrors it (same flag gate text, autorelease+nil+notification, same tail), and `blockheadUnloaded:` (bo_05) is the bare version: match rider -> autorelease, nil, beingControlled=0, speeds 0 -- no notification, no flag. `blockheadsLoaded` (bo_06) restores the saved rider from `[[self dynamicWorld] blockheads]` by `savedBlockheadIndex@120` (skip on -1, bounds-checked `>=0 && <[arr count]`, `[[arr objectAtIndex:idx] retain]`), resets the index to -1, then either stopRiding+clear (rider isClientBlockheadBeingControlledByServer) or `beingControlled=1 + [self.rider setRidingObject:self]`. `setNeedsRemoved:` (bo_28) calls `[self.rider stopRiding]` on the 0->1 edge before calling super.
- **Sailing physics (steering + motion)**: `setTargetVelocity:` (bo_29) = `targetXSpeed = v.x * 6.0f`; `rideDirection` (bo_22) = sign of targetXSpeed with a **+/-2.0f** dead band (0 when no rider); `updatePosition:` (bo_33) calls `[self.world markCircumNavigateX:newPos.x]` when the boat is ridden locally and the x actually changed, then supers; `renderPos` (bo_20) = `floatPos + (0, -0.3f)`; `riderPosForBlockhead:` (bo_27) = `Vector(floatPos.x, floatPos.y-0.9, -0.75f)`; `riderBodyYRotationForBlockhead:` (bo_23) = `bodyRotation` and `riderBodyZRotation` (bo_24) = 0.0f; `cameraPosForBlockhead:` (bo_07) = `renderPos + Vector2(targetXSpeed*0.2*(W+240)/320, (W+240)*0.5/320)` with W = first float of `[[self.world windowInfo]]` (f64 0.2/320.0 consts) -- a look-ahead camera along the boat's target speed. `tapIsWithinBodyRadius:` (bo_31) is the world-wrapped tap test: `dx` is wrapped by `worldWidthMacro*32` (halfW = `(worldWidthMacro*32)/2`, integer idiv), and the tap counts only inside `-0.5 < dx < 0.5` and `floatPos.y +/- 0.5` (f64 0.5 comparisons).
- **Net protocol**: writer `creationNetDataForClient:` (bo_08) builds a 0x28-byte blob = `[self dynamicObjectNetData]` (24-byte DynamicObjectNetData record, `{Q uniqueID; I; I; C; C[7]}`, E116 dob_06) + rider uniqueID (u64 @+0x18..0x1f, 0 when no rider) + `(int16)(actualXSpeed*255.0f)` @+0x20 (bytes +0x22..0x27 uninitialized), then `NSMutableData dataWithBytes:length:0x28`, an extra dict holding only `ownerID` (CFSTR @0xf95828) via `[dict setObject:self.ownerID forKey:]`, serialized by local plist helper 0x96c994 (`dataWithPropertyList:format:100 options:0`, the XML plist format) and appended `gzipDeflate`-ed. `updateNetDataForClient:` (bo_32) is a pure forward. Reader `initWithWorld:dynamicWorld:cache:netData:` (bo_13) supers, calls loadDerivedStuff, seeds `remoteGoalPos=pos`, sets `floatPos.y = pos.y+0.5f`, and on `[netData length] > 0x28` inflates the `{0x28, len-0x28}` subdata (plist helper 0x96be18 -> 0x9780e4) to pull `ownerID`, then `[self remoteUpdate:netData]`. `remoteUpdate:` (bo_18) spawns separate **server** and **client** interpretations of the same buffer (branch on `[[self dynamicWorld] isClient]`), both decoding `actualXSpeed@104 = (s16)buf[0x20]/255.0f` and `remoteGoalPos = makeIntpair(buf[8], buf[0xc])` with `remoteGoalPos.x += (int)(actualXSpeed*0.2f)`, both detaching a stale **non-net** rider whose uniqueID no longer matches the packet (stopRiding, autorelease, rider=nil, speeds*/flag reset), and both fast-enumerating `[[self dynamicWorld] allBlockheadsIncludingNet]` to re-attach the net blockhead named by packet bytes +0x18..+0x1f (`[self addRider:b]; beingControlled=1`). Only the server path raises `updateNeedsToBeSent`.
- **Render assets (loadDerivedStuff, bo_16)**: shader `ShadedWorldObject` fetched via `[self.cache shaderNamed:attributes:uniforms:]` with attributes `position/texCoord/normal` and uniforms `mvp_matrix/texture/light/normal_matrix`; textures `boat.png` and `sail.png` via `[self.cache textureNamed:]`; five DrawCubes, all `calculateNormals=YES`: frontBack **0.8 x 0.5 x 0.1**, side **0.1 x 0.5 x 1.8**, bottom **0.8 x 0.1 x 1.8**, mast **0.1 x 2.4 x 0.1**, sail **0.05 x 1.0 x 1.4**; tail sets `goalRotationType=0` and `bodyRotation=pi`.
- **dealloc** (bo_09) releases frontBackCube/sideCube/bottomCube/ownerID/rider and supers -- shader/texture/sailTexture/mastCube/sailCube are not released in this body.
- **draw: (bo_10, census)**: a 5837-word, 44-branch, 156-call straight-line renderer: (A) four world-wrap clamp blocks around `[self.world worldWidthMacro]*32` + `__aeabi_idiv`; (B) render-position Vector2 math + `[self.world macroTiles]` neighbour scan + `tileAtWorldPosition`; (C) local helper 0x975cb4; (D) a **fishing-rod lean**: when `[self.rider fishingRod]`'s `isInCastingAnimation` or `hookInAir` is set, the stored lean double becomes **+pi/2 @0x970f10 / -pi/2 @0x970f08** depending on `castingRight`, else 0.0 @0x970f18; (E) matrix helpers 0x975d28/0x9760c0 (230w twins) + memcpy; (F) `[[self.shader program]` -> `glUseProgram` @0x97132c, then `glUniform1i`, `glEnableVertexAttribArray`, `[self.world dayColor]` (objc_msgSend_stret, memset 0x10 in nil path) @0x971438/0x971468, vector light math and **glUniform4f** @0x971ae8; (G) seven per-part blocks -- bottom, side x2, frontBack x2, mast, sail -- each: 2x bl 0x976458 (a 368w pure-VFP matrix builder with zero calls) + `[shader uniformLocations]/objectAtIndex:/intValue` chain + 2x **glUniformMatrix4fv** + `[self.<cube> draw]`; textures bound with `glBindTexture(0xde1=GL_TEXTURE_2D)` for bottom (boat.png, 0x972230) and mast (sail.png, 0x975228); six blocks additionally call helper 0x976a18 (122w pure vector transform, zero calls; colour consts 0.9f/0.5f, 1.2f/0.5f in its param record); the sail block ends with `glDisableVertexAttribArray` @0x975c84.
- **Local helpers (out-of-batch, read-only cross-refs)**: 0x96c994 plist-from-dict (called by bo_08), 0x96be18 -> 0x9780e4 plist-from-data (called by bo_13), 0x976458 pure-VFP matrix builder (14 calls, zero calls out), 0x976a18 vector transform (6 calls, zero calls out), 0x975d28 / 0x9760c0 matrix twins (called once each; 0x975d28 calls 0x978014 + 0x976458), 0x975cb4 29w memcpy helper (1 call). Shared C helpers: makeIntpair @0x4b49fc, DynamicObjectNetData = {Q uniqueID; I; I; C; C[7]} 24B (E116 dob_06).

## Boundaries

- **Grades**: bo_10 (5837w) is the batch's [census] body -- decoded to the structural level (phase map, call groups, constant truth, texture/shader sequence, the 7-part draw order with the two repeated cubes); its per-argument float expressions inside the big stack records are NOT unfolded instruction-by-instruction, and its ~16 indirect `blx rN` sites (register-target objc_msgSend) are listed as call rows but their dynamic receivers are not statically resolvable. bo_16 (397w) and bo_18 (968w) are [census-lite] and were nevertheless read instruction-by-instruction (all branches and call rows traced); the remaining 32 bodies are <=291w and were fully read.
- **Trimmed bodies (6)**: bo_01, bo_11, bo_20, bo_21, bo_25, bo_27 end at the next ObjC IMP rather than the ARM.exidx bound. All 35 listings have rows == word count (verified programmatically), so no rows were dropped.
- **bo_08 blob quirk**: the wire buffer is 0x28 bytes (`dataWithBytes:length:0x28`, movw verified) but only 0x22 bytes are explicitly written (24B base record + 8B rider UID + s16 speed); bytes 0x22..0x27 are stack garbage in the non-nil path (zeroed only via the nil-self memset of the base record). The reader consumes +0x18/+0x1c (UID), +0x20 (speed) and the subdata offset 0x28, so the padding is never read by any batch body.
- **bo_18 no-break enumeration**: the `allBlockheadsIncludingNet` fast-enumeration that re-attaches a rider has no early exit after the matching blockhead (flow falls through the loop increment) -- transcribed as compiled, no `break` is invented.
- **bo_10 cross-batch matrix semantics**: the 0x18-byte prefix of the boat's net record is `[self dynamicObjectNetData]` (E116 dob_06, 89w); this batch reads/writes offsets +0x08/+0x0c as the goal-position pair and +0x18.. as the boat extension, but dob_06's internal field roles are only cross-referenced, not re-derived here.
- **Receiver/selector staging in bo_10**: several selectors and ivar-slot pointers are staged in stack slots ([sp,0x5f0] = SEL `draw`, [sp,0x514] = sideCube slot, [sp,0x368] = frontBackCube slot); the repeated cube draws (sideCube x2, frontBackCube x2) are evidenced by those staged slot pointers, and the fishing-rod selectors (`fishingRod`, `isInCastingAnimation`, `hookInAir`, `castingRight`) are reached through `[self.rider ...]` for the first hop only -- deeper rod state is out of batch.
- **bo_04/bo_31 argument semantics**: `blockheadCanRide:usingItem:` ignores both arguments; `tapIsWithinBodyRadius:` receives the tap Vector2 by value and ignores none, but the intended coordinate space of the tap (screen vs world) is not resolvable from this body alone.
- **Pool-word truth**: every float/double constant quoted above was read by direct ELF `struct.unpack` (file offset == vaddr) and cross-checked against the GNU objdump `_gl.txt` annotations (r2 pool-row disassembly was not used for any value statement); bo_03/05/06/19 zeroes (0.0f), bo_07 0.2/320.0/240.0, bo_18 255.0/0.2, bo_16 cube dims and pi, bo_10 pi/2 pair and vector pool were all value-verified.
- **Formula transcription vs runtime**: the addRider:/removeRider:/remoteUpdate: gate logic and the draw phase map are mechanical transcriptions of compiled control flow; no runtime roundtrip, device-side claim or visual-behavior claim is made. Static level-A evidence only (r2 pD + GNU objdump + ELF struct reads + tsv types + class_metadata).
- **Cross-class receivers not traced**: `dynamicWorldChangedAtPos:objectType:`, `markCircumNavigateX:`, `stopRiding`, `setRidingObject:`, `isClientBlockheadBeingControlledByServer`, `allBlockheadsIncludingNet`, `blockheads`, `worldWidthMacro`, `macroTiles`, `fishingRod` family, `dayColor`, `program`, `uniformLocations`/`objectAtIndex:`/`intValue`, `name`, `draw`, `textureNamed:`, `shaderNamed:attributes:uniforms:`, `initWithWidth:height:depth:calculateNormals:`, `gzipDeflate`, `gzipInflate`, `subdataWithRange:`, `getBytes:length:` and the BitmapFont/BitmapString-free render APIs are call targets on other classes/system frameworks -- only selector/argument routing is evidence here.
