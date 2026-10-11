# ClownFish (E144)

The ClownFish animal class lands: the water AI tick, the fishing-rod hook chain and the four-slot remote update queue. 34 bodies, 9587 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| clf_00 | ClownFish -[.cxx_construct] | 0x0079c14c | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_01 | ClownFish -[blockheadUnloaded:] | 0x0079be1c | 56 | 2 | 1 | 1 | 0 | 2 | 1 |
| clf_02 | ClownFish -[canBeCapturedByBlockhead:withItemType:] | 0x0078dc38 | 56 | 2 | 1 | 0 | 0 | 2 | 5 |
| clf_03 | ClownFish -[cantBeCapturedTipStringForBlockhead:withItemType:] | 0x0078dd18 | 122 | 4 | 3 | 0 | 1 | 6 | 6 |
| clf_04 | ClownFish -[captureRequiredItemType] | 0x0078d42c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_05 | ClownFish -[capturedItemType] | 0x0078d410 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_06 | ClownFish -[clownFishUpdateNetDataForClient:] | 0x0078e7e8 | 89 | 1 | 0 | 3 | 0 | 2 | 2 |
| clf_07 | ClownFish -[creationDataStructSize] | 0x0078f5b8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_08 | ClownFish -[creationNetDataForClient:] | 0x0078e94c | 131 | 4 | 1 | 0 | 1 | 8 | 4 |
| clf_09 | ClownFish -[dealloc] | 0x0078ec44 | 119 | 4 | 2 | 4 | 1 | 6 | 0 |
| clf_10 | ClownFish -[die:] | 0x00796ff8 | 194 | 6 | 3 | 6 | 2 | 8 | 6 |
| clf_11 | ClownFish -[doRemoteUpdate:] | 0x0078ee20 | 190 | 1 | 1 | 9 | 0 | 2 | 3 |
| clf_12 | ClownFish -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x0078f5d8 | 6419 | 16 | 3 | 34 | 1 | 161 | 75 |
| clf_13 | ClownFish -[foodItemType] | 0x0078d3a8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_14 | ClownFish -[getNamesArray] | 0x0078d3c4 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_15 | ClownFish -[getNamesArrayCount] | 0x0078d3f4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_16 | ClownFish -[hitWithForce:blockhead:] | 0x0079b96c | 99 | 1 | 1 | 5 | 1 | 2 | 2 |
| clf_17 | ClownFish -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] | 0x0078df00 | 328 | 7 | 1 | 3 | 1 | 14 | 13 |
| clf_18 | ClownFish -[initWithWorld:dynamicWorld:cache:netData:] | 0x0078e548 | 137 | 3 | 2 | 4 | 1 | 3 | 4 |
| clf_19 | ClownFish -[loadDerivedStuff] | 0x0078d448 | 504 | 6 | 12 | 17 | 2 | 14 | 5 |
| clf_20 | ClownFish -[maxAge] | 0x0078d348 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_21 | ClownFish -[maxHealth] | 0x0079b3e4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_22 | ClownFish -[npcType] | 0x0078d32c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_23 | ClownFish -[reactToBeingFed] | 0x0079bf18 | 141 | 4 | 3 | 3 | 2 | 7 | 0 |
| clf_24 | ClownFish -[reactToBeingHit] | 0x0079b83c | 76 | 3 | 1 | 3 | 1 | 3 | 1 |
| clf_25 | ClownFish -[remoteBlockheadHookedYou:] | 0x0079bc7c | 104 | 5 | 1 | 1 | 0 | 5 | 3 |
| clf_26 | ClownFish -[remoteCreationDataUpdate:] | 0x0078f368 | 148 | 4 | 2 | 4 | 1 | 4 | 5 |
| clf_27 | ClownFish -[remoteUpdate:] | 0x0078f118 | 148 | 4 | 2 | 4 | 1 | 4 | 5 |
| clf_28 | ClownFish -[renderPos] | 0x0079baf8 | 33 | 0 | 0 | 2 | 0 | 2 | 0 |
| clf_29 | ClownFish -[ridableWhenTamed] | 0x0079befc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| clf_30 | ClownFish -[setNeedsRemoved:] | 0x0079bb7c | 64 | 2 | 2 | 1 | 1 | 2 | 0 |
| clf_31 | ClownFish -[speciesName] | 0x0078d378 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| clf_32 | ClownFish -[tapIsWithinBodyRadius:] | 0x0079b400 | 271 | 1 | 0 | 3 | 0 | 20 | 11 |
| clf_33 | ClownFish -[updateNetDataForClient:] | 0x0078eb58 | 59 | 2 | 1 | 0 | 1 | 3 | 2 |

## Findings (E144)

- **The ClownFish batch lands**: 34 bodies / 9,587 words / 153 branches / 280 call rows of `ClownFish` (NPC subclass, instance_size 384; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). Implementation span 0x78d32c..0x79c160 (method order = pinned ObjC method-table order); roster names clf_00..clf_33, 0 collisions. Grades: 1 body >1000w [census] (clf_12 draw, 6419w), 2 bodies 300-1000w [census-lite] (clf_17 8-arg init, clf_19 loadDerivedStuff - both fully decoded despite the grade), 31 bodies <=300w fully read. Mechanical layer regenerated this run: gen_listings.py (`bodies 34 words 9587`, entrypoint-warning lines only) + build_specs.py (34 bodies, 280 call rows, 39 routes).

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | clf_00 | `ClownFish -[.cxx_construct]` | 6 | 0 | 0 | read |
  | clf_01 | `ClownFish -[blockheadUnloaded:]` | 56 | 1 | 2 | read |
  | clf_02 | `ClownFish -[canBeCapturedByBlockhead:withItemType:]` | 56 | 5 | 2 | read |
  | clf_03 | `ClownFish -[cantBeCapturedTipStringForBlockhead:withItemType:]` | 122 | 6 | 6 | read |
  | clf_04 | `ClownFish -[captureRequiredItemType]` | 7 | 0 | 0 | read |
  | clf_05 | `ClownFish -[capturedItemType]` | 7 | 0 | 0 | read |
  | clf_06 | `ClownFish -[clownFishUpdateNetDataForClient:]` | 89 | 2 | 2 | read |
  | clf_07 | `ClownFish -[creationDataStructSize]` | 8 | 0 | 0 | read |
  | clf_08 | `ClownFish -[creationNetDataForClient:]` | 131 | 4 | 8 | read |
  | clf_09 | `ClownFish -[dealloc]` | 119 | 0 | 6 | read |
  | clf_10 | `ClownFish -[die:]` | 194 | 6 | 8 | read |
  | clf_11 | `ClownFish -[doRemoteUpdate:]` | 190 | 3 | 2 | read |
  | clf_12 | `ClownFish -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 6419 | 75 | 161 | census |
  | clf_13 | `ClownFish -[foodItemType]` | 7 | 0 | 0 | read |
  | clf_14 | `ClownFish -[getNamesArray]` | 12 | 0 | 0 | read |
  | clf_15 | `ClownFish -[getNamesArrayCount]` | 7 | 0 | 0 | read |
  | clf_16 | `ClownFish -[hitWithForce:blockhead:]` | 99 | 2 | 2 | read |
  | clf_17 | `ClownFish -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]` | 328 | 13 | 14 | census-lite |
  | clf_18 | `ClownFish -[initWithWorld:dynamicWorld:cache:netData:]` | 137 | 4 | 3 | read |
  | clf_19 | `ClownFish -[loadDerivedStuff]` | 504 | 5 | 14 | census-lite |
  | clf_20 | `ClownFish -[maxAge]` | 12 | 0 | 0 | read |
  | clf_21 | `ClownFish -[maxHealth]` | 7 | 0 | 0 | read |
  | clf_22 | `ClownFish -[npcType]` | 7 | 0 | 0 | read |
  | clf_23 | `ClownFish -[reactToBeingFed]` | 141 | 0 | 7 | read |
  | clf_24 | `ClownFish -[reactToBeingHit]` | 76 | 1 | 3 | read |
  | clf_25 | `ClownFish -[remoteBlockheadHookedYou:]` | 104 | 3 | 5 | read |
  | clf_26 | `ClownFish -[remoteCreationDataUpdate:]` | 148 | 5 | 4 | read |
  | clf_27 | `ClownFish -[remoteUpdate:]` | 148 | 5 | 4 | read |
  | clf_28 | `ClownFish -[renderPos]` | 33 | 0 | 2 | read |
  | clf_29 | `ClownFish -[ridableWhenTamed]` | 7 | 0 | 0 | read |
  | clf_30 | `ClownFish -[setNeedsRemoved:]` | 64 | 0 | 2 | read |
  | clf_31 | `ClownFish -[speciesName]` | 12 | 0 | 0 | read |
  | clf_32 | `ClownFish -[tapIsWithinBodyRadius:]` | 271 | 11 | 20 | read |
  | clf_33 | `ClownFish -[updateNetDataForClient:]` | 59 | 2 | 3 | read |

- **What the class is**: ClownFish is the little clownfish NPC (aquatic, npcType = 4, maxAge = 7200.0f (2 game-hours), maxHealth = 25, foodItemType = 0x90/144, speciesName = CFString "FISH" @0xF90308). 62-name pool @0x01051CF8 (Amethyst...Xavier; includes Nemo, Dory, Bubbles, Mr. Bubbles, Fishy McFishface, Sushi; the table physically continues into other NPC name arrays past index 62). Not ridable (ridableWhenTamed = 0). Capture economy: captureRequiredItemType = 0x66/102 (a bucket - "CAN ONLY BE CAPTURED IN A BUCKET"), capturedItemType = 0x9e/158, creationDataStructSize = 0x70; capture gate = -[canBeCaptured...] (itemType==102 && (!tamed || belongsToPlayerWithBlockhead:)), tips from -[cantBeCapturedTipString...] ("%@ CAN ONLY BE CAPTURED
IN A BUCKET" wrong item / "THAT %@ BELONGS TO
SOMEONE ELSE" tamed-not-yours; nil when wild or yours). All three capture bodies branch through the same tamed/belongsTo pair (cells at 0xE812E8/0xE812EC/0xE812F0).
- **The fishing-rod interaction** (ClownFish-specific): -[remoteBlockheadHookedYou:] receives the Blockhead ([bh fishingRod] @0xC80FB0), and if the rod has no hookedFish and the fish isn't already bound to that rod: [self.hookedFishingRod autorelease]; self.hookedFishingRod@312 = [rod retain]; [rod setHookedFish:self] (FishingRod side: hookedFish/setHookedFish:/hookedFishDirection/blockhead @0x00842f9c/0x00842b58/0x00842930/0x008434c4). -[blockheadUnloaded:] clears the bind when that blockhead unloads (rod blockhead == bh -> rod autorelease, hookedFishingRod = nil; NOTE: no [super blockheadUnloaded:] call at all, unlike Scorpion sc_03). -[setNeedsRemoved:] and -[die:] both also autorelease + nil the rod. -[draw:...] when hooked: dir = [rod hookedFishDirection] (Vector2); if (dir.x > 0) { bodyRotation = goalRotation = +pi/2 (0x790718 = 0x3fc90fdb); a = atan2(dir.y, dir.x) } else { bodyRotation = goalRotation = -pi/2 (0x79071c = 0xbfc90fdb); a = atan2(-dir.y, -dir.x) }; bodyZRotation@276 = goalZRotation@272 = (float)a - the fish rides the line, nose along the drag direction.
- **Net protocol** (writer/reader pinned by tsv type strings): `ClownFishUpdateNetData = {NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}; int toSquare.x; int toSquare.y; short walkSpeed; signed char movementDirection; char[5]}` = 0x28 bytes (tsv string on clownFishUpdateNetDataForClient: literally spells this layout). Writer -[clownFishUpdateNetDataForClient:] (sret; r0=dest): [self npcUpdateNetDataForClient:arg] sret -> 0x18B NPCUpdateNetData copied to +0x00; +0x18/+0x1c = self.toSquare pair; +0x20 = (s16)(walkSpeed@284 * 255.0f) (pool 0x78e944 = 0x437f0000); +0x22 = (s8)movementDirection@236. Wrapper -[updateNetDataForClient:] = [NSData dataWithBytes:stret(...) length:0x28]. Creation blob -[creationNetDataForClient:] = 0x70B: [0x00..0x48) npcCreationNetData (0x48B sret) + [0x48..0x70) the fish update (0x28B sret) -> [NSData dataWithBytes:buf length:0x70] -> [self appendNPCCreationDataToData:]. Readers: -[remoteUpdate:] reads exactly 0x28 via getBytes and -[remoteCreationDataUpdate:] reads 0x70 and passes buf+0x48; both hand the struct to -[doRemoteUpdate:] with the AAPCS split w0/w1 in r2/r3 + w2..w9 on the stack (identical convention on all three sites).
- **The four-slot remote-update queue** (the headline structure): -[doRemoteUpdate:] (clf_11) splits by [self.dynamicWorld isClient]. SERVER (not client): applies directly to the authoritative state - walkSpeed = (s16)w8/255.0f, movementDirection = (s8)(w8 byte +0x22), toSquare = {w6, w7}, and sets updateNeedsToBeSent@49 = 1 (no queue touch). CLIENT: pushes into the 4-slot ring at nextToSquare@320[4 intpair]/nextWalkSpeed@352[4f]/nextMovementDirection@368[4i] with currentNetQueueSize@316 as count: if (size >= 4) { size = 3; currentNetQueueSize = 3; } then nextToSquare[size] = makeIntpair(w6, w7) (symbol makeIntpair(int,int) via sret), nextWalkSpeed[size] = (s16)w8/255.0f, nextMovementDirection[size] = (s8)w8.byte2, currentNetQueueSize = size + 1. The client queue is seeded by the 4-arg net init (clf_18: all 4 slots = self.pos / 0 / 0) and drained by the AI step in -[update:accurateDT:isSimulation:] (0x797300, outside this batch). -[reactToBeingHit] resets currentNetQueueSize = 0 (queue flushed on hit). w9 (+0x24..0x27 pad) is never written by this writer.
- **Client-side dead-fish special** (clf_26/clf_27, identical dead paths): after [super ...], if (self.dead@56) { if (self.travelFraction@256 < 1.0f && ![self.dynamicWorld isClient]) self.needsRemoved@48 = 0; return; } - a dead-but-still-interpolating fish on the server (non-client) keeps needsRemoved cleared so the death animation finishes before removal.
- **init/dealloc**: the 8-arg init (clf_17) mirrors Shark sh_20 structurally: super 8-arg, then tileAtWorldPositionLoaded(pos.x, pos.y, world); non-wasPlaced spawns require tile != 0 && tileIsWater(tile) && tile->byte4 >= 0x7f, else removeFromMacroBlock + release + nil; then weather/dayNight/season/temperature gate: fail iff temp < 0.1f OR (age@88 > 0.1 && temp < 2.0f); success -> loadDerivedStuff. The net init (clf_18) supers, loadDerivedStuff, seeds the 4-slot queue with pos/0/0, then remoteCreationDataUpdate:netData. -[dealloc] releases the 3 DrawCubes, clears the rod back-ref ([hookedFishingRod setHookedFish:nil]) and autoreleases the rod, [super dealloc]; shader/textures are not released.
- **loadDerivedStuff (clf_19, fully read)**: shader@208 = [cache shaderNamed:@"ShadedWorldObject" attributes:[position,texCoord,normal] uniforms:[mvp_matrix,texture,light,normal_matrix]]; bodyTexture@212 = clownFishBody.png; tailTexture@216 = clownFishTail.png; sideFinTexture@220 = clownFishSideFin.png; bodyCube@224 = (0.5, 0.5, 0.2, calcNormals) 4-arg; tailCube@228 = 8-arg (0.4, 0.4, 0.1, center 0.0, 0.4, 0.05); sideFinCube@232 = 8-arg (0.3, 0.1, 0.15, center 0.1, 0.05, 0.0). Movement seeds: x = lrand48()/2^31; movementDirection = x>0.75 ? 1 : (x<0.25 ? -1 : 0) [gl 0.75/0.25]; toSquare = pos; fromSquare = toSquare; travelFraction = 1.0; randomTimeBetweenDirectionChanges = 0.0; walkSpeed = 0.1 + 0.2*second-draw (same distribution family as Shark); bodyRotation = goalRotation = +-pi/2 by direction==1. Two rng draws total (call 0x78dc28 = lrand48 wrapper; also used by clf_10 and clf_12).
- **Combat/feed reactions**: -[hitWithForce:blockhead:] runs [super] FIRST (super2), then local-only (skips when dead or isNet): a lrand48 coin (>0.5 -> 1 else -1) sets movementDirection, walkSpeed = 3.0, rTBDC = 5.0. -[reactToBeingFed]: [super], then plays "fishRun.wav" (0.6s) + "crunch.wav" (0.1s) at floatPos, walkSpeed = 1.0, walkTimer = 0.0 (bounded dart, not a full stop). -[reactToBeingHit]: "fishRun.wav" (0.1s) at floatPos + queue reset. -[die:]: "fishDie.wav" + delay 0.1, travelFraction = 0, rod unbind; if (arg != 0) drops n = lrand48()%3 + 1 free blocks of type 0x97/151 at self.pos via [self.dynamicWorld createFreeBlockAtPosition:... priorityBlockhead:arg]; then [super die:arg].
- **draw (census, 6419w / 75 br / 161 calls)**: enormously spilled O0 frame (sub sp 0x9f0 + 0x1000, bic sp,#0xf; scratch state struct at sp+0x176c holding the two 16-float GLKMatrix4 args, camera ints, dt at +0x1f8 and self at +0x200). Head: toroidal x-wrap against worldWidthMacro*32 (divisor 2; blt/bge wrap pairs 0x78f8a8..0x78fbe0) then camera-range early-outs b 0x7959fc; Vector2 walk-offset accumulation at sp+0x1940; isOnAirAboveSolidGround@309 -> y -= 0.3; ground probe tileAtWorldPosition(fromSquare.x, fromSquare.y, world) 0x78ff90 with visibility early-out (tile==0 || tile->byte6==0 -> self.visible@57 = 0; return) and tileIsSolid(tile) -> dt zeroed. Bubble block 0x790180: bubbleEmitTimer@300 accumulates dt * walkSpeed-snapshot (f64 math, threshold constant gl 0.5); particle emission via [ParticleEmitter instance] with velocity (x=(rnd-0.5)*0.5, y=rnd*0.2+0.4, z) -> addParticleAtPos:velocity:color:gravityType:life:scale:. Hooked block 0x790880 (rod direction -> atan2 z-rotation +-pi/2 body). Pose section 0x790ad0..0x792c94: 5 sinf phases + the local 64B matrix-compose helper family (0x795a24/0x795a98/0x795c80/0x796018/0x7963b0/0x796748/0x7969fc/0x796a38, called ~27x) + 7 memcpy(64B). GL prologue 0x792c94: [shader program] -> glUseProgram; [[shader uniformLocations] objectAtIndex:0] intValue -> glUniform1i(loc, 0). Render: dayColor glUniform4f, glEnableVertexAttribArray(2), then 4 cube blocks each = mvp_matrix (uniformLocations[0]) + normal_matrix (uniformLocations[3]) glUniformMatrix4fv pair: B1 bind clownFishBody.png -> [bodyCube draw]; B2 bind clownFishTail.png -> [tailCube draw]; B3 bind clownFishSideFin.png -> [sideFinCube draw]; B4 [sideFinCube draw] again (second fin side); glDisableVertexAttribArray(2). GL totals: 8 glUniformMatrix4fv, 3 glBindTexture, 1 glUseProgram/glUniform1i/glUniform4f, 1 enable + 1 disable attrib array, 5 sinf, 2 atan2, 7 memcpy.

## Boundaries

- **clf_12 is census grade**: call histogram + constant scan + targeted window sampling define the semantics (window reads: 0x78f8a0 head/wrap, 0x78fbd0 camera bounds, 0x78fe90 ground probe, 0x790860 hooked gate, 0x790880-0x790ad0 atan2 block, 0x790cc0 sinf site, 0x790e90 helper+memcpy64 site, 0x792c94 GL prologue, 0x793690-0x7937a4 particle block, 0x793f40-0x794090 body block, 0x7948a0 tail, 0x7950e0 sidefin, 0x7959a0-0x795a04 last block). The 12 local matrix-compose helpers (0x795a24..0x796a38, just past the body end) stay opaque - their contracts are inferred from call shape (64B out, in-place operand) and the surrounding memcpy(64B)/glUniformMatrix4fv chains. The three sinf-phase amplitudes (f64, amp-spilled in the arenas at sp+0x740-region slots) are not each enumerated; phase results land in the draw-state at +0x108 and similar float fields. The exact per-cube matrix arguments are not enumerated (uniformLocations[0]=mvp, [3]=normal_matrix pinned by index values 0/3 at the two glUniformMatrix4fv sites).
- **clf_17/clf_19 are census-lite by word count but were fully read this run**: cube argument tuples come from the O0 spill/GL-truth map (corrected VFP immediates), not from byte-verified per-call values; `tile->byte4`/`tile->byte6` are raw Tile-struct byte offsets (field names unknown - outside batch). The temperature call passes season/dayNight/weather in float registers as the shark-analogous C++ signature does; its internal units are not re-derived here.
- **Queue consumer outside batch**: nextToSquare/nextWalkSpeed/nextMovementDirection/currentNetQueueSize are written only by clf_11/clf_18/clf_24 in this batch; the consumer that drains the 4-slot queue (advancing to the next square) lives in -[update:accurateDT:isSimulation:] (0x797300), one of 3 ClownFish methods outside the batch (with -[initWithWorld:dynamicWorld:saveDict:cache:] @0x78e420 and -[getSaveDict] @0x78e76c; ClownFish has 37 methods total per tsv, batch covers 34). makeIntpair(int,int) (symbol, called from clf_11 via sret) is a helper outside the batch span.
- **r2 vs GNU truth**: float immediates re-read from _gl.txt for every quoted threshold (0.5/0.75/0.25/2.0/3.0/5.0/255/2^31/0.1/0.6/+-pi/2 and the two doubles 0x3FB99999A0000000/0x3FE3333340000000). The r2 listing renders `vmov.f64 d1, #5`-style immediates misleadingly; no quoted constant relies on r2 alone.
- **Boundary trims** (roster.json): 6 bodies were trimmed at the next IMP (boundary case 2) because they share exidx ends with neighbours: clf_05 -> 0x78d42c (captureRequiredItemType), clf_13 -> 0x78d3c4 (getNamesArray), clf_14 -> 0x78d3f4 (getNamesArrayCount), clf_15 -> 0x78d410 (capturedItemType), clf_31 -> 0x78d3a8 (foodItemType), clf_32 -> 0x79b83c (reactToBeingHit). All other bodies ended on exidx bounds. No body rows were dropped anywhere (rows == words for every body; batch total 9,587 words).
- **Struct naming**: field names above the NPC level (NPCUpdateNetData/NPCCreationNetData internals, tile byte4/byte6) are not enumerable from this batch (base-class/-struct headers outside it); the ClownFishUpdateNetData layout IS tsv-pinned verbatim. The draw-state struct at sp+0x176c is compiler-generated spill state, not a source-level object.
- Static level-A evidence only (r2 pD + GNU objdump + ELF struct reads + tsv type strings + BL-caller scans): no runtime roundtrip, no device-side rendering or netplay claims.
