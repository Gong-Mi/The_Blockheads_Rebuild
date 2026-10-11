# FreeBlock (E152)

The FreeBlock entity lands: the dropped-item physics, the light contribution and the pickup priority. 31 bodies, 5938 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| fb_00 | FreeBlock -[creationNetDataForClient:] | 0x0062a6f0 | 641 | 12 | 3 | 12 | 3 | 25 | 21 |
| fb_01 | FreeBlock -[creationNetDataForFreeblockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:priorityBlockhead:soundType:creationSoundPlayTime:] | 0x0062b260 | 525 | 11 | 3 | 0 | 3 | 23 | 19 |
| fb_02 | FreeBlock -[creationSoundPlayTime] | 0x00634914 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_03 | FreeBlock -[dataA] | 0x006346c0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_04 | FreeBlock -[dataB] | 0x00634744 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_05 | FreeBlock -[dealloc] | 0x00629500 | 92 | 2 | 2 | 4 | 1 | 5 | 0 |
| fb_06 | FreeBlock -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x0062f868 | 1789 | 5 | 1 | 15 | 0 | 47 | 34 |
| fb_07 | FreeBlock -[dynamicObjectSaveDict] | 0x00634850 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_08 | FreeBlock -[falling] | 0x006343f4 | 74 | 1 | 1 | 3 | 0 | 3 | 2 |
| fb_09 | FreeBlock -[hitLava] | 0x0062bcd8 | 196 | 5 | 1 | 1 | 2 | 16 | 0 |
| fb_10 | FreeBlock -[hovers] | 0x00634894 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_11 | FreeBlock -[initSubDerivedObjects] | 0x00625c90 | 210 | 5 | 3 | 6 | 1 | 8 | 1 |
| fb_12 | FreeBlock -[initWithWorld:dynamicWorld:atPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:cache:hovers:priorityBlockhead:] | 0x00626004 | 591 | 8 | 1 | 14 | 2 | 22 | 19 |
| fb_13 | FreeBlock -[initWithWorld:dynamicWorld:cache:netData:] | 0x00627f74 | 72 | 1 | 0 | 0 | 0 | 4 | 1 |
| fb_14 | FreeBlock -[initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:] | 0x006280cc | 964 | 21 | 5 | 17 | 3 | 40 | 44 |
| fb_15 | FreeBlock -[itemType] | 0x00634640 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_16 | FreeBlock -[priorityBlockhead] | 0x0063480c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_17 | FreeBlock -[priorityBlockheadCannotPickup] | 0x0063451c | 66 | 3 | 0 | 4 | 0 | 3 | 0 |
| fb_18 | FreeBlock -[remoteUpdate:] | 0x0062ba94 | 145 | 3 | 2 | 6 | 1 | 3 | 4 |
| fb_19 | FreeBlock -[removeFromMacroBlock] | 0x00629670 | 101 | 2 | 2 | 3 | 1 | 2 | 5 |
| fb_20 | FreeBlock -[setCreationSoundPlayTime:] | 0x0063495c | 19 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_21 | FreeBlock -[setDataA:] | 0x006346fc | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_22 | FreeBlock -[setDataB:] | 0x00634780 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_23 | FreeBlock -[setHovers:] | 0x006348d0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_24 | FreeBlock -[setItemType:] | 0x0063467c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_25 | FreeBlock -[setSoundType:] | 0x006349e4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_26 | FreeBlock -[shouldSaveEveryChangeInPosition] | 0x00634624 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| fb_27 | FreeBlock -[soundType] | 0x006349a8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_28 | FreeBlock -[subItems] | 0x006347c8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| fb_29 | FreeBlock -[updateNetDataForClient:] | 0x0062a4bc | 141 | 3 | 1 | 5 | 1 | 4 | 2 |
| fb_30 | FreeBlock -[updatePosition:] | 0x00626940 | 74 | 2 | 0 | 2 | 1 | 2 | 2 |

## Findings (E152)

- **The FreeBlock batch lands**: 31 bodies / 5938 words / 154 in-body branch rows / 207 call rows of the dropped-item entity `FreeBlock` (**super = DynamicObject**; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). Mechanical layer regenerated this run: `gen_listings.py` ("bodies 31 words 5938", 0 collisions) + `build_specs.py` (31 bodies / 207 call rows / 29 routes). Listing rows == roster word count for every body (verified programmatically: 0 mismatches). Grades: **1 census** (>1000w): fb_06 (1789w `draw:`); **4 census-lite**: fb_14 (964), fb_00 (641), fb_12 (591), fb_01 (525); the remaining **26 are <=210w and were fully read**. 6 bodies are TRIMMED at the next IMP (fb_02, fb_16, fb_22, fb_23, fb_26, fb_28 -- see Boundaries).

- **What the class is**: the item-dropped-on-the-ground entity (player discard / death drop / trade overflow). Ivar surface actually touched: itemType@56, dataA@60 (u16), dataB@62 (u16), hovers@64 (BOOL), bounceTimer@68, fallSpeed@72, rotation@76, creationTime@80 (double, world time), blockCube@88 (DrawCube, block items only), subItems@112 (array of arrays), xVelocity@116, yVelocity@124, priorityBlockhead@136 (pickup reservation), dynamicObjectSaveDict@140, creationSoundPlayTime@144, soundType@148, paintColor@152 (specs ivars; last field, beyond the 24-ivar metadata list). Base-class fields used: DynamicObject pos@16 / floatPos@24 / world@4 / dynamicWorld@8 / cache@32 / isNet@52 / needsRemoved@48 / updateNeedsToBeSent@49 / uniqueID@40.

- **Creation record (fb_00 / fb_01 / fb_29, 0x38 / 0x28 bytes)**: fb_00 `-creationNetDataForClient:` builds a fixed **0x38-byte** record `{dynamicObjectNetData(0x18) | priorityBlockhead.uniqueID(u64)@+0x18 | u16 itemType@+0x20 | u16 dataA@+0x22 | u16 dataB@+0x24 | u16 fallSpeed*255@+0x26 | u16 xVelocity*255@+0x28 | u16 yVelocity*255@+0x2a | f32 creationSoundPlayTime@+0x2c | s8 soundType@+0x30 | u8 hovers@+0x31 | u8 hasExtra@+0x32}` and, when hasExtra (= saveDict exists or subItems non-empty), appends `gzip(plist(dict))` with keys "dynamicObjectSaveDict" and "subItems" (items = per-stack arrays of `[elem saveData]`, elements with itemType 0xb skipped). Its `(data)` argument is ignored; it returns a fresh NSMutableData. fb_01 is the class-side twin (same record; uniqueID = 0xffffffffffffffff, kinematics 0, bytes +0x11..0x17 uninitialized - stale stack). fb_29 `-updateNetDataForClient:` builds the **0x28-byte** per-update record (same layout minus the creation-only fields) - and fb_18 `-remoteUpdate:` reads exactly that 0x28 record back (kinematics restored only when isNet). Shared local helpers: 0x62b0f4 (plist+deflate writer side) and 0x628fdc (inflate+plist reader side).

- **Net round-trip / dupe guard (fb_14, census-lite)**: `-initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:` re-reads the 0x38 record, **refuses itemType 0xb** ([self release]; nil), restores all creation fields, jitters floatPos.x when hovers == 0, then rebuilds `subItems` from `dict["subItems"]` as real `[[InventoryItem alloc] initWithSaveData:]` objects (0xb skipped), copies `dynamicObjectSaveDict`, and runs a **uniqueID LRU dup-guard**: if `[[saveDict objectForKey:@"uniqueID"] unsignedLongValue]` is already inside the `avoidFreeblockDupeObjectIds` `std::list<unsigned long long>&` (hand-inlined std::find) the new instance is released and nil returned; otherwise the uid is push_back'ed and pop_front'ed past 32 entries. Finally: `isNet = 0` when `![[dynamicWorld] isClient]`, and `priorityBlockhead = [[dynamicWorld blockheadWithIDIncludingNet:record+0x18] retain]`. fb_13 is the convenience thunk that calls it with a freshly built empty list.

- **Physics / lifecycle**: fb_12 (designated init) - super DynamicObject init, field copies, retains, subItems filter (0xb skip), x-jitter `lrand48()/2^31*5-2` when not hovering, `bounceTimer = 1.0`, `fallSpeed = -0.05`, `floatPos.y = pos.y + 5.0`, `creationTime = [world worldTime]`, `yVelocity = 5.0`, then `initSubDerivedObjects`. fb_30 `updatePosition:` - super call then `[dynamicWorld freeblockPositionChanged:self oldPos:...]` whenever the intpair pos changed. fb_08 `falling` - NO while hovering, else `tileIsAirOrSnow(tileAtWorldPosition(pos.x, pos.y-1, [world macroTiles], world))`. fb_09 `hitLava` - `setNeedsRemoved:YES` + particle burst (lrand48-driven offsets; color 0.4/0.2/0.2/0.5; gravity 0, life 1.0, scale 12.0) + MJSoundManager "freeblockLavaHiss.wav" at floatPos. fb_17/fb_18 - pickup reservation (`priorityBlockhead@136` retain/release + `dynamicWorldChangedAtPos:objectType:` / nil-when-uid-cleared). fb_19 `removeFromMacroBlock` - super call then, for hovering "pole items" (itemType in 0x8c..0x8f) `[dynamicWorld poleItemTaken:itemType]`. fb_11 `initSubDerivedObjects` - random rotation `2*pi*lrand48()/2^31`, `paintColor` from saveDict, and the block cube (`[[DrawCube alloc] initItemBlockOfType:... level:[saveDict["level"] intValue] paint:(paintColor!=0) size:0.4f world:]`) only for `itemTypeIsBlock`. fb_05 dealloc releases priorityBlockhead/subItems/dynamicObjectSaveDict/blockCube + super2 dealloc. fb_26 `shouldSaveEveryChangeInPosition` = NO.

- **Rendering (fb_06, census)**: the draw: entry advances the animation clocks (bounceTimer/rotation += dt), computes the bounce offset `|sin(2*pi*rotation)*(1-bounceTimer)*5|`, notifies `dynamicWorldChangedAtPos:objectType:` on the bounce-completion frame, camera-culls with 4 worldWidthMacro-wrap blocks (6x __aeabi_idiv) + a 4-way compare chain, computes the screen position (floatPos - cameraMin + wrap*32), bails when `tileAtWorldPosition` returns 0, adds the `sin(rotation*4)*0.1` wobble, composites the tile light (u16 tile[0xe]/[0x10]/[0x12] / 1024.0f) with `[world dayColor]` (stret 0x10) into the render-params struct, then either the block cube path (blockCube@88 != nil -> helpers 0x63145c/0x631644/0x631a04/0x632fc4/0x631fc8) or the item-icon quad fallback (Vector(-0.5,-0.3,1.0) + helpers 0x633094/0x6330e0). The 7 local helpers themselves are outside this batch.

## Per-body table

| name | method | words | branches | calls | grade |
|---|---|---|---|---|---|
| fb_00 | `-[creationNetDataForClient:]` | 641 | 21 | 25 | census-lite |
| fb_01 | `-[creationNetDataForFreeblockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:priorityBlockhead:soundType:creationSoundPlayTime:]` | 525 | 19 | 23 | census-lite |
| fb_02 | `-[creationSoundPlayTime]` | 18 | 0 | 0 | read |
| fb_03 | `-[dataA]` | 15 | 0 | 0 | read |
| fb_04 | `-[dataB]` | 15 | 0 | 0 | read |
| fb_05 | `-[dealloc]` | 92 | 0 | 5 | read |
| fb_06 | `-[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 1789 | 34 | 47 | census |
| fb_07 | `-[dynamicObjectSaveDict]` | 17 | 0 | 0 | read |
| fb_08 | `-[falling]` | 74 | 2 | 3 | read |
| fb_09 | `-[hitLava]` | 196 | 0 | 16 | read |
| fb_10 | `-[hovers]` | 15 | 0 | 0 | read |
| fb_11 | `-[initSubDerivedObjects]` | 210 | 1 | 8 | read |
| fb_12 | `-[initWithWorld:dynamicWorld:atPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:cache:hovers:priorityBlockhead:]` | 591 | 19 | 22 | census-lite |
| fb_13 | `-[initWithWorld:dynamicWorld:cache:netData:]` | 72 | 1 | 4 | read |
| fb_14 | `-[initWithWorld:dynamicWorld:cache:netData:avoidFreeblockDupeObjectIds:]` | 964 | 44 | 40 | census-lite |
| fb_15 | `-[itemType]` | 15 | 0 | 0 | read |
| fb_16 | `-[priorityBlockhead]` | 17 | 0 | 0 | read |
| fb_17 | `-[priorityBlockheadCannotPickup]` | 66 | 0 | 3 | read |
| fb_18 | `-[remoteUpdate:]` | 145 | 4 | 3 | read |
| fb_19 | `-[removeFromMacroBlock]` | 101 | 5 | 2 | read |
| fb_20 | `-[setCreationSoundPlayTime:]` | 19 | 0 | 0 | read |
| fb_21 | `-[setDataA:]` | 18 | 0 | 0 | read |
| fb_22 | `-[setDataB:]` | 18 | 0 | 0 | read |
| fb_23 | `-[setHovers:]` | 17 | 0 | 0 | read |
| fb_24 | `-[setItemType:]` | 17 | 0 | 0 | read |
| fb_25 | `-[setSoundType:]` | 17 | 0 | 0 | read |
| fb_26 | `-[shouldSaveEveryChangeInPosition]` | 7 | 0 | 0 | read |
| fb_27 | `-[soundType]` | 15 | 0 | 0 | read |
| fb_28 | `-[subItems]` | 17 | 0 | 0 | read |
| fb_29 | `-[updateNetDataForClient:]` | 141 | 2 | 4 | read |
| fb_30 | `-[updatePosition:]` | 74 | 2 | 2 | read |

## Boundaries

- **Scope**: the batch covers 31 of the 35 tsv rows whose class is FreeBlock (34 instance + 1 class method `creationNetDataForFreeblockAtPosition:...`). The four FreeBlock instance methods NOT in this batch are `objectType` (0x625fe8), `initWithWorld:dynamicWorld:saveDict:cache:` (0x626a68), `getSaveDict` (0x629804) and `update:accurateDT:isSimulation:` (0x62bfe8); none of them appears in any other batch roster either (checked all bh-work rosters), so those four remain undecoded in the current corpus. The World-side factories `createFreeBlockAtPosition:*` (0x8ddc78/0x8de880/0x8df3c4), `drawFreeBlocks:...` (0x8d4760) and `freeBlockCreationCountForTile:withItem:` carry class=World in the tsv and are other batches' scope.
- **TRIMMED bodies** (listing bound = next ObjC IMP; header keeps the ARM.exidx end): fb_02 (exidx end 0x6349a8, trimmed at 0x63495c setCreationSoundPlayTime:), fb_16 (0x634894 / 0x634850 dynamicObjectSaveDict), fb_22 (0x634894 / 0x6347c8 subItems), fb_23 (0x6349a8 / 0x634914 creationSoundPlayTime), fb_26 (0x63467c / 0x634640 itemType), fb_28 (0x634894 / 0x63480c priorityBlockhead). All six are <=19w stubs whose pools re-bound at the trim point; no identified instruction lost.
- **Census-grade body** (structure + phases + windows, not per-instruction reads): fb_06 (1789w). Its seven local helper subroutines (0x63145c, 0x631644, 0x631a04, 0x631fc8, 0x632fc4, 0x633094, 0x6330e0) sit outside the batch and were characterised only by call site/role - the actual GL/geometry emission inside them is not decoded here. The exact interleaving of the tile-light/day-color compositing between 0x630ab0 and 0x630e14 is summarised, not instruction-by-instruction.
- **Census-lite bodies** (fb_00/fb_01/fb_12/fb_14) were fully read; their shared local pipeline helpers (0x62b0f4 plist+deflate, 0x628fdc inflate+plist) are single functions beyond the batch bounds, characterised by role only.
- **Observed record quirks (literal, not normalised)**: fb_01 leaves record bytes +0x11..+0x17 unwritten (uninitialized stack in the wire blob); fb_14 sets creationTime@80 = (double)(f32 record[0x2c]) - i.e. it aliases the creationSoundPlayTime slot - and does NOT restore fallSpeed@72; fb_12's `if yVelocity > 0 -> fallSpeed -= 0.1` check is dead on the fresh-alloc path (yVelocity is assigned 5.0 only later); fb_18 restores kinematics only when isNet@52 != 0.
- **VFP immediates** were taken from the `_gl` (GNU objdump) listings per batch convention (255.0f = 0x437f0000, 2^31 = 0x4f000000, pi double 0x400921fb54442d18, -0.05f = 0xbd4ccccd, 0.1f = 0x3dcccccd, 0.4f = 0x3ecccccd, 2.0f/5.0f/4.0f in the -0x62fb30 window); r2's pool mislabelling was not used for constants.
- **Batch-level**: 0 name collisions against checked-in listings; mechanical artefacts regenerated into the batch directory only (no repo writes).
