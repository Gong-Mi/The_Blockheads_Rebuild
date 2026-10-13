# Action (E154)

The rail station object lands: the placement and net twin pair, the sub-derived geometry, the text-editing family and the removal path. 27 bodies, 6815 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). Every listing regenerates byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| ts_00 | TrainStation -[canBeUsedByBlockhead:] | 0x00b3f7f0 | 120 | 5 | 2 | 2 | 1 | 5 | 5 |
| ts_01 | TrainStation -[creationNetDataForClient:] | 0x00b395e4 | 223 | 6 | 4 | 3 | 2 | 11 | 5 |
| ts_02 | TrainStation -[dealloc] | 0x00b39df0 | 92 | 2 | 2 | 4 | 1 | 5 | 0 |
| ts_03 | TrainStation -[destroyItemType] | 0x00b3f17c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_04 | TrainStation -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00b3a2b0 | 3729 | 17 | 2 | 12 | 0 | 158 | 32 |
| ts_05 | TrainStation -[freeBlockCreationDataA] | 0x00b3e730 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_06 | TrainStation -[freeBlockCreationDataB] | 0x00b3e74c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_07 | TrainStation -[freeBlockCreationSaveDict] | 0x00b3e6e4 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| ts_08 | TrainStation -[freeblockCreationItemType] | 0x00b3e6c8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_09 | TrainStation -[initSubDerivedItems] | 0x00b380dc | 551 | 8 | 18 | 8 | 2 | 19 | 0 |
| ts_10 | TrainStation -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] | 0x00b38978 | 388 | 7 | 3 | 3 | 2 | 14 | 6 |
| ts_11 | TrainStation -[initWithWorld:dynamicWorld:cache:netData:] | 0x00b3912c | 204 | 7 | 5 | 3 | 1 | 12 | 2 |
| ts_12 | TrainStation -[interactionObjectType] | 0x00b3a290 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_13 | TrainStation -[interactionRenderItemType] | 0x00b3f9d0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_14 | TrainStation -[occupiesNormalContents] | 0x00b3f9ec | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_15 | TrainStation -[remoteUpdate:] | 0x00b39acc | 201 | 8 | 5 | 3 | 1 | 13 | 1 |
| ts_16 | TrainStation -[remove:] | 0x00b3e768 | 349 | 7 | 1 | 9 | 0 | 12 | 9 |
| ts_17 | TrainStation -[requiresHumanInteraction] | 0x00b3f108 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_18 | TrainStation -[requiresSingleLineTextEditing] | 0x00b3f160 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ts_19 | TrainStation -[setNeedsRemoved:] | 0x00b3ecdc | 114 | 2 | 1 | 2 | 1 | 6 | 0 |
| ts_20 | TrainStation -[setText:] | 0x00b3ef34 | 117 | 7 | 1 | 3 | 0 | 7 | 1 |
| ts_21 | TrainStation -[text] | 0x00b3f124 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| ts_22 | TrainStation -[title] | 0x00b3eea4 | 36 | 1 | 2 | 1 | 1 | 1 | 0 |
| ts_23 | TrainStation -[updateBitmapString] | 0x00b39f60 | 174 | 5 | 2 | 4 | 3 | 7 | 1 |
| ts_24 | TrainStation -[updateNetDataForClient:] | 0x00b39590 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| ts_25 | TrainStation -[worldChanged:] | 0x00b3f198 | 391 | 2 | 1 | 3 | 0 | 16 | 21 |
| ts_26 | TrainStation -[objectType] | 0x00b380c0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |

## Findings (E155)

The TrainStation class lands whole: 26/26 bodies, 6808 instruction words, 288 call rows (199 bl / 89 blx) and 83 branch
rows, from the pinned original libApplication.so (1.7.6, armeabi-v7a, sha256 733d8210...30b94c7). Every listing row is
byte-identical to its GNU objdump cross-check (26/26 bodies, 6808/6808 rows: same address set, same 4 bytes; r2 prints
memory order, GNU prints the big-endian word) and the listing row count equals the roster word count for all 26 bodies with
the header IMP equal to the roster IMP. 61/61 ivar pool cells resolve through the two-stage Apportable idiom (cell =
PIC base 0x0105FAF4 + s32(pool word), then the OBJC_IVAR word whose first dword is the offset) to the class_metadata.json
offsets of the flattened TrainStation chain (own ivars cubeShader 100, signShader 104, tileDestructTexture 108,
platformBlock 112, poleDrawCube 116, bitmapString 120, needsToUpdateBitmapString 124, text 128; InteractionObject
currentBlockhead 56 / shader 60 / texture 64 / isInUse 68 / remoteBlockheadInUseUniqueID 72 / ownerName 84 /
needsToBeRemovedWhenInteractionEnds 96; DynamicObject world 4 / pos 16 / cache 32 / ownerID 36 / isNet 52) - 61/61 match,
zero mismatches. All 86 selector cells resolve to their expected method name (cell content is the VA of the
__objc_methname string in this build, one deref), 15 class cells resolve (OBJC_CLASS_$_TrainStation cell 0x00e8be8c holds
0x00e91db8, exactly the class_metadata class_addr), and the 51 import cells are objc_msgSend / objc_msgSendSuper2 /
__CFConstantStringClassReference.

| name | method | words | branches | calls | grade |
|---|---|---|---|---|---|
| ts_00 | `-[canBeUsedByBlockhead:]` | 120 | 5 | 5 (0 bl / 5 blx) | read |
| ts_01 | `-[creationNetDataForClient:]` | 223 | 5 | 11 (4 bl / 7 blx) | read |
| ts_02 | `-[dealloc]` | 92 | 0 | 5 (0 bl / 5 blx) | read |
| ts_03 | `-[destroyItemType]` | 7 | 0 | 0 (0 bl / 0 blx) | read |
| ts_04 | `-[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 3729 | 32 | 158 (145 bl / 13 blx) | census |
| ts_05 | `-[freeBlockCreationDataA]` | 7 | 0 | 0 (0 bl / 0 blx) | read |
| ts_06 | `-[freeBlockCreationDataB]` | 7 | 0 | 0 (0 bl / 0 blx) | read |
| ts_07 | `-[freeBlockCreationSaveDict]` | 19 | 0 | 1 (0 bl / 1 blx) | read |
| ts_08 | `-[freeblockCreationItemType]` | 7 | 0 | 0 (0 bl / 0 blx) | read |
| ts_09 | `-[initSubDerivedItems]` | 551 | 0 | 19 (3 bl / 16 blx) | census-lite |
| ts_10 | `-[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]` | 388 | 6 | 14 (9 bl / 5 blx) | read |
| ts_11 | `-[initWithWorld:dynamicWorld:cache:netData:]` | 204 | 2 | 12 (3 bl / 9 blx) | read |
| ts_12 | `-[interactionObjectType]` | 8 | 0 | 0 (0 bl / 0 blx) | read |
| ts_13 | `-[interactionRenderItemType]` | 7 | 0 | 0 (0 bl / 0 blx) | read |
| ts_14 | `-[occupiesNormalContents]` | 7 | 0 | 0 (0 bl / 0 blx) | read |
| ts_15 | `-[remoteUpdate:]` | 201 | 1 | 13 (3 bl / 10 blx) | read |
| ts_16 | `-[remove:]` | 349 | 9 | 12 (4 bl / 8 blx) | read |
| ts_17 | `-[requiresHumanInteraction]` | 7 | 0 | 0 (0 bl / 0 blx) | read |
| ts_18 | `-[requiresSingleLineTextEditing]` | 7 | 0 | 0 (0 bl / 0 blx) | read |
| ts_19 | `-[setNeedsRemoved:]` | 114 | 0 | 6 (5 bl / 1 blx) | read |
| ts_20 | `-[setText:]` | 117 | 1 | 7 (5 bl / 2 blx) | read |
| ts_21 | `-[text]` | 15 | 0 | 0 (0 bl / 0 blx) | read |
| ts_22 | `-[title]` | 36 | 0 | 1 (0 bl / 1 blx) | read |
| ts_23 | `-[updateBitmapString]` | 174 | 1 | 7 (5 bl / 2 blx) | read |
| ts_24 | `-[updateNetDataForClient:]` | 21 | 0 | 1 (0 bl / 1 blx) | read |
| ts_25 | `-[worldChanged:]` | 391 | 21 | 16 (13 bl / 3 blx) | read |
| ts_26 | `TrainStation -[objectType]` | 7 | 0 | 0 | read |

- **Grades: 24 read, 1 census-lite (ts_09), 1 census (ts_04).** 22 of the 24 read bodies are at or below 223 words and were
  decoded instruction by instruction (the 7-word constant predicates fall out of a single movw/mov pair); ts_10/ts_16/ts_25
  (388/349/391 words) were also read through, including the 9-argument stack frame, the six tile-removal coordinates and the
  std::vector intpair walk. ts_09 was decoded as census-lite (slot-table reconstruction of the ~90-instruction cell preload
  plus targeted windows and the full call-site list). ts_04 is a structural census (call histogram, selector/constant/ivar
  inventory, three read windows) and is NOT a per-instruction decode.

- **Base contract (the one-liner layer, cross-checkable against INTERACTIONOBJECT.md / CHEST.md / TRADINGPOST.md)**:
  interactionObjectType = **6** (ts_12, uxth of movw 6; ladder base 0, Chest 2, TradingPost 5, TrainStation 6),
  interactionRenderItemType = **200** = ItemType TrainStation (ts_13), destroyItemType = **200** (ts_03),
  freeblockCreationItemType = **200** (ts_08), freeBlockCreationDataA = **0** (ts_05) and freeBlockCreationDataB = **0**
  (ts_06) as u16s, occupiesNormalContents = **YES** (ts_14), requiresHumanInteraction = **YES** (ts_17),
  requiresSingleLineTextEditing = **YES** (ts_18), freeBlockCreationSaveDict is just `return [self getSaveDict]` (ts_07), and
  updateNetDataForClient: is just `return [self creationNetDataForClient:client]` (ts_24, single tail send - the per-update
  net record is the creation record for this class).

- **Net twin pair**: ts_01 `creationNetDataForClient:` builds the wire blob as a **0x28-byte (40) InteractionObjectNetData
  prefix plus gzip(plist)** tail. The prefix comes from the inherited `interactionObjectCreationNetData` called with a hidden
  stret buffer (sp+0x70, memset 0x28 when self is nil), copied with memcpy and wrapped by
  `[NSMutableData dataWithBytes:length:0x28]`; the dictionary gets only the non-nil keys **text** (CFString 0xf9d608),
  **ownerID** (0xf9d628) and **ownerName** (0xf9d638), then `[[plist writer 0xb39960](dict) gzipDeflate]` is appended. The
  `client` argument is spilled at fp-0x24 and never read. ts_11 `initWithWorld:dynamicWorld:cache:netData:` is the mirror
  reader: super2 with the same four-argument selector (cache/netData arriving as the two stack words), nil propagates, then
  `tail = [netData subdataWithRange:NSMakeRange(0x28, len-0x28)]`, `dict = 0xb3945c([tail gzipInflate])` (plist reader,
  propertyListWithData:options:format:error: with options 0), and text@128 / ownerID@36 / ownerName@84 are each set to
  `[[dict objectForKey:key] retain]` before `[self initSubDerivedItems]`. ts_15 `remoteUpdate:` reuses the same tail/dict
  decode with a different discipline: it supers first, then **returns early while self->currentBlockhead != nil** (0xb39b50),
  applies the new text through `[self setText:]` (so it inherits the retain/release + updateBitmapString + dynamicWorld
  notification chain) but swaps ownerID/ownerName by hand ([old release] then `[[dict objectForKey:...] retain]`).

- **Placed-by-client ctor (ts_10, 388 words)**: 9 arguments forwarded to objc_msgSendSuper2 with pos.x/pos.y as the first two
  stack words (fp = entry_sp - 8, so the eight argument words sit at [fp,#8..#0x24] - encoder labels and callee frames agree
  here, unlike the E154 ac_10 case). text@128 = `[[saveDict objectForKey:@"text"] retain]`, with the literal **TRAIN**
  (CFString 0xf9d618) built by `[[NSString alloc] initWithString:@"TRAIN"]` when the key is absent. The tail walks three tile
  probes and, for each non-nil tile, calls `fillTile:atPos:withType:dataA:dataB:placedByClient:saveDict:placedByClientName:`
  with **withType 0xc7 (199)**, dataA 1, dataB 0, placedByClient 0, saveDict 0, name 0 at the coordinates (x,y), (x-1,y) and
  (x+1,y) - gated respectively by the probes at (x,y), **(x+1,y)** and **(x-1,y)**, i.e. the right probe gates the left fill
  and vice versa (the cross pairing is what the compiled add/sub immediates say, see Boundaries). It ends with
  `[self initSubDerivedItems]`.

- **Lifecycle cluster**: ts_16 `remove:` is the destruction path - guards on needsRemoved@48 and isNet@52, an in-use branch
  that either defers (`needsToBeRemovedWhenInteractionEnds@96 = 1` when the attached blockhead isNet or
  remoteBlockheadInUseUniqueID@72 is nonzero) or detaches (`[currentBlockhead stopInteracting]`), then
  `[world removeTileAtWorldX:pos.x worldY:pos.y ... removeBlockhead:arg]`, `[self setNeedsRemoved:1]`,
  `[dynamicWorld createFreeBlockAtPosition:pos ofType:200 dataA:0 dataB:0 subItems:nil dynamicObjectSaveDict:[self getSaveDict]
  hovers:0 playSound:1 priorityBlockhead:arg]`, `[dynamicWorld railOrStationNameChanged]`, and five more removeTile calls -
  six tiles total: (x,y), (x-1,y), (x-1,y+1), (x,y+1), (x+1,y), (x+1,y+1), a 3x2 footprint. ts_19 `setNeedsRemoved:` is the
  straight-line rail cleanup that runs before the super flag write: `[dynamicWorld removeRailAtPos:]` at (x,y), (x-1,y) and
  (x+1,y) built with makeIntpair@0x4b49fc, then objc_msgSendSuper2(setNeedsRemoved:). ts_02 dealloc releases exactly four
  ivars - platformBlock@112, poleDrawCube@116, bitmapString@120, text@128 - and then supers dealloc; cubeShader/signShader/
  tileDestructTexture are **not** released. ts_25 `worldChanged:` takes a const std::vector intpair reference (methtype
  ^{vector<intpair,...>}), returns immediately when self->isNet@52, and for every changed tile normalises the world-wrapped
  dx (worldWidthMacro << 5, /2 via __aeabi_idiv, fabs via 0xb3f7b4) and skips unless the absolute dx is below 2 and
  entry.y == pos.y - 1; when any of the three tiles above the station row exists and is not solid it calls `[self remove:nil]`
  and returns.

- **Text / sign cluster**: ts_21 `text` is a bare ivar getter (cell -> OBJC_IVAR_$_TrainStation.text, first dword 128, no
  retain). ts_22 `title` = `[NSString stringWithFormat:@"%@ STATION", self->text]` (format record at 0xf9d648, flags 0x7c8,
  len 10). ts_20 `setText:` early-returns when `[newText isEqualToString:self->text]` (the argument is the comparison's
  receiver), else `[old autorelease]`, `self->text = [new retain]`, `[self updateBitmapString]`,
  `[dynamicWorld dynamicWorldChangedAtPos:pos objectType:[self objectType]]` (objectType pushed as a 5th stack word) and
  `[dynamicWorld railOrStationNameChanged]`. ts_23 `updateBitmapString` clears needsToUpdateBitmapString@124, releases
  bitmapString@120 and sets it to nil, returns when text is nil, and otherwise builds
  `[[BitmapString alloc] initWithString:fmt dimensions:Vector2(256.0f,48.0f) horizontalAlignment:1
  font:[BitmapFont embossedFont] cache:self->cache color:Vector(1,1,1,1)]` - 256.0f/48.0f come from movw/movt
  0x43800000/0x42400000 and the two by-value vectors are built by the out-of-line stubs 0xb3a218 (Vector2: arg1 to [r0],
  arg2 to [r0+4]) and 0xb3a244 (4-float Vector).

- **ts_09 initSubDerivedItems (census-lite)**: one ~90-instruction preload block places shader/texture/class/selector cells
  into fp-relative slots, then 19 calls build the render set: `[self->cache shaderNamed:attributes:uniforms:]` (twice, names
  StandardObject / FreeBlock / WorldObject with the CFString sets position/texCoord/normal and mvp_matrix/texture/daylight/
  lightPosition/artificalLight/normal_matrix/destruct_texture, cells 0xf9d4f8..0xf9d5e8), `[cache textureNamed:@"TileMap.png"]`,
  `[cache textureNamed:withAlpha:@"TileReflect.png"]`, "TileDestruct.png" for tileDestructTexture, writing
  InteractionObject.shader@60 / texture@64 and TrainStation.cubeShader@100 / signShader@104 / tileDestructTexture@108, then
  `[[DrawCube alloc] initWithWidth:height:depth:topMinS:...:calculateNormals:]` -> platformBlock@112 and
  `texCoordsForImageIndex(0xcb = 203)` + `[[DrawCube alloc] initPyramidWithWidth:...:topScale:rightScale:]` (float pool
  0.2/0.0/0.7, immediates 4.0/2.0/1.0/5.0, double 5.0) -> poleDrawCube@116; the tail runs
  tileTexCoordsForItemType(0x419 = 1049) twice and ends with `[self updateBitmapString]`.

- **ts_04 draw (census)**: the batch heavyweight at 3729 words / 158 call rows / 32 branches / **0 backward branches** (no
  loops, fully unrolled). Frame: sub sp,#0xfb0 + bic sp,#0xf, two GLKMatrix4 by value (64 B each) and 4 camera ints from the
  stack. It exits immediately when `tileAtWorldPosition(pos.x,pos.y,&macroTile,self->world)` is nil (0xb3abec -> 0xb3dcc0).
  Bind pass: `[self->world dayColor]` as a 16-byte stret struct (memset 0x10 when nil), glBindTexture(GL_TEXTURE_2D 0xde1)
  for texture@64 and, after glActiveTexture(GL_TEXTURE1 0x84c1), for tileDestructTexture@108. Counts: 52 objc_msgSend + 21
  Vector.operator_float__ + 12 Vector2.operator_float__ + 3 Vector ctors + 6 __aeabi_idiv (worldWidthMacro wrap) + 7
  glUniformMatrix4fv + 4 glUniform4f + 3 glUniform1i + 4 glBindTexture + 2 glActiveTexture + 5 glEnable + 2 glDisable (GL_BLEND
  0xbe2 at the tail) + 3 glEnableVertexAttribArray + 1 glDisableVertexAttribArray + 2 glUseProgram + 1 drawShaderQuad + 1
  pushDepthMaskState / 1 popDepthMaskState (0xb3cb7c / 0xb3dcbc around the sign pass) + 1 memcpy + 2 memset. Geometry
  constants are inline movw+movt pairs -1.5 / -1.4 / -1.03 / -0.99 / 0.3 / 0.013089 and vmov.f32 #1.0 x5; the sign tail
  (0xb3d2d8..0xb3da88) resolves a uniform by name through [signShader program] -> uniformLocations ->
  objectAtIndex:[name intValue] and then calls setColor: and renderWithProjectionMatrix:modelViewMatrix: on bitmapString@120.


- **The objectType tail lands (integration addition, ts_26)**: `TrainStation -[objectType]` @0xb380c0 is the 7-word class-constant stub returning **49** (`movw r2,0x31; mov r0,r2; bx lr`). The instruction words and the constant cross-check byte-for-byte against the checked-in `dynamicobject_type_objecttype_matrix.json` TrainStation row (imp 0x00b380c0, type_id 49). With this tail the class closes 29/29 on the ledger refs axis.
## Boundaries

- **TRIMMED bodies (roster flag) recorded as-is**: ts_05, ts_13, ts_17, ts_18 and ts_21 share an ARM.exidx function entry with
  their neighbours (ts_17/ts_18/ts_21/ts_03 all sit inside the single exidx range 0xb3f108..0xb3f198; ts_05/ts_06 share
  0xb3e730..0xb3e768; ts_13/ts_14 share the range ending 0xb3fa08), so their per-body bounds use the next-IMP rule instead of
  the exidx end. Nothing was extended into a neighbour: every captured stream is complete and ends in its own bx lr, the
  trailing literal-pool words that fall inside the bound are included (e.g. ts_21's two pool words at 0xb3f158/0xb3f15c), and
  no instruction of a neighbouring method is present. In the table, words = listing rows = instructions + trailing pool or
  alignment words (ts_12's 8th word is an andeq filler at 0xb3a2ac), which is why 7-word predicates have 7 rows for 5
  instructions plus their value word.

- **Out-of-line stubs are outside the roster by construction**: ts_23 ends at exidx 0xb3a218 and its two bl targets
  0xb3a218 / 0xb3a244 are the Vector2 and 4-float Vector constructors emitted between methods (decoded read-only with GNU
  objdump: 0xb3a218 stores r1 to [r0] and r2 to [r0+4]; 0xb3a244 stores r1/r2/r3/[sp] to [r0..r0+12]). ts_04 calls the
  adjacent thunks 0xb3dcf4 (x3), 0xb3dedc (x6), 0xb3e49c (x2), 0xb3e510 (x1) and 0xb3a244 (x1); none of these were decoded
  in this batch, so their bodies are unnamed. The plist helpers reached from ts_01 (0xb39960) and ts_11/ts_15 (0xb3945c ->
  0xb3fa08) are likewise local unnamed stubs - their identity (writer / reader of NSPropertyListSerialization) is inferred
  from the only selector cells they reference, not from a symbol, because the nearest exported symbol is the unrelated
  _Z18getRandomWorldNamev.

- **ts_10 probe/fill cross pairing is compiled, not a transcription slip**: probe (x+1,y) gates the fillTile at (x-1,y) and
  probe (x-1,y) gates the fill at (x+1,y). Evidence is the raw listing immediates (add r3,r3,1 at 0xb38cfc; sub ip,ip,1 at
  0xb38d6c; sub r3,r3,1 at 0xb38e0c; add ip,ip,1 at 0xb38e7c) plus makeIntpair@0x4b49fc, which writes arg1 to [r0] and arg2 to
  [r0+4]. The source-level intent behind the swap is not recoverable from the binary and is not asserted.

- **Interpretations separated from immediates**: the "3x2 station footprint" phrasing for ts_16's six removeTile coordinates
  and the "station tile plus horizontal neighbours" phrasing for ts_19 are readings of the immediate coordinates
  ((x,y),(x-1,y),(x-1,y+1),(x,y+1),(x+1,y),(x+1,y+1) and (x,y),(x-1,y),(x+1,y)); the coordinates themselves are read off the
  add/sub immediates. ts_19's three removeRailAtPos: calls are unconditional (0 branches) - there is no tile lookup before
  the rails are removed. For ts_25 the "|wrapped dx| < 2" and "entry.y == pos.y - 1" gates come from
  `cmp r0,2 / bge 0xb3f740` and `cmp r2,r0 / bne 0xb3f740`; the abs helper 0xb3f7b4 itself was not decoded, so that step is
  inferred from the call shape (single argument, compared against 2). ts_16's fillTile withType 0xc7 (199) is an immediate;
  tile type 199 was not identified against a tile-type table in this batch (only the neighbouring ItemType 200 = TrainStation
  is name-backed).

- **Name provenance kept separate**: ItemType 200 as "TrainStation" comes from the pinned reference enum snapshot
  (reference_itemtype_enum.txt, third-party MIT labels with numerics corroborated by in-repo ELF extractions), and
  interactionObjectType 6 is named only by the E-sibling convention (base 0, Chest 2, TradingPost 5); no independent
  InteractionObjectType enum table was consulted here. The save-dict keys text/ownerID/ownerName and the shader names
  StandardObject/FreeBlock/WorldObject plus the attribute/uniform names are hard evidence: they are decoded from the 16-byte
  CFString constant records (isa 0, flags 0x7c8, cstr pointer, length) in the pinned ELF.

- **Selector-cell resolution model (differs from the E154 note)**: in this build the cell content is the VA of the
  __objc_methname string itself (one deref, e.g. cell 0x00e86574 holds 0xf17cb2 = the byte address of "isAdmin"), so a
  two-level selref-word dereference yields garbage - 86/86 cells were resolved with the one-deref model and matched their
  expected names. Class cells are two kinds: 9 of 15 hold an in-file class pointer (OBJC_CLASS_$_TrainStation cell 0x00e8be8c
  holds 0x00e91db8, equal to the class_metadata class_addr), while the Foundation class cells (NSString, NSArray,
  NSMutableDictionary, NSMutableData, BitmapString's neighbours) read 0 in the file and are bound by the dynamic linker
  through .rel.dyn, so their identity is from the relocation table, not from the file word.

- **ts_04 is a census, not a decode**: the call histogram, the 0 backward branches, the gl-API counts, the selector/ivar
  inventory and the inline constant set are exact counts over the listing; three windows (entry/head bind pass, the sign
  tail, the drawShaderQuad region) were read in full, but the ~3600 instructions in between were not traced one by one, so no
  per-instruction claim is made there, and the 52 objc_msgSend sites are counted rather than individually attributed. One
  constant is left unexplained: 0x3c567344 = 0.013089. ts_09 is census-lite for the same reason: the preload block and slot
  table are exact, the 19 call sites and their selector/receiver slots are exact, but the individual argument registers of
  the two shaderNamed:attributes:uniforms: calls were not traced one by one.

- **Static evidence only (level A)**: r2 pD listings + byte-identical GNU objdump cross-check (26/26 bodies, 6808/6808 rows)
  + direct ELF reads at file-offset == vaddr (ivar words, cell words, CFString records, the makeIntpair and Vector/Vector2
  ctor stubs, the 0x4b49fc and helper bodies) + class_metadata.json ivar tables + the specs' resolved cell/route maps. No
  runtime or device probes, no Unicorn execution, no differential testing were performed for any of the 26 bodies.

- **Scope**: exactly the 26 ts_* targets in targets.json. Batch-directory writes only - semantics_trainstation.json,
  findings_trainstation.md and the analysis scripts under _work/ (read.py, rd.py, verify.py, verify_cells.py,
  cells_in_range.py, resolve.py, sends.py, slots.py, census.py, stats.json, cells_report.json). No make_deliverables call, no
  repository writes, no git operations.

