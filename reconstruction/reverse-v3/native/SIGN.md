# Sign (E147)

The Sign interaction object lands: the text bitmap render pipeline, the connection-type switching and the world-change recompute. 36 bodies, 6132 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| sg_00 | Sign -[actionTitle] | 0x00600b94 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| sg_01 | Sign -[canBeUsedByBlockhead:] | 0x00600f24 | 120 | 5 | 2 | 2 | 1 | 5 | 5 |
| sg_02 | Sign -[connectionType] | 0x006012d8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| sg_03 | Sign -[creationNetDataForClient:] | 0x005fb474 | 131 | 5 | 1 | 2 | 1 | 8 | 2 |
| sg_04 | Sign -[dealloc] | 0x005fb7ec | 64 | 2 | 2 | 2 | 1 | 3 | 0 |
| sg_05 | Sign -[destroyItemType] | 0x00600b48 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_06 | Sign -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x005fcaf0 | 2498 | 15 | 2 | 12 | 0 | 117 | 45 |
| sg_07 | Sign -[freeBlockCreationDataA] | 0x00600540 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_08 | Sign -[freeBlockCreationDataB] | 0x0060055c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_09 | Sign -[freeBlockCreationSaveDict] | 0x006004f4 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| sg_10 | Sign -[freeblockCreationItemType] | 0x006004a8 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| sg_11 | Sign -[initSubDerivedItems] | 0x005f9b00 | 430 | 6 | 14 | 9 | 1 | 14 | 15 |
| sg_12 | Sign -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] | 0x005fa1b8 | 268 | 4 | 2 | 6 | 1 | 7 | 13 |
| sg_13 | Sign -[initWithWorld:dynamicWorld:cache:netData:] | 0x005fa89c | 374 | 12 | 5 | 6 | 1 | 20 | 9 |
| sg_14 | Sign -[interactionObjectType] | 0x005fa5e8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_15 | Sign -[interactionRenderItemType] | 0x00601104 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_16 | Sign -[isPaintable] | 0x00601264 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_17 | Sign -[isSignSubclass] | 0x005fae98 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_18 | Sign -[loadRemoteUpdateDataDict:] | 0x005fc5a4 | 120 | 4 | 4 | 2 | 0 | 8 | 0 |
| sg_19 | Sign -[netDataExtraDataDict] | 0x005fb268 | 131 | 2 | 4 | 3 | 1 | 4 | 3 |
| sg_20 | Sign -[occupiesForegroundContents] | 0x00601280 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_21 | Sign -[offsetType] | 0x0060129c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| sg_22 | Sign -[paint:] | 0x00601120 | 81 | 3 | 1 | 5 | 0 | 3 | 1 |
| sg_23 | Sign -[remoteUpdate:] | 0x005fc784 | 165 | 7 | 2 | 4 | 1 | 8 | 2 |
| sg_24 | Sign -[remove:] | 0x00600578 | 372 | 8 | 1 | 10 | 0 | 13 | 17 |
| sg_25 | Sign -[removeFromMacroBlock] | 0x005fb8ec | 27 | 1 | 1 | 0 | 1 | 1 | 0 |
| sg_26 | Sign -[requiresHumanInteraction] | 0x00600bc4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_27 | Sign -[requiresSingleLineTextEditing] | 0x00600f08 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sg_28 | Sign -[setNeedsRemoved:] | 0x00600be0 | 182 | 2 | 1 | 4 | 1 | 7 | 8 |
| sg_29 | Sign -[setText:] | 0x005fc3e8 | 96 | 6 | 1 | 3 | 0 | 6 | 1 |
| sg_30 | Sign -[text] | 0x005fc568 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| sg_31 | Sign -[title] | 0x00600b64 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| sg_32 | Sign -[twoBlocksWide] | 0x00600eb8 | 20 | 0 | 0 | 1 | 0 | 0 | 0 |
| sg_33 | Sign -[updateBitmapString] | 0x005fb958 | 259 | 5 | 1 | 5 | 2 | 12 | 6 |
| sg_34 | Sign -[updateNetDataForClient:] | 0x005fb214 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| sg_35 | Sign -[worldChanged:] | 0x005ffb58 | 596 | 4 | 1 | 8 | 0 | 16 | 31 |

## Findings (E147)

- **The Sign batch lands**: 36 bodies / 6,132 words / 158 branches / 255 call rows of `Sign` (InteractionObject subclass, instance_size 121; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). Implementation span 0x5f9b00..0x601314 (targets ordered by selector name, not address; the 36 IMPs sit among the class's remaining methods, e.g. `initWithWorld:dynamicWorld:saveDict:cache:` @0x5fa604, `getSaveDict` @0x5faeb4, `update:accurateDT:isSimulation:` @0x5fca18 which are NOT in this batch). Roster names sg_00..sg_35, 0 collisions; 9 bodies TRIMMED at the next IMP (sg_00/05/07/10/16/20/21/31/32, boundary case 2). Grades: **sg_06 [census]** (2498w); 4 [census-lite] (sg_11 430w, sg_13 374w, sg_24 372w, sg_35 596w); 31 bodies <=268w fully read. Mechanical layer regenerated this run: `gen_listings.py` ("bodies 36 words 6132", entrypoint warnings only) + `build_specs.py` (36 bodies, 255 call rows, 36 routes). Listing rows == word count for every body (verified programmatically: 0 mismatches).

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | sg_00 | `Sign -[actionTitle]` | 12 | 0 | 0 | read |
  | sg_01 | `Sign -[canBeUsedByBlockhead:]` | 120 | 5 | 5 | read |
  | sg_02 | `Sign -[connectionType]` | 15 | 0 | 0 | read |
  | sg_03 | `Sign -[creationNetDataForClient:]` | 131 | 2 | 8 | read |
  | sg_04 | `Sign -[dealloc]` | 64 | 0 | 3 | read |
  | sg_05 | `Sign -[destroyItemType]` | 7 | 0 | 0 | read |
  | sg_06 | `Sign -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]` | 2498 | 45 | 117 | census |
  | sg_07 | `Sign -[freeBlockCreationDataA]` | 7 | 0 | 0 | read |
  | sg_08 | `Sign -[freeBlockCreationDataB]` | 7 | 0 | 0 | read |
  | sg_09 | `Sign -[freeBlockCreationSaveDict]` | 19 | 0 | 1 | read |
  | sg_10 | `Sign -[freeblockCreationItemType]` | 19 | 0 | 1 | read |
  | sg_11 | `Sign -[initSubDerivedItems]` | 430 | 15 | 14 | census-lite |
  | sg_12 | `Sign -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]` | 268 | 13 | 7 | read |
  | sg_13 | `Sign -[initWithWorld:dynamicWorld:cache:netData:]` | 374 | 9 | 20 | census-lite |
  | sg_14 | `Sign -[interactionObjectType]` | 7 | 0 | 0 | read |
  | sg_15 | `Sign -[interactionRenderItemType]` | 7 | 0 | 0 | read |
  | sg_16 | `Sign -[isPaintable]` | 7 | 0 | 0 | read |
  | sg_17 | `Sign -[isSignSubclass]` | 7 | 0 | 0 | read |
  | sg_18 | `Sign -[loadRemoteUpdateDataDict:]` | 120 | 0 | 8 | read |
  | sg_19 | `Sign -[netDataExtraDataDict]` | 131 | 3 | 4 | read |
  | sg_20 | `Sign -[occupiesForegroundContents]` | 7 | 0 | 0 | read |
  | sg_21 | `Sign -[offsetType]` | 15 | 0 | 0 | read |
  | sg_22 | `Sign -[paint:]` | 81 | 1 | 3 | read |
  | sg_23 | `Sign -[remoteUpdate:]` | 165 | 2 | 8 | read |
  | sg_24 | `Sign -[remove:]` | 372 | 17 | 13 | census-lite |
  | sg_25 | `Sign -[removeFromMacroBlock]` | 27 | 0 | 1 | read |
  | sg_26 | `Sign -[requiresHumanInteraction]` | 7 | 0 | 0 | read |
  | sg_27 | `Sign -[requiresSingleLineTextEditing]` | 7 | 0 | 0 | read |
  | sg_28 | `Sign -[setNeedsRemoved:]` | 182 | 8 | 7 | read |
  | sg_29 | `Sign -[setText:]` | 96 | 1 | 6 | read |
  | sg_30 | `Sign -[text]` | 15 | 0 | 0 | read |
  | sg_31 | `Sign -[title]` | 12 | 0 | 0 | read |
  | sg_32 | `Sign -[twoBlocksWide]` | 20 | 0 | 0 | read |
  | sg_33 | `Sign -[updateBitmapString]` | 259 | 6 | 12 | read |
  | sg_34 | `Sign -[updateNetDataForClient:]` | 21 | 0 | 1 | read |
  | sg_35 | `Sign -[worldChanged:]` | 596 | 31 | 16 | census-lite |

- **What the class is**: Sign is the interactable sign object (wood/stone sign family; `interactionObjectType` = 4, sg_14). It stores the player-written string (`text@100`), a lazily-built `BitmapString` renderer (`bitmapString@104`), the destruct overlay texture (`tileDestructTexture@108`), wall-connection info (`connectionType@112`, `offsetType@116`) and a `blackText@120` flag. It inherits the whole ownership/isInUse/net protocol from InteractionObject (E146) and adds: a hardcoded `title`/`actionTitle` pair, the text lifecycle (setText: → updateBitmapString), the packed wire protocol (0x30-byte struct + gzipped plist), and the tile-marker bookkeeping for its wall-connection side (tile byte +0xb = 0x30).
- **Identity / constants**: `title` = static CFString **"SIGN"** @0xF7E3D8 (sg_31; base class returns @""), `actionTitle` = static CFString **"CHANGE SIGN"** @0xF7E3E8 (sg_00; NOT [self title], unlike the base class). `interactionObjectType` = 4 (uxth), `interactionRenderItemType` = 0xa3 = 163 (sg_15) and `destroyItemType` = 0xa3 = 163 (sg_05) - the same item id 163 is both the dropped item and the render item. Booleans: `isPaintable` YES (sg_16; base NO), `occupiesForegroundContents` YES (sg_20), `requiresHumanInteraction` YES (sg_26), `requiresSingleLineTextEditing` NO (sg_27), `isSignSubclass` NO (sg_17), `twoBlocksWide` = `offsetType != 0` (sg_32). `freeBlockCreationDataA`/`B` = 0 (sg_07/08), `freeBlockCreationSaveDict` = [self getSaveDict] (sg_09), `freeblockCreationItemType` = [self destroyItemType] (sg_10). Accessors `text`/`connectionType`/`offsetType` are plain unloc-chain ivar getters (sg_30/02/21).
- **Text lifecycle**: `setText:` (sg_29) = `if ([text isEqualToString:self.text]) return; [self.text autorelease]; self.text=[text retain]; [self updateBitmapString]; [[self.dynamicWorld] dynamicWorldChangedAtPos:self.pos objectType:[self objectType]]` (no isNet gate, no updateNeedsToBeSent - paint: differs, see below). `updateBitmapString` (sg_33) releases+nils the old BitmapString; requires text; sets `blackText@120` via a luminance rule on the color-converted paintColor (`c.y > 0.75 - 0.25*(c.x+c.z)`, helper 0x5fbd64 converts the u16 nibble color to RGBA floats); rebuilds `bitmapString` as `[[BitmapString alloc] initWithString:text dimensions:{130.0f,48.0f} horizontalAlignment:1 font:(blackText ? [BitmapFont blackFont] : [BitmapFont embossedFont]) cache:self.cache color:(1,1,1,1)]`. `paint:` (sg_22) stores paintColor, rebuilds the bitmap string, and if not net marks `updateNeedsToBeSent` + notifies `dynamicWorldChangedAtPos:objectType:` - that notification shape is shared with setText: (both pass pos as an {x,y} word pair + objectType on the stack).
- **Net protocol (SignCreationNetData)**: writer `creationNetDataForClient:` (sg_03) emits a 0x30-byte blob: 0x28 bytes of `[self interactionObjectCreationNetData]` + `connectionType` (char @+0x28) + `offsetType` (char @+0x29); then appends `gzip([self netDataExtraDataDict])`, where the extra dict (sg_19) carries `text`/`ownerID`/`ownerName` (keys CFSTR @0xF7E388/3B8/3C8; only non-nil values stored) - the dict is serialized to an XML plist by the local helper @0x5fb680 (`dataWithPropertyList:format:100 options:0`, @try/@catch + NSLog). `updateNetDataForClient:` (sg_34) is a pure forward to sg_03. Reader `initWithWorld:dynamicWorld:cache:netData:` (sg_13) getBytes 0x30 -> `connectionType`/`offsetType` from buf[0x28/0x29]; subdata {0x30, len-0x30} -> gzipInflate -> plist helper @0x5fae74/0x601824 -> `text`/`ownerID`/`ownerName` retained straight into the ivars; `[self initSubDerivedItems]`; then (unless isSignSubclass) fast-enumerates `[self.dynamicWorld blockheads]` and calls `[b netInteractionObjectWasLoaded:self]`. Delta reader `remoteUpdate:` (sg_23) supers first, and only when the super pass left `currentBlockhead == nil` re-reads the extra payload (`subdata/length-0x30` -> gzipInflate -> plist -> `loadRemoteUpdateDataDict:` (sg_18), which re-applies text/ownerName/ownerID with release/retain). It then unconditionally re-reads the fixed 0x30 bytes (`getBytes:`) and refreshes `connectionType`/`offsetType` from buf[0x28/0x29], and calls `updateBitmapString` when the super pass changed paintColor. Note sg_03's dataWithBytes length (0x30) vs bytes actually written (0x2A) - see Boundaries.
- **Placement / markers / removal**: placing ctor sg_12 (9 args) supers, sets `text` from saveDict["text"], computes `connectionType`/`offsetType` via the C helper `signConnectionTypeAndOffsetForPos(pos, &offsetType, world, 0)` @0x5f85a0 (in sg_35 the same helper is re-run with the *current* connectionType as 4th arg), sets tile byte `[tile+0xb]=0x30` on the connection side (pos.x+1 for offsetType==1, pos.x-1 for offsetType==2), overrides `flipped = (offsetType==2)`, then `initSubDerivedItems`. sg_11 builds the render assets (shader "WorldObjectNewLighting" with its attribute/uniform name arrays, "TileMap.png" texture, "TileDestruct.png"+"TileReflect.png" destruct pair) and plants the 0x30 marker at the sign's own tile plus the connection-side tile. `setNeedsRemoved:` (sg_28) clears the connection-side 0x30 marker (matching guard `t[0xb]==0x30`), notifies `worldContentsChangedAtPos:`, then supers. `remove:` (sg_24) is the full removal tail (NOT the E146 stub): needsRemoved/isNet guards; in-use handling (kick currentBlockhead; park into `needsToBeRemovedWhenInteractionEnds` when the holder or remote UID is net/remote); old-side marker clear; `[dynamicWorld createFreeBlockAtPosition:... ofType:[self destroyItemType] ... priorityBlockhead:removeArg]`; `[world removeTileAtWorldX:... removeBlockhead:removeArg onlyRemoveForegroundContents:1]`; `[self setNeedsRemoved:1]`. `removeFromMacroBlock` (sg_25) is a bare super call. `canBeUsedByBlockhead:` (sg_01) adds an admin shortcut and an owner check on top of the E146 default: `(world.isAdmin && !bh.isClientBlockheadBeingControlledByServer) -> YES; else super result, ANDed with [[bh localNetID] isEqualToString:self.ownerID] when ownerID set`.
- **worldChanged: (sg_35)**: sole consumer of the `vector<intpair>*` change list among the decoded batches - supers' per-tick change notification drives re-derivation of this sign's wall connectivity: for every changed tile inside the 3x3 neighborhood of the sign, re-run `signConnectionTypeAndOffsetForPos`, tear down the old side's marker, install the new side's marker, update `flipped`/`connectionType`/`updateNeedsToBeSent`, and notify `dynamicWorldChangedAtPos:objectType:`; if the sign ends up with `connectionType == 0` (no wall to attach) it calls `[self remove:0]`. Straight-line per item (no nested loops); 328-byte frame; no VFP (all integer + makeIntpair).
- **draw: (sg_06, census)**: a 2498-word, 2336-byte-frame, strictly straight-line (zero back-edges) renderer: camera/world clamping via `[world worldWidthMacro]` x32 + `__aeabi_idiv` + Vector2 ops with early-outs; a macro-tile liveness check (`tileAtWorldPosition:...MacroTile:...`); `[self.shader@60 use]` -> glUseProgram + uniform-location lookups (`uniformLocations`/`objectAtIndex:`/`intValue`) -> glUniform1i x2; the tile image index comes from a switch on `connectionType-1` (jump table @0x5fd564: 1->(interactionObjectType==8 ? 0x28a : 0xb2), 2->0x28e, 3->0x28c + destruct-overlay flag, 4->0x28c; unconnected base 0xb0 or 0x288 for type 8) -> `paintedIndexForImageIndex`; UVs are atlas-normalized (/1024.0f @0x5fd9d4, clamped <=1, scaled by 1/(0.3f+[+0x1e4]), /255.0f @0x5fd9dc); three texture bind/activate passes (main texture unit 0, destruct texture unit 1/2) plus 4x glUniform4f color vectors; the mvp matrix is built by local helper 0x5ff3e0 and uploaded via glUniformMatrix4fv(loc,1,0,ptr); `glEnable(GL_BLEND)` + `pushDepthMaskState()`; positions are doubles (world x 1/32 = 0.03125 with +1/2048 offsets; f64 consts @0x5fe1e0-f0) plus a +/-5.0f flip adjustment; `drawShaderQuad` #1 emits the quad (10 float args from the computed rect at [+0xdc..+0xf0]); when the destruct flag is set, a texture frame is derived via `__modsi3(180)`/`__aeabi_idiv(32)` with f64 consts {1/2048, 1/1024, 5/4096}, the quad edges are rotated when `offsetType==1`, v edges shrink by 0.0009765625, and `drawShaderQuad` #2 draws the destruct strip; then textures are unbound, and if `bitmapString@104` exists it takes `[bitmapString setColor:lightVector]` (light = byte/255 lerp, f64 0.9/0.2 consts), local uniform helpers 0x5ff1f8/0x5ff9a0 (@sp+0x5d0 / @sp+0x550, consts 0.2f 0x3e4ccccd, 0.0125f 0x3c4ccccd) and finally `[bitmapString renderWithProjectionMatrix:modelViewMatrix:]`; ends with `glDisable(GL_BLEND)` + `popDepthMaskState()`.
- **Local helpers (out-of-batch, read-only cross-refs)**: 0x5fb680 plist-from-dict (used by sg_03), 0x5fae74 -> 0x601824 plist-from-data (used by sg_13/sg_23), 0x5fbd64 u16-nibble-color -> Vector4 (used by sg_33/sg_06), 0x5fc370 2-float struct writer, 0x5fc39c 4-float struct writer, 0x5ff1f8 / 0x5ff3e0 / 0x5ff9a0 (sg_06 uniform/matrix helpers, not decoded here). Shared C helpers reached directly: `signConnectionTypeAndOffsetForPos(intpair,int&,World*,int)` @0x5f85a0, `tileAtWorldPositionLoaded(int,int,World*)` @0xa12f24, `tileAtWorldPosition(int,int,MacroTile*,World*)` @0xa16e68, `makeIntpair(int,int)` @0x4b49fc (8-byte sret), `paintedIndexForImageIndex(int)` @0xa15e28.

## Boundaries

- **Grades**: sg_06 (2498w) is the batch's [census] body - decoded to the structural level (phase map, control-flow skeleton, constant truth, call groups, texture/shader sequence); its ~15 indirect `blx rN` call sites (register-target, mostly around the texture/uniform setup and the two drawShaderQuad blocks) are listed as call rows but their dynamic receivers are NOT resolvable statically. The 4 [census-lite] bodies (sg_11/13/24/35) were nevertheless read instruction-by-instruction (all branches and call rows traced); the remaining 31 bodies are <=268w and were fully read.
- **Trimmed bodies (9)**: sg_00/05/07/10/16/20/21/31/32 end at the next ObjC IMP rather than the ARM.exidx bound (boundary case 2). All 36 listings have rows == word count (verified programmatically), so no rows were dropped.
- **sg_03 blob size quirk**: the wire buffer is 0x30 bytes (`dataWithBytes:...length:0x30`, movw ip,#0x30 byte-verified) but only 0x2A bytes are explicitly written (0x28 IO blob + 2 strb chars); the remaining 6 bytes are stack garbage in the non-nil path (zeroed only via the nil-self memset of 0x28). Reported mechanically; the reader only consumes +0x28/+0x29/chars and the subdata offset 0x30, so the padding bytes are never read by any batch body.
- **sg_06 field decode is partial by design**: local stack slots are described by semantic role inferred from data flow (quad rect, UV rect, flags at sp+0x863/0x86b, image-index @sp+0x864); the exact struct types (the shader/uniform helpers' argument structs) are not named. The `draw:` tsv type string (`v156@0:4 f8(_GLKMatrix4...)12 i76 i140 i144 i148 i152`) is quoted as-is; the body treats arg3 as a preserved pointer (vmov s0 -> [+0x260]) and the mvp upload pointer comes from the local helper's buffer - whether the caller passes the matrices by pointer or by value is not fully resolved from this body alone.
- **sg_12/sg_11 marker duplication**: both bodies plant the same connection-side 0x30 marker (sg_12 for offsetType 1/2; sg_11 additionally the self-tile marker, and sg_11 runs from sg_12's tail), so the same tile byte can be written twice - the guard (`if (!t[0xb])` in sg_11/sg_12 vs `if (t[0xb]==0x30)` clears in sg_28/sg_24/sg_35) makes it idempotent, but the worldContentsChanged noise difference (gated in sg_11, unconditional in sg_24/28/35) is compiler/source shape, reported as-is. Tile byte `+0xb` semantic (what 0x30 means in the tile record) is not resolvable from this batch - only its set/clear discipline is evidenced.
- **worldChanged: vector internals**: the begin/end/iteration scaffolding is the O0 expansion of a range-for over `std::vector<intpair>`; the component comparisons are transcribed with their exact branch sense (skip when outside pos-1..pos+1). Which subsystem produces the change list and whether items can repeat is out of this batch.
- **Cross-class receivers not traced**: `getSaveDict`, `loadRemoteUpdateDataDict:`, `removeFromMacroBlock` (InteractionObject impl), `stopInteracting`, `netInteractionObjectWasLoaded:`, `worldContentsChangedAtPos:`, `createFreeBlockAtPosition:...`, `removeTileAtWorldX:...`, `shaderNamed:attributes:uniforms:`, `textureNamed:[withAlpha:]`, `renderWithProjectionMatrix:modelViewMatrix:`, BitmapFont/BitmapString APIs, `isAdmin`, `isClientBlockheadBeingControlledByServer`, `localNetID`, `worldWidthMacro`, `macroTiles`, `paintedIndexForImageIndex` are call targets on other classes - only selector/argument routing is evidence here.
- **VFP conventions**: sg_33/sg_06 use VFP heavily; all float immediates were taken from the GNU objdump (`_gl.txt`) annotations (1.0 0x3f800000, 0.75, 0.25, 130.0f 0x43020000, 48.0f 0x42400000, 1024.0f 0x44800000, 0.3f 0x3e99999a, 255.0f 0x437f0000, f64 0.03125/1e-3-range consts) and pool words were read by direct ELF struct reads (file offset == vaddr); r2 pool-row disassembly was not used for any value statement. sg_35/sg_24/sg_28 contain zero VFP instructions.
- **Formula transcription vs runtime**: sg_33's `c[1] > 0.75 - (c[0]+c[2])*0.25` luminance rule and sg_06's screen-space math are mechanical transcriptions; the unproven parts (e.g. which color component selection drives blackText, frame counter source `__modsi3(180)`) are stated as arithmetic, not as verified visual behavior. Static level-A evidence only (r2 pD + GNU objdump + ELF struct reads + tsv types + class_metadata): no runtime roundtrip, no device-side claims.
