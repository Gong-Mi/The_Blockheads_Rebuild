# Wire class closure (non-render) — init/save/net pairs, worldChanged adjacency refresh, utility bodies

The full non-render remainder of the `Wire` class (0x26 / type-0x60 wire
block): construction from position/save/net data, save-dict + net-data
serialization, remote updates, dealloc, the sub-derived static-geometry
reload, freeblock-creation constants, the adjacency-driven
`worldChanged:` refresh, and the two occupancy predicates. 18 bodies,
**2104 verified words** total, recovered from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_wire_closure.py`; JSON: `wire_closure.json`).

## Construction pair

- **`objectType`** (`0x0094fd48`..`0x0094fd64`, 7 words). Leaf:
  `return 0x26` - the wire dynamic-object type tag (same tag the
  `DynamicWorld wireAtPos:` / `addWireAtPos:` family passes around).
- **`initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:`**
  (`0x0094fd64`..`0x0095002c`, 178 words). `objc_msgSendSuper2(super,
  'initWithWorld:dynamicWorld:atPosition:cache:')`; nil -> nil;
  `Wire.itemType@56 = type`; save-dict branch (`retain` / `objectForKey:`
  pair) vs the no-saveDict branch; finishing calls
  `[self initSubDerivedItems]` + **`[self updateWireConfiguration]`**
  (the E1 configuration engine re-entry); return self.
- **`initWithWorld:dynamicWorld:saveDict:cache:`** (`0x0095002c`..
  `0x0095034c`, 200 words). Super call, nil guard, then restores
  `Wire.itemType@56` / `currentConfiguration@60` /
  `currentSolidConfiguration@64` from the save dict (`objectForKey:` +
  `intValue` + `retain` chains); a field reading 0 is forced to 1;
  `[self initSubDerivedItems]`; return self.
- **`initWithWorld:dynamicWorld:cache:netData:`** (`0x0095034c`..
  `0x00950688`, 207 words). Super call, nil guard; **`gzipInflate`** ->
  `subdataWithRange:` -> `length` / `getBytes:length:` -> unpack
  `{uint16 itemType@56, u8 currentConfiguration@60, u8
  currentSolidConfiguration@64}`; segments beyond `0x20` go through the
  private helper `0x00950688` (IMP gap, out of body);
  `[self initSubDerivedItems]`; return self.

## Save + net serialization

- **`getSaveDict`** (`0x00950770`..`0x00950a64`, 189 words). `dict =
  [super getSaveDict]` (stret); `[dict setObject:[NSNumber
  numberWithInt:itemType@56] forKey:]` + `currentConfiguration@60` +
  `currentSolidConfiguration@64`; when `ownerID@36` non-nil an extra
  `setObject:forKey:`; return dict.
- **`updateNetDataForClient:`** (`0x00950a64`..`0x00950ab8`, 21 words).
  Single forward: `[self creationNetDataForClient:client]`.
- **`creationNetDataForClient:`** (`0x00950ab8`..`0x00950dbc`, 193 words).
  Reads the client's `dynamicObjectNetData` blob (0x18 bytes via
  `objc_msgSend_stret`; `memset 0` when client is nil); fills
  `{uint16 itemType@56, u8 currentConfiguration@60, u8
  currentSolidConfiguration@64}`; wraps via `dataWithBytes:length:` /
  `appendData:` + **`gzipDeflate`** into the dictionary record; non-zero
  field -> extra `setObject:forKey:`; private helper `0x00950dbc` (IMP
  gap, out of body); returns the assembled dict.
- **`remoteUpdate:`** (`0x00950f28`..`0x009510f8`, 116 words). `[super
  remoteUpdate:data]`; `[data getBytes:buf length:0x20]`; when the buf
  `{cfg,solid}` pair differs from `currentConfiguration@60` /
  `currentSolidConfiguration@64` -> write both + rebuild static geometry
  (`macroTiles` + `reloadDrawBlockDynamicObjectStaticGeometryForTile` on
  the pos pair); unchanged -> no-op.

## Lifecycle + helpers

- **`dealloc`** (`0x009506ac`..`0x00950770`, 49 words).
  `[self.ownerID@36 release]; objc_msgSendSuper2(super, dealloc)`.
- **`initSubDerivedItems`** (`0x0094fca0`..`0x0094fd48`, 42 words). Reads
  the pos pair (`DynamicObject.pos@16` writeback) + `world@4`; one
  `objc_msgSend` for `macroTiles`; then
  `reloadDrawBlockDynamicObjectStaticGeometryForTile(posPair,
  macroTiles, world)`.
- **`removeFromMacroBlock`** (`0x00954a2c`..`0x00954b34`, 66 words).
  Same reload pattern; then `objc_msgSendSuper2(super,
  'removeFromMacroBlock')`. Body trimmed to the next IMP (exidx
  over-covered `0x00954c74`).
- Freeblock-creation constants: **`freeblockCreationItemType`**
  (`0x00951320`..`0x0095135c`, 15 words) = `*(int *)(self + 56)` getter
  (`itemType@56`); **`freeBlockCreationSaveDict`** = nil;
  **`freeBlockCreationDataA`** = 0; **`freeBlockCreationDataB`** = 0
  (7 words each).

## worldChanged: adjacency refresh

**`worldChanged:`** (`0x009513b0`..`0x00951ef0`, 720 words). Gate:
`itemType@56 != 0xb2` -> return. Loop over the changed `{x,y}` vector
(8-byte stride) with wrap-aware distance normalization (macro-size value
`<< 5` then `/ 2` via `__aeabi_idiv`; helper `0x00951ef0` in the IMP tail,
out of body). Two cases per changed position:

- **Own cell** (`x,y == pos@16`): `tileAtWorldPositionLoaded` +
  `tileIsWater` + workbench gate; qualifying positions go to
  **`createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:`**
  + `removeStandardObject:` (`needsRemoved@48`; `isClient` via
  `dynamicWorld@8`).
- **Neighbor**: four probes around `(x,y)` with the `tile[1]==2`,
  non-nil, `!tileIsSolid`, `tile[3] != 0x60`, `tile[3] != 0x2e` screens
  -> `[self updateWireConfiguration]`.

## Occupancy predicates

- **`occupiesForegroundContents`** (`0x00954b34`..`0x00954bd4`, 40 words)
  = `tile[0xb] == 0x60` at the wire's own position.
- **`occupiesNormalContents`** (`0x00954bd4`..`0x00954c74`, 40 words)
  = `tile[3] == 0x60` at the wire's own position.
- Both via `tileAtWorldPositionLoaded(pos.x, pos.y, world)`; `0x60` is
  the wire block id.

## Anchors

- Cells: `Wire.itemType@56` / `currentConfiguration@60` /
  `currentSolidConfiguration@64`; `DynamicObject.ownerID@36` / `pos@16` /
  `world@4` / `dynamicWorld@8` / `needsRemoved@48`; classref
  `OBJC_CLASS_$_Wire`; selectors `macroTiles`, `retain`,
  `objectForKey:`, `intValue`, `initSubDerivedItems`,
  `updateWireConfiguration`, `numberWithInt:`, `setObject:forKey:`,
  `length`, `getBytes:length:`, `gzipInflate`, `gzipDeflate`,
  `subdataWithRange:`, `dynamicObjectNetData`, `dataWithBytes:length:`,
  `appendData:`, `dictionary`, `remoteUpdate:`, `dealloc`, `release`,
  `isClient`, `removeStandardObject:`, `createFreeBlockAtPosition:...`,
  `worldWidthMacro`; imports `objc_msgSend` / `objc_msgSendSuper2` /
  `objc_msgSend_stret` / `__aeabi_idiv` / `memset` / `memcpy`.
- All 83 call sites pinned (2/0/7/10/10/2/8/1/9/4/0/0/0/0/25/3/1/1), all
  70 branches pinned.
- Key callees: `reloadDrawBlockDynamicObjectStaticGeometryForTile`
  (`0x00a19598`), `tileAtWorldPositionLoaded` (`0x00a12f24`),
  `tileIsSolid` (`0x00a1179c`), `tileIsWater` (`0x00a11690`), private
  helpers `0x00950688` / `0x00950dbc` / `0x00951ef0`.

## Boundaries

- Bodies are next-IMP bounded; three tails are private helpers inside IMP
  gaps (excluded): `0x00950688` (initnet), `0x00950dbc` (creationnet),
  `0x00951ef0` (worldchanged). `removeFromMacroBlock` trimmed to next IMP
  `0x00954b34`; `occupiesForegroundContents` trimmed to next IMP
  `0x00954bd4` (exidx over-covered into its sibling).
- The render trio (`draw:projectionMatrix:...`,
  `staticGeometryDrawCubeCount`, `addDrawCubeData:fromIndex:`) is a
  separate batch; grid/cache internals of `macroTiles` and the reload
  helper are out of body scope.
