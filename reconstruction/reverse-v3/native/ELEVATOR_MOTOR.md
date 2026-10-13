# ElevatorMotor closure — the elevator motor (DynamicObject 0x37)

The elevator motor half of the elevator family: init trio pairs, the photo of
its power contract (E1's hasRequiredPower/usePower + the 15-unit charge loop),
rail re-scan on world change, atomic minY/maxY accessors, static-geometry
drawing, and the save/net serialization quartets. 26 bodies, **2569 verified
words** total, recovered from the pinned original `libApplication.so` (1.7.6,
armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_elevator_motor.py`; JSON: `elevator_motor.json`).

## Power contract (E7 core)

- **`update:accurateDT:isSimulation:`** (0x007017a0, 159w): gate `!isNet`; while
  `availableElectricity` (u16@60) < `0xf`: decrement
  `timeUntilNextPowerCheck` (float@72) by accurateDT; at <= 0 reset to
  **5.0f**; `pending = 0xf - availableElectricity`;
  **`[dynamicWorld findAndSubtractAllPowerUpTo:pending forUser:0]`** (E2
  engine) - if result > 0: `availableElectricity += result` (strh),
  `[self objectType]` / `[dynamicWorld dynamicWorldChangedAtPos:objectType:]`,
  `updateNeedsToBeSent = 1`.
- **`remoteUpdate:`** (178w): super2 + `getBytes:length:` decode of u16
  fields (availableElectricity / minY / maxY); `!isNet` path clears
  timeUntilNextPowerCheck to 0.0f / decrements availableElectricity (clamped
  at 0); `isNet` path writes the three fields back + change replay.
- E1 batch (separate commit): `hasRequiredPower` / `usePower` (20/88w).

## Rail geometry

- **`initWithWorld:...atPosition:...`** (303w): super2 init; vertical scans
  `tileAtWorldPositionLoaded(x, i)` while `tile[3] == 0x67` (elevator-rail
  tile) upward for **maxY**@68 and downward for **minY**@64; nil-saveDict
  branch restores itemType/extra field via `objectForKey:` + `intValue`.
- **`worldChanged:`** (396w): external intpair-vector iteration (8-byte
  steps); per change: if `change.x == pos.x`: rail-lost inside
  [minY..maxY] -> shrink (maxY = y-1 / minY = y+1) with
  updateNeedsToBeSent; rail-extension at the boundary -> re-scan to 0x400 /
  down to 0; re-scan rejects non-`0x67` tiles.
- **minY / maxY / setMinY: / setMaxY:** = **dmb ish atomic accessors**
  (offsets 64/68; loads + stores both fence-flagged).
- **`objectType` = 0x37** (55); `isStorageDevice` = 0; `occupiesNormalContents` = 1.

## Serialization quartets

- **`getSaveDict`** (223w): super stret dict + numberWithInt pairs for the
  u16 fields + conditional extra key (CFString keys 0xfff273xx - v2-era
  keys, not resolvable in this build).
- **`initWithWorld:...saveDict:`** (218w): `objectForKey:` + `intValue`
  decode of six fields (one strh u16).
- **`creationNetDataForClient:`** (223w): super 0x18-byte net struct + one
  memcpy frame (12 words from the six u16 fields) + appendData pair +
  helper 0x70136c (gzip region).
- **`initWithWorld:...netData:`** (217w): 0x28-byte stack buffer +
  `getBytes` decode (four u16 fields; two strh + two str) + helper
  0x700b38 + tail chain.
- **`updateNetDataForClient:`** (21w) = `[self creationNetDataForClient:arg]`
  forward; **`freeBlockCreationSaveDict`** (19w) = `[self getSaveDict]`
  forward; freeblockDataA/B = 0; freeblockCreationItemType = ivar load.

## Static geometry

- **`initSubDerivedItems`** (42w): `[self macroTiles]` +
  `reloadDrawBlockDynamicObjectStaticGeometryForTile(pos, ...)`.
- **`removeFromMacroBlock`** (66w): reload + **`[super removeFromMacroBlock]`**
  (objc_msgSendSuper2).
- **`staticGeometryDrawCubeCount` = 1**; **`draw:`** (138w) = arg-frame
  reshuffle shim (0 calls / 0 branches); **`addDrawCubeData:fromIndex:`**
  (195w) = DrawCube builder: floatPos (+5y), z = -1.5f (0xbfc00000),
  helper 0x702660, `texCoordsForImageIndex(0x248)` (**texture 584**),
  20-word vertex block, **`fillBuffer:fromIndex:matrix:...:macroWorldY:`**
  (20-arg, objc_msgSend).
- **`dealloc`** (49w) = release + super2.

## Anchors

- 26 bodies pinned: imp/boundary_end per body (0x006ffeec..0x00702ac4
  span); 72 call sites, 82 branches, 11 route targets
  (reloadDrawBlockDynamicObjectStaticGeometryForTile 0x1c6504? via bl
  resolution, tileAtWorldPositionLoaded, texCoordsForImageIndex, helper
  0x702660 + 0x70136c + 0x700b38, memcpy/memset, objc_msgSend /
  objc_msgSendSuper2 / objc_msgSend_stret).
- Cells: 43 selectors (`macroTiles`, `findAndSubtractAllPowerUpTo:forUser:`,
  `dynamicWorldChangedAtPos:objectType:`, `getBytes:length:`,
  `creationNetDataForClient:`, `getSaveDict`,
  `fillBuffer:...:macroWorldY:`, ...), 16 imports, 58 ivar cells
  (itemType@56 / availableElectricity@60 / minY@64 / maxY@68 /
  timeUntilNextPowerCheck@72; DynamicObject pos@16 / world@4 / ownerID@36 /
  updateNeedsToBeSent@49), 8 class cells (OBJC_CLASS_$_ElevatorMotor,
  OBJC_CLASS_$_DrawCube).

## Boundaries

- ElevatorShaft (27 bodies / approx 5187w) and TradePortal (54 bodies /
  approx 8616w) are separate campaigns. E1's hasRequiredPower/usePower stay
  in the E1 commit; `setMaxY:` body trimmed at 0x00702ac4 (exidx
  over-covers); `draw:` submits no GL in-body (caller frame only).
