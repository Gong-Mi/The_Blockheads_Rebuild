# ElevatorShaft closure — the rail-and-door shaft (DynamicObject 0x38)

The shaft half of the elevator family (motor closed in E7): door rail
tracking, the solid/open/door draw pipeline, paint, and the save/net
quartets. 26 bodies, **4175 verified words** total, recovered from the
pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_elevator_shaft.py`; JSON: `elevator_shaft.json`).

## Door contract

- State ivars: **solidTile@86** (byte), **opening@68** (byte),
  **paintColor@84** (u16), **lastKnownMotorPos@60** (intpair),
  **itemType@56**.
- **`open`** (16w) = stores byte 1 to `opening@68`.
- **`staticGeometryDrawCubeCount`** (23w) = `solidTile ? 0 : 3`;
  **`staticGeometryDrawQuadCountForMacroPos:`** (26w) = `solidTile ? 0 : 2`.
- **`draw:...`** (0x00cae4d8, 714w, door render): gate `solidTile`; **animation
  phase**: float field += the draw's float arg; when > 5.0f reset to 0.0f
  and clear the `opening`-adjacent byte; gate byte; `Vector2` pos (+5y);
  helper **0xcaf000** (quad-position builder); texcoords via
  `paintedIndexForImageIndex` when `paintColor` set +
  `texCoordsForImageIndex`; phase = `abs(4*f - 1)`; two
  **`fillQuadBufferColored(...)`** submissions (20+ args, 0.51/-0.51/0.5/
  -1.0 constants).
- **`addDrawQuadData:fromIndex:forMacroPos:`** (503w): solid -> 0 (+ clears
  the macro-pos stash); else stash the macroPos pair, Vector(1,1,1,1),
  texture 583, phase math, helper 0xcaf000, two fillQuadBufferColored,
  returns index+2.
- **`addDrawCubeData:fromIndex:`** (802w): solid -> 0; **three cube
  submissions** - two with texture 583 (+painted variant) and one with
  `texCoordsForImageIndex(0x73)` = texture 115; positions +5y z = -1.5f;
  constants 0.95/0.55/0.05/0.1/0.2/-1.95/0.7/0.5/1.0; helper 0xcaf000;
  returns index+3.

## Rail + motor tracking

- **`initSubDerivedItems`** (184w): macroTiles + static/quad reloads;
  **`[world elevatorMotorForShaftAtPos:]`** (sel `elevatorMotorForShaftAtPos:`)
  + `pos` -> stores the motor position into `lastKnownMotorPos@60`
  (8-byte stret copy with memset fallback); `tileIsSolid(tile)` -> the
  solid byte.
- **`worldChanged:`** (308w): gate `isNet`; external intpair iteration;
  if `change.x == pos.x`: recompute the motor position from the world,
  re-check `tileIsSolid` vs the stored solid byte; on change: rewrite +
  reload both static (cubes) and quad geometry + `updateNeedsToBeSent`
  when `!isNet`.
- **`lastKnownMotorPos`** (24w) = `objc_copyStruct` accessor reading
  `OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos@60` (8, 1, 0 flags; PIC
  base verified via the 0xcb1554/0xcb15a0 literal pair).

## Serialization quartets

- **`getSaveDict`** (223w): super stret + numberWithInt pairs; u16 fields
  via `ldrh`, the lastKnownMotorPos pair as two keys; conditional extra
  key (b2i CFString block 0xfff436b4/c4/d4/e4/f4).
- **`initWithWorld:...saveDict:`** (214w): seven `objectForKey:` +
  `intValue` decodes (one strh u16).
- **`creationNetDataForClient:`** (209w): super 0x18-byte frame
  {u16 itemType, u8 solid, lastKnownMotorPos pair, u16 paintColor} +
  memcpy + appendData pair + helper **0xcae0ac** (gzip region) + optional
  key.
- **`initWithWorld:...netData:`** (212w): 0x28-byte `getBytes:length:`
  decode + helper **0xcad974** + tail chain.
- **`remoteUpdate:`** (127w): `getBytes:length:` 0x28 decode; pos
  static+quad reloads; `tileIsSolid` -> solid byte; packet u16 ->
  `paintColor`.
- **`updateNetDataForClient:`** (21w) = `[self creationNetDataForClient:]`
  forward; **`freeBlockCreationSaveDict`** (19w) = `[self getSaveDict]`
  forward; freeblockDataA/B = 0; freeblockCreationItemType = ivar load.
- **`paint:`** (134w): stores the u16 arg to `paintColor@84`, both
  geometry reloads, and when `!isNet`: `updateNeedsToBeSent` + change
  replay pair (objc_msgSend_stret style).
- **`removeFromMacroBlock`** (95w): static+quad reloads + super2.
  `dealloc` (49w); `objectType` = **0x38**; `isPaintable` = 1;
  `occupiesNormalContents` = 1.

## Anchors

- 26 bodies pinned imp/end (0x00cacc58..0x00cb15a4); 120 call sites,
  53 branches, 19 route targets (`reloadDrawBlockDynamicObject
  StaticGeometryForTile` / `...QuadsForTile`, `fillQuadBufferColored`,
  `tileIsSolid`, `Vector` ctor/operators, `paintedIndexForImageIndex`,
  `texCoordsForImageIndex`, `objc_copyStruct`, helpers 0xcaf000 /
  0xcaf074 / 0xcae0ac / 0xcad974, memset/memcpy, objc_msgSend family).
- Cells: 47 selectors (`elevatorMotorForShaftAtPos:`, `getBytes:length:`,
  `getSaveDict`, `creationNetDataForClient:`, `fillBuffer:...:paintColor:`,
  `macroTiles`, ...), 13 imports, 69 ivar cells (shaft: itemType@56 /
  lastKnownMotorPos@60 / opening@68 / paintColor@84 / solidTile@86;
  DynamicObject pos@16 / world@4 / dynamicWorld@8 / ownerID@36 /
  updateNeedsToBeSent@49 / isNet@52), 7 class cells.

## Boundaries

- TradePortal (54 bodies / approx 8616w) remains the open special-item
  campaign; E7's ElevatorMotor stays in its own commit. The two
  pre-existing annotated listings (`disasm_elevatorshaft_getsavedict.txt`,
  `disasm_elevatorshaft_initwithworld.txt`) are b2i consumers and remain
  untouched; the closure twins carry the `_closure` suffix.
