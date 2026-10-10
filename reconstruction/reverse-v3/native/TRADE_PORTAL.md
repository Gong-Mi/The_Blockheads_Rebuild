# TradePortal structure batch (E9a) — placement, net/save quartets, portal light, draw

The trade portal (DynamicObject 0x32), part 1 of 2 (E9b closes the trade
economics). 40 bodies, **4716 verified words** total, recovered from the
pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_trade_portal.py`; JSON: `trade_portal.json`).

## Placement trio + serialization

- **`initWithWorld:...atPosition:cache:item:flipped:saveDict:placedByClient:clientName:`**
  (0x00d37d8c, 348w — the 10-arg placement incl. `clientName:`): super2 init;
  stores item/flipped/placedByClient; save-dict decode (key f4e724); tile at
  (pos.x, pos.y-1): `tile[3] = 0`, `tile[1] == 2 -> 0xa`; **LEVEL JUMP TABLE**
  `switch(level@132, 0..5)` writes `tile[0] = {0x3c,0x3d,0x3e,0x3f,0x40,0x41}`;
  glow registration (sel 0xffe28d20) + tail pair; return self.
- **`initWithWorld:...saveDict:`** (0x00d382fc, 281w): super2; `localPriceOffsets
  = [NSMutableArray array]`; objectForKey decodes (f4e724/f4e734, conditional
  f4e744) incl. the level; conditional light rebuild (sels 0xffe28d30/0xffe28d20)
  + glow reload; return self.
- **`initWithWorld:...netData:`** (0x00d38760, 423w): super2; `getBytes:length:
  0x30`; level = payload byte; item array (sel 0xffe28d3c + `sub 0x30`/
  0xffe28d40 pair); helper **0xd38dfc** (price decode); localPriceOffsets rebuilt
  by fast enumeration; light rebuild + glow reload.
- **`getSaveDict`** (0x00d39460, 157w): super stret + setObject:forKey: chain:
  conditional f4e724 (price array non-empty), level key f4e734, conditional
  f4e744.
- **`updateNetDataForClient:`** (0x00d38e20, 237w): super stret 0x28 net struct;
  level byte + three conditional price keys (f4e754/f4e764/f4e724); helper
  **0xd391d4**; appendData pair (0xffe28d64/0xffe28d60).
- **`remoteUpdate:`** (0x00d396f0, 682w): super2 + packet decode (0x228 frame);
  level raise (packet level > slot 132) -> apply + **8-iteration price rebuild**
  (helper **0xd37798**, 64.0f scaling, 0x40-byte item structs via sel
  0xffe28d8c) + **LEVEL JUMP TABLE (level-1, 0..4)**: tile[0] =
  {0x3d,0x3e,0x3f,0x40,0x41}; when slot 0xffffcfd0 == 0: getBytes:length: 0x30 +
  helper 0xd38dfc + fast-enumeration price rebuild + duplicate jump table + tail
  chain (sel 0xffe28d18).
- **`dealloc`** (0x00d39340, 72w): release chain (light 0xfffffd60 + array
  0xfffffd64) + super2.

## Portal light

- **`getLightRGB`** (25w) = `Vector(255.0, 246.0, 64.0)` (0xff/0xf6/0x40).
- **`updatePortalLight`** (148w): `[light removeFromTiles]` + `release` (via
  slot 0xfffffd60); builds an **`ArtificialLight`** via
  `[ArtificialLight alloc] initWithWorld:dynamicWorld:atPosition:cache:
  parentObject:colorR:colorG:colorB:heat:radius:lightDirection:` at
  `makeIntpair(pos.x, pos.y-1)` with color 255/246/64; stores it; setup + glow
  reload (`reloadDrawBlockLightGlowQuadsForTile`).
- **`lightPos`** (46w) = `Vector(pos.x, pos.y+1, -1.0)`;
  **`lightGlowQuadCount`** = 1;
  **`addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:`** (29w)
  forwards to the light via `addContributionForPhysicalBlockLoadedAtXPos:yPos:`.
- **`setNeedsRemoved:`** (85w): super2 + when removing: light teardown
  (`removeFromTiles`/`release`) + glow reload. **`remove:`** (258w): gate byte
  0xffffc8d4; net branch (`stopInteracting`, super2 setNeedsRemoved:YES + byte
  0xffffcfe0); else **3x `createFreeBlockAtPosition:ofType:dataA:dataB:subItems:
  dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:`** with
  `{0xd2, 1, 0, res, 1, 0, arg}` at (y, y-1, y+1) rebuilding the portal column
  (destroyItemType/freeblockCreationItemType = 0xd2 = 210).

## Draw + static geometry

- **`draw:...`** (0x00d3a198, 472w): gates (slot 0xffffcfd8 + light state
  0xfffffd6c/0xfffffd70; light on/off via sels 0xffe28d90/0xffe28d94);
  **animationLoopTimer@0xfffffd74 += pinchScale**; while timer > 0.2f: subtract
  0.2f + **animationLoopIndex@0xfffffd5c += 1 (mod 8)** + stepped flag; texture
  scroll via `__modsi3`/`__aeabi_idiv` + doubles {0.5, 0.25, 1.0} ->
  `updateQuadBufferTexCoords(buf, 0x20, f, f, f, f)` (savedDrawBuffer/@0xfffffd78,
  savedDrawBufferIndex/@0xfffffd7c).
- **`addDrawQuadData:fromIndex:forMacroPos:`** (0x00d3c9d8, 234w): stashes the
  macro pair (0xfffffd78/fd7c); Vector2 pos (-5y); z = -0.99f (0xbf7d70a4);
  helper **0xd3cd80**; scroll math `(animationLoopIndex + 0x2f0) mod 8` /8 with
  doubles {0.03125, 0.5, 0.25} -> 4 scrolling texcoords; one
  `fillQuadBuffer(...20 args)`; index+1. **`staticGeometryDrawQuadCountForMacroPos:`
  = 1**, **`staticGeometryDrawCubeCount` = 1**.
- **`removeFromMacroBlock`** (66w): light teardown + quads reload + super2.

## Titles + interaction flags

- **`title`** (37w): `[NSString stringWithFormat: CFString(f4e784+slide),
  level@132 + 1]`.
- **`actionTitle` / `secondOptionTitle` / `thirdOptionTitle`** (173/292/222w):
  stret getters (sel 0xffe28dbc) + state-byte chains returning CFStrings
  f4e794/f4e7a4/f4e7b4 (stack-canary checked).
- **`setWorkbenchChoiceUIOption:`** (143w): zeroes flag bytes 0xfffffd80/fd84;
  per-option title check (sel 0xffe28dcc vs f4e794/f4e7a4) sets the flags.
- Flags: objectType = 0x32; interactionObjectType = 7; isDoubleHeight = 1;
  requiresHumanInteraction = 1; isPaintable-class constants; interactionRenderItemType
  = 0xa7 (167); occupiesNormalContents = 1; canBeUsedInExpertModeWhenNotOwned = 1;
  `level`/`localPriceOffsets` are **dmb ish atomic accessors** (132/128);
  `worldContentsChanged:` is an empty no-op; freeblock quartet as usual
  (fbsave = forward sel 0xffe28d6c, fba/fbb = 0).

## Anchors

- 40 bodies pinned imp/end (0x00d37598..0x00d3f8f4); 196 call sites,
  153 branches, 24 route targets (helpers 0xd37798/0xd38dfc/0xd391d4/0xd3cd80,
  ArtificialLight init, fillQuadBuffer, updateQuadBufferTexCoords,
  createFreeBlockAtPosition:..., tileAtWorldPositionLoaded, reloadDrawBlock*
  family, NSMutableArray/NSString, __modsi3/__aeabi_idiv/memset/memcpy).
- Cells: 92 selectors (incl. the full ArtificialLight init selector,
  `removeTileAtWorldX:...removeBlockhead:`, `createFreeBlockAtPosition:...
  priorityBlockhead:`, `stringWithFormat:`, `stopInteracting`, `isNet`),
  24 imports, 81 ivar cells (TradePortal: level@132 / localPriceOffsets@128 /
  animationLoopIndex@108 / savedDrawBuffer@120 / savedDrawBufferIndex@124 /
  sound / paused / animationLoopTimer; InteractionObject.isInUse; DynamicObject
  set), 13 class cells.

## Boundaries

- E9b closes the trade economics: loadPriceOffsets:, sellItem:atTotalPrice:
  count:usageMultiplier:, buyItem:atTotalPrice:count:, upgradeToNextLevel,
  upgradeCraftableItem, takeItemsFromBlockheadForUpgradeToNextLevel,
  currentBlockhead{Cash,CountOfInventoryItemsOfType:,UsageMultiplier...},
  setPaused:, randomizeLocalTradeOffsets, worldChanged:, isSellInteraction,
  isMissionInteraction.
- Pinned-but-out-of-batch neighbors: helper 0xd37798 (portal price hash, called
  from subderived/remoteupd), helper 0xd38dfc (price decode), helper 0xd391d4
  (gzip region), helper 0xd3cd80 (quad builder).
- The pre-existing annotated lists (`disasm_tradeportal_getsavedict.txt` sha-
  pinned in a b2e test, `disasm_tradeportal_loadpriceoffsets.txt` consumed by
  the price-offsets ARM test) remain untouched; the closure twin carries the
  `_closure` suffix.
