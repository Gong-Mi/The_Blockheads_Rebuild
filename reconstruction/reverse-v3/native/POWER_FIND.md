# Electricity power-flow search — WirePathCreator findAndSubtractAllPowerUpTo:forUser:

`-[WirePathCreator findAndSubtractAllPowerUpTo:forUser:]`
(`0x00db2690` .. `0x00db51d4`, 2769 verified words) — **how current flows**:
the index-set search that walks the wire network from a start index, finds
wire-connected electricity sources, moves up to `upTo` power out of them, and
emits the electricity-particle path. Recovered from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_power_find.py`; JSON: `power_find.json`).

## Flow

1. **Prologue.** `derivedTileIndices` cleared (`std::__1::__tree<>::clear`
   at `0xdb2840`); state struct reset: `uint16 remaining @+0` =
   `uint16 initial @+8` = `upTo` (`strh r2, [ip, 8]`, `ldrh`, `strh [ip]`);
   a field zeroed; a `0x88`-byte user payload copied (`objc_msgSend_stret`,
   or `memset 0` when `user == nil`) plus the user flag byte
   (`strb r0, [sp, 0x487]`); `startIndex@16` =
   `worldIndexAtWorldPosition` of the wrapped start position;
   start tile = `tileAtWorldIndexLoaded` — `nil` → return 0.
   `openList@8` / `closedList@12` (NSMutableIndexSet) are prepared through
   the `alloc`/`init` msgSend trampolines; four `__block` captures are
   built (descriptor flags `0x20000000` / `0xc2000000`, one capture =
   `0x98967f` = 9,999,999).
2. **Enumerate + probe.** The open list is enumerated via
   `[openList enumerateIndexesUsingBlock:]` (`0xe88f48`); each index
   resolves to `(x, y)` via `getWorldPosForWorldIndex` and probes four
   directions through the 13-argument C helper
   `testTile(x-1,y / x+1,y / x,y-1 / x,y+1, openList, closedList, 10,
   tile, props, idx, idx2, budget, world, self, flag)` at `0xdb222c`
   (10 = probe budget).
3. **Main loop** (`while [openList count] (0xe88f44) > 0`, back edge
   `0xdb50fc → 0xdb2a78`, drain exit `0xdb2abc → 0xdb5140`). Per direction
   (left/right/down/up), the testTile result list is walked via its `[+8]`
   chain (sentinel `-1`; `removeIndex:`/`addIndex:` maintain the
   open/closed sets): each candidate's `availableElectricity` (`0xe88f28`)
   is read as uint16, `amount = min(available, remaining)` through the
   min-selection chains (state offsets `+0x3a/+0x5a/…/+0xfa`); when `> 0`:
   `remaining -= amount` and the source is updated via
   `[candidate subtractElectricty:amount]` (`0xe88f50`, original
   spelling). The path tile `{x, y, -1}` (12-byte
   `ElectrictyParticlePathIndex`) is pushed into a per-direction
   `std::vector`, which is copied and handed to
   `[[ParticleEmitter instance] addElectricityParticleWithPath:vectorCopy
   size:count]` (`0xe88f54`/`0xe88f58`) — the electricity particle visual
   (same convention as the net-path sync `World`
   sendNetDataForElectricityParticlePathIfRequired:). Direction finish:
   `remaining == 0` → exit returning `upTo` (flag 1), else continue
   (flag 0).
4. **Epilogue.** `_Block_object_dispose` ×4; when the open list drains:
   `return = uint16 initial − remaining` (`0xdb5140`–`0xdb5150`) = the
   power actually delivered (`int16`).

## Anchors

- Selectors (14): index-set control (`init`/`alloc`/`release`/`count`/
  `enumerateIndexesUsingBlock:`/`addIndex:`/`removeIndex:`),
  `pos`/`isStorageDevice`,
  `tileDerivedPropertiesAtWorldIndex:`,
  **`availableElectricity`** (`0xdb3bf4` → `0xe88f28`),
  **`subtractElectricty:`** (`0xdb3dc0` → `0xe88f50`), `instance`
  (`0xdb434c`), **`addElectricityParticleWithPath:size:`**
  (`0xdb44b8` → `0xe88f58`).
- Class cell: `OBJC_CLASS_$_ParticleEmitter` (`0xdb4344`).
- Ivars (6): `WirePathCreator.world`@4, `openList`@8, `closedList`@12,
  `startIndex`@16, `derivedTileCount`@24, `derivedTileIndices`@28.
- Imports: `objc_msgSend` (`0xdb36b8`), `_NSConcreteStackBlock`
  (`0xdb3a40`).
- 120 call sites (all pinned): 23 `objc_msgSend`, 16 `~vector`,
  13 `tileAtWorldIndexLoaded`, 12 `tileIsSolid`, 12
  `__push_back_slow_path`, 9 `worldIndexAtWorldPosition`, 8
  `_Block_object_dispose`, 4 `testTile` (the four directions), 4 copy
  ctors, 4 `__aeabi_idiv`, 1 `getWorldPosForWorldIndex`, 1
  `map<>::clear`, 1 `memset`, 1 `objc_msgSend_stret`, 1 `_Unwind_Resume`,
  10 `blx` (GOT trampolines: r2×4, r3×4, r8×1, ip×1).
- All 232 branches (5 loops: `0xdb32c0→0xdb3098`, `0xdb3bdc→0xdb399c`,
  `0xdb44e4→0xdb42a8`, `0xdb4dbc→0xdb4b90`, `0xdb50fc→0xdb2a78`).
- Key instructions: the `upTo` store/copy (`0xdb2720`/`0xdb2728`/
  `0xdb272c`), the `9,999,999` guard (`0xdb2afc`/`0xdb2b00`), the block
  flag `0xc2000000` (`0xdb2b64`), the probe constant 10 (`0xdb2d38`),
  the power-field stores (`0xdb3670`/`0xdb3fb8`/`0xdb48a4`), the epilogue
  arithmetic (`0xdb5140`–`0xdb5158`).

## Boundaries

- The C helper `testTile` (`0xdb222c`, between `tileDerivedProperties…`
  and this body) and the four `__block` closures are separate objects:
  every invocation site and argument setup is pinned here, but their
  internals are outside this body.
- Body is ARM.exidx-bounded (`0xdb51d4`); the table's 2929-word figure is
  the next-IMP gap and includes trailing pool/alignment.
- The particle renderer consuming `addElectricityParticleWithPath:size:`
  is out of scope.
