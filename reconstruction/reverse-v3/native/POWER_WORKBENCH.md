# Electricity consumers + producers closure — Workbench electric API, power search forwarder, particle emitter pair

The consumer/producer surface that drives the electricity domain: how a
workbench decides whether it conducts/generates/requires electricity, how it
deducts power and re-broadcasts the change, how a solar panel measures its
light input, how `DynamicWorld` routes a power search into the
`WirePathCreator` engine, and how the electricity-particle visual allocates
its segments. 11 bodies, **1400 verified words** total, recovered from the
pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_power_workbench.py`; JSON: `power_workbench.json`).

## Workbench electric API

1. **`availableElectricity`** (`0xb01284`..`0xb012c0`, 15 words). Leaf
   getter: `return *(uint16 *)((char *)self + 222)` —
   `Workbench.availableElectricity@222`.
2. **`conductsElectricity`** (`0xb012c0`..`0xb0137c`, 47 words).
   `return [self isStorageDevice] || [self generatesElectricity]`
   (short-circuit: the second message only runs when the first is false).
3. **`subtractElectricty:`** (`0xb0137c`..`0xb01744`, 242 words).
   `(uint16 amount) -> BOOL deducted`. If `amount > availableElectricity`
   -> skip deduction (flag 0). Else `available -= amount`, flag := 1,
   `updateNeedsToBeSent@49 := 1`, re-broadcast through the
   `objectType` / `dynamicWorldChangedAtPos:objectType:` pair. Then when
   `type == 0xf` (`Workbench.type@120`): the steam regeneration loop while
   `fuelFraction@212 > 0` && `available < 100 (0x64)`:
   `fuelFraction -= 0.000583f (0x3a18d478)`;
   `available += 10 (0xa)`; `particleCreateTimerSteamEngine@280 += 0.1f
   (0x3dcccccd)`. After the loop clamp
   `particleCreateTimerSteamEngine <= 4.0f`; tail:
   `objectType`/`dynamicWorldChangedAtPos:objectType:` pair +
   `updateHasFuel` + `updateNeedsToBeSent@49 := 1`. Returns the flag byte
   (`ldrsb [fp,-0x1b]`).
4. **`generatesElectricity`** (`0xb01c24`..`0xb01cac`, 34 words).
   `return type == 0xf || type == 0x14` (`Workbench.type@120`).
5. **`usesStoresConductsOrProducesElectricity`** (`0xb01cac`..`0xb01ec0`,
   133 words). 11-compare whitelist over `Workbench.type@120`:
   `type in {0xf, 0x14, 0x15, 0x11, 0x10, 0x1b, 0x12, 0x13, 0x1a, 0x1d,
   0x1e}` (each match returns 1; the final `0x1e` compare stores `moveq`).
6. **`requiresElectricty`** (`0xb0b7d0`..`0xb0b868`, 38 words).
   `return H([self type], [self level])` — two `objc_msgSend` trampolines
   (`type` then `level`) feed the shared helper `bl 0xae3574` (internals out
   of body); `sxtb` result.
7. **`combinedLightForSolarPanelWithFullSunlight`** (`0xaee208`..`0xaee4e0`,
   182 words). `world@4` -> `macroTiles` -> `tileAtWorldPosition(pos.x+1,
   pos.y, macroTile, world)`; gates: `!tileIsAirOrSnow(tile)` or
   `tile[3] == 0x2e` -> return 0.0. Light = `powf(tile[7]/255.0, 4.0)`;
   `A = clamp(light, 0, 1)`; `B = min(sum16(tile+0xe, +0x10, +0x12),
   2000.0)` (the L2a light-word accumulators); `total = A + B * 1e-4`
   (f64 const `0x3f1a36e2eb1c432d`); `tileIsTree(tile)` -> `total /= 2`.
8. **`combinedLightForSolarPanel`** (`0xaee508`..`0xaee9d0`, 306 words).
   Same skeleton, but daylight is measured:
   `day = [world getDayNightFractionForX:(pos.x+1)
   atWorldTime:[world worldTime]]`;
   `light = clamp((day - 0.23f) * 4.0, 0, 1) * powf(tile[7]/255.0, 4.0)`;
   `w = [world getWeatherFractionForPos:pos]`; when `w > 0` ->
   `light *= (1 - min(w, 0.2) * 4)`; clamp `light >= 0`;
   `total = light + min(sum16(tile+0xe, +0x10, +0x12), 2000.0) * 1e-4`;
   `tileIsTree(tile)` -> `total /= 2`.

## Power-search routing + particle emitter

9. **DynamicWorld `findAndSubtractAllPowerUpTo:forUser:`**
   (`0x8fdee8`..`0x8fdf6c`, 33 words). Forwarder:
   `return [self.wirePathCreator@9496
   findAndSubtractAllPowerUpTo:upTo forUser:user]` — one `objc_msgSend`
   (`uxth` on upTo). The engine itself is the WirePathCreator body
   `0x00db2690` (electricity power-flow search batch).
10. **ParticleEmitter `addElectricityParticleWithPath:size:`**
    (`0xd8753c`..`0xd876b0`, 93 words).
    `[self.world@4 sendNetDataForElectricityParticlePathIfRequired:(vector
    copy) size:size ignoreClient:0]`; then when `!stopAllParticles@96` ->
    `[self doAddElectricityParticleWithPath:(vector copy) size:size]`
    (two stack vector copies; `~vector` x3 unwind paths + `_Unwind_Resume`
    `0xd87690`).
11. **ParticleEmitter `doAddElectricityParticleWithPath:size:`**
    (`0xd876b0`..`0xd87b04`, 277 words). Segment allocator: guard
    `stopAllParticles@96 != 0` -> return. `step = 50.0/size` (f64
    `0x4049000000000000`), `remaining = size`, `t = 0.0f`. Loop while
    `remaining > 0`: `index = [electrictyFreeIndices@52 firstIndex]`;
    `0x7fffffff` (NSNotFound) -> return; index moves free -> taken via
    `removeIndex:`/`addIndex:` on the two `NSMutableIndexSet` ivars;
    `slot = electrictyParticles@48 + index*40`; `slot+0x10` vector <-
    path (`vector::assign`); cursor `+0x1c := 0`; `{x,y} =
    slot.path.at(cursor)`; `macro = makeIntpair(x mod (worldWidthMacro@100
    << 5), y / (worldWidthMacro<<5))`; pos `Vector = (macro.x+5,
    macro.y+5, z)` with `z = (low byte of y == 1) ? 0.03f : -1.47f`
    (`0x3cf5c28f` / `0xbfbc28f6`); `slot+0x20 = 0.0f`; `slot+0x24 = t`;
    `t += step`; `remaining -= 5.0f`.

## Anchors

- Dispatch table: 18 selector cells (`isStorageDevice`,
  `generatesElectricity`, `type`, `level`, `macroTiles`,
  `getDayNightFractionForX:atWorldTime:`, `worldTime`,
  `getWeatherFractionForPos:`, `firstIndex`, `addIndex:`, `removeIndex:`,
  `objectType`, `dynamicWorldChangedAtPos:objectType:`, `updateHasFuel`,
  `sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:`,
  `doAddElectricityParticleWithPath:size:`,
  `findAndSubtractAllPowerUpTo:forUser:`), 7 import cells (`objc_msgSend`
  x5, `__wrap_powf`, `..`), 22 ivar descriptor cells (Workbench
  `availableElectricity`@222 / `type`@120 / `fuelFraction`@212 /
  `particleCreateTimerSteamEngine`@280; DynamicObject `world`@4 /
  `dynamicWorld`@8 / `pos`@16 / `updateNeedsToBeSent`@49; DynamicWorld
  `wirePathCreator`@9496; ParticleEmitter `world`@4 / `electrictyParticles`
  @48 / `electrictyFreeIndices`@52 / `electrictyTakenIndices`@56 /
  `stopAllParticles`@96 / `worldWidthMacro`@100), no class cells.
- All 42 call sites pinned (5/8/0/2/5/0/0/3/1/9/9), all 58 branches pinned,
  52 instruction anchors.
- Key callees: `tileAtWorldPosition` (`0xa16e68`), `tileIsAirOrSnow`
  (`0xa12760`), `tileIsTree` (`0xa13214`), `__wrap_powf` (`0x1c3f98`),
  `makeIntpair` (`0x4b49fc`), `Vector::Vector(float,float,float)`
  (`0x4b52ac`), `__modsi3` (`0x1c3020`), `__aeabi_idiv` (`0x1c3728`), the
  shared boolean helper `0xae3574`, vector `at`/`assign`/copy-ctor/dtor.
- Constants: 255.0 (`0x437f0000`), 2000 (0x7d0), 1e-4 (f64
  `0x3f1a36e2eb1c432d`), 0.23f (`0x3e6b851f`), 0.2 (f64
  `0x3fc999999999999a`), 0.000583f (`0x3a18d478`), 0.1f (`0x3dcccccd`),
  4.0, 0.03f (`0x3cf5c28f`), -1.47f (`0xbfbc28f6`), 50.0 (f64
  `0x4049000000000000`), 0x7fffffff (NSNotFound), 40-byte particle slot.

## Boundaries

- Bodies are ARM.exidx-bounded; three tails trimmed to the reviewed range:
  `combinedLightForSolarPanelWithFullSunlight` (0x00aee4e0..pool excluded),
  `combinedLightForSolarPanel` (0x00aee9d0..pool excluded),
  `subtractElectricty:` (0x00b01744..float-const tail excluded);
  `generatesElectricity` trimmed to next IMP `0x00b01cac` (exidx
  over-covered `0x00b01ec0`); `requiresElectricty` trimmed to next IMP
  `0x00b0b868` (exidx over-covered `0x00b0bca4`).
- The helper `0xae3574` internals, the `WirePathCreator` engine internals
  (separate body `0x00db2690`), the `ParticleEmitter` renderer consuming the
  electrictyParticles array, and the net transport consumers are outside
  these bodies.
