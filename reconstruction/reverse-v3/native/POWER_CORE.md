# Electricity-domain core — Wire configuration + WirePathCreator slots + ElevatorMotor consumer

Four bodies (1010 verified words) covering the conductivity wiring and the
first consumer: how a wire recomputes its connection configuration from its
four neighbours (the conductivity graph), how per-tile power-path property
slots are allocated, and how the elevator motor stores/consumes power.
Recovered from the pinned original `libApplication.so` (1.7.6, armeabi-v7a,
SHA-256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`);
every instruction word re-verified, tool refuses to emit on drift
(`tools/recover_power_core.py`; JSON: `power_core.json`).

| body | IMP | end | words |
|---|---|---|---|
| `-[Wire updateWireConfiguration]` | `0x0094f000` | `0x0094fca0` | 808 |
| `-[WirePathCreator tileDerivedPropertiesAtWorldIndex:]` | `0x00db20b4` | `0x00db222c` | 94 |
| `-[ElevatorMotor hasRequiredPower]` | `0x007027f8` | `0x00702848` | 20 |
| `-[ElevatorMotor usePower]` | `0x00702848` | `0x007029a8` | 88 |

## Wire updateWireConfiguration — the conductivity recompute

**Per direction** (up `(x, y+1)`, right `(x+1, y)`, down `(x, y-1)`,
left `(x-1, y)`): `tile = tileAtWorldPositionLoaded(nx, ny, self.world)`;
nil → no connection; else

- `connect = tileConductsElectricity(tile) || (tile[3] == 0x68) ||
  ((tile[3] == 0x2e || tile[3] == 0x2f) &&
  [[self.dynamicWorld workbenchAtPos:(nx, ny)]
  usesStoresConductsOrProducesElectricity])`
- when connected: `connFlag = 1`, and `openFlag = !tileIsSolid(tile)`.

The special path is the **workbench/production query** — content bytes 0x2e
(`.`) and 0x2f (`/`) ask the dynamic object at that position whether it
"uses, stores, conducts or produces electricity" (selector
`usesStoresConductsOrProducesElectricity`); the same predicate serves all
four directions.

**Connection combiner** — `(up, right, down, left)` → the wire's moving
configuration value:

| u r d l | value | u r d l | value |
|---|---|---|---|
| 1111 | 1 | 0111 | 8 |
| 1110 | 4 | 0110 | 9 |
| 1101 | 5 | 0101 | 0xb |
| 1100 | 3 | 0100 | 3 |
| 1011 | 7 | 0011 | 6 |
| 1010 | 0xa | 0010 | 6 |
| 1001 | 0xc | 0001 | 6 |
| 1000 | 3 | 0000 | 2 |

**Cover combiner** (only when the wire's own tile is solid; keyed on the
openFlags):

| u r d l | value | u r d l | value |
|---|---|---|---|
| 1111 | 2 | 0111 | 0xa |
| 1110 | 5 | 0110 | 0xb |
| 1101 | 6 | 0101 | 0xd |
| 1100 | 4 | 0100 | 0x11 |
| 1011 | 9 | 0011 | 7 |
| 1010 | 0xc | 0010 | 8 |
| 1001 | 0xe | 0001 | 0xf |
| 1000 | 0x10 | 0000 | keep 3 |

(Not-solid wires keep cover value 1 and skip the cover combiner.)

**Commit.** Store only when changed: `Wire.currentConfiguration@60` = moving;
`Wire.currentSolidConfiguration@64` = cover; both unchanged → return. On
change and when `!DynamicObject.isNet@52`:
`DynamicObject.updateNeedsToBeSent@49 = 1`;
`[self.dynamicWorld dynamicWorldChangedAtPos:intpair(self.x, self.y)
objectType:[self objectType]]`;
`reloadDrawBlockDynamicObjectStaticGeometryForTile(intpair,
[self.world macroTiles], self.world)`.

## WirePathCreator tileDerivedPropertiesAtWorldIndex: — the slot allocator

Memoized per-tile property slot: if `WirePathCreator.derivedTileCount@24 ==
0x1ff` (511, array full) → return `0`. Else `cached =
WirePathCreator.derivedTileIndices@28` (a `std::__1::map<int,int>`)[worldIndex];
`cached != 0` → return `&derivedTilePropertiesArray@20[cached]` (12-byte
`{int,int,int}` slots, `mul #0xc`). Fresh: `++derivedTileCount`,
`map[worldIndex] = newCount`, return `&array[newCount]` (base +
`newCount*12`). This is the per-tile storage that
`findAndSubtractAllPowerUpTo:forUser:` (the power-flow engine, next batch)
writes into.

## ElevatorMotor — the consumer side

- `hasRequiredPower` = `availableElectricity@60` (uint16 halfword) `>= 10`.
- `usePower`: if `DynamicObject.isNet@52` → `availableElectricity += 10`;
  else when `availableElectricity > 0`:
  `timeUntilNextPowerCheck@72 = 0.0f`; then `> 10` → `-= 10`, else `= 0`.
  In every path `DynamicObject.updateNeedsToBeSent@49 = 1`.

## Anchors

- Wire selectors: `usesStoresConductsOrProducesElectricity` (`0x94fc5c`),
  `workbenchAtPos:` (`0x94fc68`), `objectType` (`0x94fc8c`),
  `dynamicWorldChangedAtPos:objectType:` (`0x94fc90`), `macroTiles`
  (`0x94fc98`); import `objc_msgSend` (`0x94fc58`).
- Wire ivars: `DynamicObject.world`@4 (`0x94fc50`), `pos`@16 (`0x94fc54`),
  `dynamicWorld`@8 (`0x94fc60`), `isNet`@52 (`0x94fc80`),
  `updateNeedsToBeSent`@49 (`0x94fc84`), `Wire.currentConfiguration`@60
  (`0x94fc78`), `currentSolidConfiguration`@64 (`0x94fc7c`).
- WirePathCreator ivars: `derivedTilePropertiesArray`@20 (`0xdb2224`),
  `derivedTileCount`@24 (`0xdb221c`), `derivedTileIndices`@28 (`0xdb2220`);
  callee `std::__1::map<int,int>::operator[]` `0x86c818`.
- ElevatorMotor ivars: `availableElectricity`@60 (`0x702840`, `0x702990`),
  `clientPowerUsage`@62 (`0x70299c`), `timeUntilNextPowerCheck`@72
  (`0x702998`); DynamicObject `isNet`@52 / `updateNeedsToBeSent`@49.
- Direct calls: `tileAtWorldPositionLoaded` `0xa12f24`,
  `tileConductsElectricity` `0xa11818`, `tileIsSolid` `0xa1179c`,
  `makeIntpair` `0x4b49fc`,
  `reloadDrawBlockDynamicObjectStaticGeometryForTile` `0xa19598`.
- All 118 branches of the wire combiner, all 6 consumer branches, all 30/2
  call sites pinned.

## Boundaries

- The per-direction special query dispatches into the dynamic object
  (`workbenchAtPos:` → `usesStoresConductsOrProducesElectricity`); the
  implementations of those selectors are outside this batch.
- The combiner value tables are recorded mechanically from the branch
  structure (all 16 entries each).
- `findAndSubtractAllPowerUpTo:forUser:` (2929 words) — the actual power
  distribution engine — is NOT in this batch; it is the next one.
