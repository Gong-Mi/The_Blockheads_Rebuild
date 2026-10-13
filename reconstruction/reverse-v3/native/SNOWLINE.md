# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 5866 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| sl_00 | SnowSurfaceBlock -[setNeedsRemoved:] | 0x00d918d8 | 50 | 2 | 2 | 0 | 1 | 2 | 1 |
| sl_01 | SnowSurfaceBlock -[dealloc] | 0x00d8d9b8 | 49 | 2 | 2 | 1 | 1 | 2 | 0 |
| sl_02 | SnowSurfaceBlock -[initWithWorld:dynamicWorld:atPosition:cache:] | 0x00d8d5e0 | 175 | 5 | 0 | 3 | 1 | 9 | 2 |
| sl_03 | SnowSurfaceBlock -[initWithWorld:dynamicWorld:saveDict:cache:] | 0x00d8d89c | 71 | 2 | 2 | 0 | 1 | 2 | 2 |
| sl_04 | SnowSurfaceBlock -[getSaveDict] | 0x00d8da7c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| sl_05 | SnowSurfaceBlock -[objectType] | 0x00d8d5c4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| sl_06 | SnowSurfaceBlock -[initSubDerivedItems] | 0x00d8d4b8 | 63 | 2 | 2 | 2 | 1 | 3 | 0 |
| sl_07 | SnowSurfaceBlock -[removeFromMacroBlock] | 0x00d8dab8 | 28 | 1 | 1 | 0 | 1 | 1 | 0 |
| sl_08 | SnowSurfaceBlock -[updateInTimeSinceSaved] | 0x00d8db28 | 642 | 6 | 1 | 5 | 0 | 16 | 30 |
| sl_09 | SnowSurfaceBlock -[update:accurateDT:isSimulation:] | 0x00d8e530 | 1428 | 16 | 2 | 10 | 1 | 62 | 65 |
| sl_10 | SnowSurfaceBlock -[updateRain:dt:] | 0x00d8fb80 | 526 | 3 | 0 | 4 | 1 | 25 | 22 |
| sl_11 | SnowSurfaceBlock -[spreadGrass:tile:] | 0x00d903b8 | 421 | 3 | 1 | 4 | 0 | 13 | 40 |
| sl_12 | SnowSurfaceBlock -[updateGroundFrozen:tile:] | 0x00d90a4c | 270 | 2 | 1 | 3 | 0 | 9 | 21 |
| sl_13 | SnowSurfaceBlock -[updateSnowContent:tile:] | 0x00d90e84 | 198 | 3 | 1 | 4 | 0 | 6 | 17 |
| sl_14 | SnowSurfaceBlock -[removeAllSnow] | 0x00d911d8 | 127 | 2 | 1 | 3 | 0 | 4 | 4 |
| sl_15 | SnowSurfaceBlock -[removeIfFloating] | 0x00d913d4 | 109 | 2 | 1 | 2 | 0 | 6 | 7 |
| sl_16 | SnowSurfaceBlock -[worldChanged:] | 0x00d91588 | 212 | 2 | 1 | 3 | 0 | 5 | 18 |
| sl_17 | SnowSurfaceBlock -[partialContent] | 0x00d919a0 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| sl_18 | SnowSurfaceBlock -[setPartialContent:] | 0x00d919e8 | 19 | 0 | 0 | 1 | 0 | 0 | 0 |
| sl_19 | Column -[updateConfiguration] | 0x00834210 | 202 | 3 | 0 | 6 | 0 | 6 | 14 |
| sl_20 | Column -[update:accurateDT:isSimulation:] | 0x00835b60 | 272 | 6 | 1 | 6 | 0 | 10 | 7 |
| sl_21 | Stairs -[updateConfiguration] | 0x006cbbe0 | 439 | 3 | 0 | 6 | 0 | 17 | 43 |
| sl_22 | Stairs -[update:accurateDT:isSimulation:] | 0x006cdccc | 272 | 6 | 1 | 6 | 0 | 10 | 7 |
| sl_23 | DynamicWorld -[snowChangedAtMacroPos:] | 0x008e1bf0 | 202 | 0 | 0 | 1 | 0 | 1 | 11 |
| sl_24 | DynamicWorld -[loadSnowSurfaceBlockAtPos:loadSnow:] | 0x008e6608 | 51 | 2 | 1 | 0 | 0 | 2 | 1 |

## Findings (E118)

- **The ice melt is fully pinned**: `[Column update:...]`/`[Stairs update:...]` gate on
  `itemType == 0xf4` (244 = Ice Column; 253 = Ice Stairs in the community id list), accumulate
  `iceMeltTimer += dt`, act only past 5.0 s, and melt via `fillTile:atPos:withType:` with the
  0x423 tile-type constant when `currentTemperatureForTileAtWorldPos > 1.0` - the wiki's "melt
  into half a block of water" (the earlier research decode also showed the 0x7f half-water byte).
- **The snow amount is a scaled fraction**: `partialContent` (a 0..1 float) maps to the tile
  partial-content byte (`partialContentLeft`, +0x04) as `(int)(v * 255.0)` (`updateSnowContent:tile:`, constant 255.0).
- **Freeze/thaw is server-side only**: both `updateGroundFrozen:tile:` and the tick gate on
  `[dynamicWorld isClient]`; the frozen pairs are 0x1b/0x1c and 0x31/0x32 (with the 27/28 and
  49/50 decimal reads), written into both fg and bg, and every flip fires
  `snowChangedAtMacroPos:` with the macro coordinates `x>>5, (y-1)>>5`.
- **The melt/accumulation rates** (from the f64 chains): melt `-= ((0.02 + max(weather-0.2,
  0.001)*0.2) * (temp+1)) * 0.01 * 4`; accumulation `+= (weather-0.2) * 0.005 * ramp` with
  `ramp = (sunLight-240)` clamped to [0,1], cap 0.6, floor 0.002, sunLight gate >239 (open to the sky).
- **Temperature is a derived field**: `SnowSurfaceBlock.temperature` is written every tick from
  `currentTemperatureForTileAtWorldPos(Tile*, intpair, ...)` fed by `getDayNightFractionForX:`
  / `getWeatherFractionForPos:` / `seasonForWorldX` / `worldTime`.
- **The column layout probe** reads the marker byte 0x64 ('d') above and below the column
  (`tileAtWorldPositionLoaded` x, y-1 / y+1) and derives `config = 4 - 2*above - below` -
  the same surface-marker byte family as the E72 torch codes; every config change fires
  `dynamicWorldChangedAtPos:objectType:` and a static-geometry reload.
- **objectType 29 = SnowSurfaceBlock** (sl_05) matches the rebuild's
  `dynamic_object_type_table.inc` entry `{29, "SnowSurfaceBlock"}`.
- The precipitation visuals come from `ParticleEmitter.instance` `addParticleAtPos:...` loops
  paced by `rainRandomTimer` (sl_10) and by the `(s16@0x14+4)/4` count (sl_09; +0x14 = artificialHeat).

## Boundaries

- The ParticleEmitter / dayColor / macroTiles field contracts are asserted at the selector
  level; their own bodies are outside this batch.
- sl_08/sl_09/sl_10/sl_21 are census-grade; the other 21 read in full.
- The 0x422/0x423 tile-type constants are recorded as the fill type argument; their own type
  table entries stay outside this batch.
