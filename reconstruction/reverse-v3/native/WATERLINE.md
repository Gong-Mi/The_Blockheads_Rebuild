# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 11897 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| aq_00 | Weather -[initWithCache:world:worldTime:] | 0x007e3a28 | 1101 | 18 | 20 | 20 | 7 | 63 | 13 |
| aq_01 | Weather -[updateCloudsForLoadOrHDTeturesChange] | 0x007e4b6c | 639 | 5 | 16 | 8 | 1 | 23 | 10 |
| aq_02 | Weather -[loadCricketSounds] | 0x007e5568 | 362 | 11 | 5 | 1 | 4 | 27 | 8 |
| aq_03 | Weather -[dealloc] | 0x007e5b10 | 232 | 3 | 2 | 13 | 1 | 14 | 1 |
| aq_04 | Weather -[update:rainFraction:snowFraction:] | 0x007e5eb0 | 752 | 0 | 0 | 9 | 0 | 6 | 24 |
| aq_05 | Weather -[updateBirdSoundWithBirdFraction:dayNightMix:undergroundMix:dt:playPosition:] | 0x007e6a70 | 310 | 3 | 1 | 5 | 0 | 10 | 16 |
| aq_06 | Weather -[updateRainSoundWithRainFraction:undergroundMix:position:] | 0x007e6f48 | 658 | 4 | 1 | 5 | 0 | 21 | 21 |
| aq_07 | Weather -[updateCloudsWithTranslation:] | 0x007e7990 | 966 | 1 | 1 | 6 | 0 | 31 | 37 |
| aq_08 | Weather -[renderCloudWithMatrix:translation:dt:weatherFraction:futureWeatherFraction:timeOfDayFraction:] | 0x007e88a8 | 1877 | 18 | 2 | 15 | 0 | 93 | 31 |
| aq_09 | Weather -[renderWithMatrix:pinchScale:withDayColor:rainFraction:snowFraction:snowLevel:] | 0x007ea820 | 818 | 4 | 1 | 4 | 0 | 61 | 11 |
| aq_10 | Weather -[setSoundPaused:] | 0x007eb4e8 | 107 | 1 | 1 | 5 | 0 | 4 | 3 |
| aq_11 | Weather -[cloudColorForWeatherFraction:timeOfDayFraction:isBackground:] | 0x007eb694 | 531 | 3 | 1 | 5 | 0 | 32 | 17 |
| aq_12 | Weather -[windStrength] | 0x007ebee0 | 32 | 0 | 0 | 1 | 0 | 1 | 0 |
| aq_13 | Weather -[windMovement] | 0x007ebf60 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| aq_14 | Weather -[setWindMovement:] | 0x007ebfa8 | 19 | 0 | 0 | 1 | 0 | 0 | 0 |
| aq_15 | Weather -[.cxx_construct] | 0x007ebff4 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_16 | World -[getWeatherFractionForPos:] | 0x00582a50 | 34 | 1 | 0 | 1 | 0 | 1 | 0 |
| aq_17 | World -[getWeatherFractionForPos:atWorldTime:] | 0x00582408 | 32 | 1 | 0 | 0 | 0 | 1 | 0 |
| aq_18 | World -[getWeatherFractionForPos:atWorldTime:ignoreSandFraction:] | 0x00582488 | 355 | 2 | 1 | 6 | 0 | 8 | 19 |
| aq_19 | World -[weatherFraction] | 0x005d9ab0 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| aq_20 | World -[rainFractionNotIncludingSnow] | 0x005d9b40 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| aq_21 | World -[removeWaterTileAtPos:] | 0x00578430 | 380 | 8 | 1 | 3 | 2 | 22 | 23 |
| aq_22 | World -[waterMovedFrom:fromTile:to:toTile:amount:] | 0x005c1ddc | 621 | 2 | 0 | 7 | 1 | 31 | 21 |
| aq_23 | World -[waterAnimationIndex] | 0x005da5c4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| aq_24 | WorldTileLoader -[recursivelyFlowOutWaterFromTile:atPos:] | 0x0085c214 | 193 | 1 | 0 | 1 | 0 | 9 | 9 |
| aq_25 | DynamicWorld -[waterChangedAtPos:fullBlock:] | 0x008e0ad0 | 560 | 1 | 1 | 4 | 0 | 7 | 32 |
| aq_26 | SurfaceBlock -[subtractWater:fromOtherTile:atPos:] | 0x00812184 | 41 | 1 | 0 | 1 | 0 | 1 | 2 |
| aq_27 | SurfaceBlock -[takeAnyWaterFromTileAtPos:tile:] | 0x00812228 | 691 | 4 | 0 | 6 | 0 | 33 | 31 |
| aq_28 | SurfaceBlock -[removeIfFloatingAndEmptyOfWater] | 0x008144a8 | 260 | 3 | 1 | 4 | 0 | 11 | 18 |
| aq_29 | DynamicObject -[waterContentChanged:] | 0x0083b5f8 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| aq_30 | DynamicWorld -[placeBoatInWaterAtPos:saveDict:placedByClient:] | 0x008ee1f0 | 126 | 5 | 1 | 3 | 1 | 6 | 1 |
| aq_31 | Blockhead -[environmentTemperature] | 0x00b8ca38 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| aq_32 | Blockhead -[currentTemperature] | 0x00c8a540 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| aq_33 | ChilliPlant -[minAllowedTemperature] | 0x006ba1b4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_34 | WheatPlant -[minAllowedTemperature] | 0x006d143c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_35 | TomatoPlant -[minAllowedTemperature] | 0x006ffc08 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_36 | CarrotPlant -[minAllowedTemperature] | 0x00741978 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_37 | FlaxPlant -[minAllowedTemperature] | 0x00770d2c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_38 | SunflowerPlant -[minAllowedTemperature] | 0x009bc5f0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_39 | NormalPlant -[minAllowedTemperature] | 0x00a65554 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_40 | CornPlant -[minAllowedTemperature] | 0x00b50248 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_41 | NPC -[suffersDamageAtHighTemperatures] | 0x00650a48 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| aq_42 | CaveTroll -[suffersDamageAtHighTemperatures] | 0x00d85230 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |

## Findings (E119)

- **The weather field is fully pinned** (`getWeatherFractionForPos:atWorldTime:ignoreSandFraction:`):
  `W` = the 3D `weatherNoiseFunction` sample, plus loader-type offsets (byte@8 == 3/4), minus the
  altitude fade `clamp((y-512-C)/C, 0, 1)` (rain thins above y=512), times the `noRainTimer` ramp
  `clamp((noRainTimer-d2)/d2, 0, 1)`, minus the sand suppression (`sandFractionForPos:highRes:`:
  `3S` when `S > 0.2`, `S*S` for `0 < S <= 0.2`), clamped to `[-1, 2]`. The wrapper chain:
  `getWeatherFractionForPos:` -> `eventTime` variant -> `ignoreSandFraction:NO`.
- **The plant hardiness table** (minAllowedTemperature): chilli **-1**, tomato **-2**, sunflower
  **-5**, corn **-10**, wheat **-15**, carrot/flax/normal **-20**. The NPC family:
  `suffersDamageAtHighTemperatures` = **1** for NPC, **0** for CaveTroll (the troll is heat-immune).
- **windStrength = clamp((windMovement - 5) / 32, 0, 3)** - the wind audio mixer (aq_06) consumes it.
- **The water flow quartet**: `recursivelyFlowOutWaterFromTile:` (still water `byte0 == 2 && byte2 == 1`
  becomes flowing `byte0 = 3, byte4 = 0xff, byte7 = 0`, recursion via the notify), `waterMovedFrom:...`
  (the camera-culled splash particles, light-channel tint /1024, colour 0.808/0.854/0.886, count
  from the move amount), `removeWaterTileAtPos:` (the admin 0x18-byte network record +
  sendDataToServer:reliable:, tile rewrite byte0 = 2/byte4 = 0, attachment detach over the column)
  and `waterChangedAtPos:fullBlock:` (`reloadDrawBlockWaterForTile` + deduped
  waterChangedPositions / worldChanged*MacroPositions) - the same macro-position event
  machinery the E118 snow flip feeds via snowChangedAtMacroPos:.
- **The surface pump** `takeAnyWaterFromTileAtPos:tile:`: takes up to 0xff units, rewrites the source
  to `byte0 = 3, byte4 = 0xff`, and spreads into the three air-or-snow neighbours.
- **The rain/snow particle FIELD** (`update:rainFraction:snowFraction:`): minimum-dt gate; rain drift
  `5*dt` with the PRNG helper and the `0x1000` index wrap (recalcRandomIndex); the snow side runs
  `0x200` (512) points with linearInterpolate blends; the renderers are pure uniform/draw passes.

## Boundaries

- The Weather render/construction giants (aq_00/aq_01/aq_04/aq_07/aq_08/aq_09) are census-grade;
  the other 37 read in full (the 7-word constant getters fully pinned).
- The byte0 material codes around water (the 2/3 pair here, the 4 special in E118) are recorded as
  observed transitions; the full per-code decode table stays outside this batch.
- The sandFractionForPos:highRes:/getX:Y:Z:octaves: internals and the sound system contracts are
  asserted at the selector level.
