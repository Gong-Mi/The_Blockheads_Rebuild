# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 12812 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| hl_00 | FireObject -[initSubDerivedItems] | 0x0067440c | 155 | 3 | 7 | 4 | 1 | 6 | 0 |
| hl_01 | FireObject -[objectType] | 0x00674688 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| hl_02 | FireObject -[getLightRGB] | 0x006746a4 | 24 | 0 | 0 | 0 | 0 | 1 | 0 |
| hl_03 | FireObject -[initWithWorld:dynamicWorld:atPosition:cache:] | 0x00674704 | 252 | 5 | 1 | 7 | 2 | 11 | 2 |
| hl_04 | FireObject -[initWithWorld:dynamicWorld:saveDict:cache:] | 0x00674af4 | 259 | 7 | 8 | 7 | 2 | 17 | 2 |
| hl_05 | FireObject -[initWithWorld:dynamicWorld:cache:netData:] | 0x00674f00 | 71 | 2 | 2 | 0 | 1 | 2 | 2 |
| hl_06 | FireObject -[getSaveDict] | 0x0067501c | 244 | 3 | 8 | 3 | 2 | 13 | 1 |
| hl_07 | FireObject -[updateNetDataForClient:] | 0x006753ec | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| hl_08 | FireObject -[creationNetDataForClient:] | 0x00675440 | 72 | 2 | 1 | 0 | 1 | 4 | 2 |
| hl_09 | FireObject -[dealloc] | 0x00675560 | 58 | 2 | 2 | 1 | 1 | 2 | 0 |
| hl_10 | FireObject -[setNeedsRemoved:] | 0x00675648 | 58 | 2 | 2 | 1 | 1 | 2 | 1 |
| hl_11 | FireObject -[removeFromMacroBlock] | 0x00675730 | 361 | 12 | 2 | 4 | 1 | 18 | 14 |
| hl_12 | FireObject -[requiresPhysicalBlock] | 0x00675cd4 | 23 | 0 | 0 | 1 | 0 | 0 | 2 |
| hl_13 | FireObject -[update:accurateDT:isSimulation:] | 0x00675d30 | 692 | 5 | 0 | 8 | 0 | 33 | 24 |
| hl_14 | FireObject -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x00676800 | 2268 | 9 | 2 | 9 | 0 | 69 | 25 |
| hl_15 | FireObject -[worldChanged:] | 0x00679a48 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| hl_16 | FireObject -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:] | 0x00679ab4 | 29 | 1 | 1 | 1 | 0 | 1 | 0 |
| hl_17 | ArtificialLight -[recursivelyUpdateLightWithList:] | 0x00a8f22c | 2753 | 3 | 2 | 13 | 0 | 76 | 241 |
| hl_18 | ArtificialLight -[addToTiles] | 0x00a92238 | 970 | 8 | 0 | 11 | 0 | 38 | 78 |
| hl_19 | ArtificialLight -[removeFromTiles] | 0x00a93198 | 356 | 3 | 1 | 6 | 0 | 8 | 14 |
| hl_20 | ArtificialLight -[objectType] | 0x00a93728 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| hl_21 | ArtificialLight -[initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:] | 0x00a93744 | 286 | 4 | 1 | 13 | 1 | 7 | 4 |
| hl_22 | ArtificialLight -[lightColor] | 0x00a93bbc | 42 | 0 | 0 | 3 | 0 | 1 | 0 |
| hl_23 | ArtificialLight -[initWithWorld:dynamicWorld:saveDict:cache:parentObject:] | 0x00a93c64 | 412 | 7 | 11 | 11 | 1 | 24 | 5 |
| hl_24 | ArtificialLight -[getSaveDict] | 0x00a942d4 | 310 | 3 | 10 | 7 | 2 | 17 | 0 |
| hl_25 | ArtificialLight -[dealloc] | 0x00a947ac | 59 | 2 | 2 | 2 | 1 | 4 | 0 |
| hl_26 | ArtificialLight -[worldChanged:] | 0x00a94898 | 577 | 3 | 1 | 7 | 0 | 16 | 25 |
| hl_27 | ArtificialLight -[removeFromMacroBlock] | 0x00a9519c | 43 | 2 | 2 | 0 | 1 | 2 | 0 |
| hl_28 | ArtificialLight -[addContributionForPhysicalBlockLoadedAtXPos:yPos:] | 0x00a95248 | 413 | 3 | 1 | 5 | 0 | 17 | 12 |
| hl_29 | ArtificialLight -[.cxx_construct] | 0x00a958bc | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| hl_30 | GlowBlock -[initSubDerivedItems] | 0x00ca8304 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| hl_31 | GlowBlock -[objectType] | 0x00ca8318 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| hl_32 | GlowBlock -[getLightRGB] | 0x00ca8334 | 40 | 1 | 0 | 1 | 0 | 2 | 2 |
| hl_33 | GlowBlock -[initWithWorld:dynamicWorld:atPosition:cache:tile:] | 0x00ca83d4 | 339 | 5 | 1 | 6 | 2 | 6 | 25 |
| hl_34 | GlowBlock -[initWithWorld:dynamicWorld:saveDict:cache:] | 0x00ca8920 | 214 | 7 | 4 | 6 | 2 | 10 | 3 |
| hl_35 | GlowBlock -[getSaveDict] | 0x00ca8c78 | 123 | 3 | 4 | 2 | 2 | 5 | 1 |
| hl_36 | GlowBlock -[dealloc] | 0x00ca8e64 | 58 | 2 | 2 | 1 | 1 | 2 | 0 |
| hl_37 | GlowBlock -[removeFromMacroBlock] | 0x00ca8f4c | 92 | 3 | 1 | 3 | 1 | 5 | 0 |
| hl_38 | GlowBlock -[worldChanged:] | 0x00ca90bc | 188 | 2 | 1 | 4 | 0 | 3 | 7 |
| hl_39 | GlowBlock -[setNeedsRemoved:] | 0x00ca93ac | 85 | 3 | 1 | 3 | 1 | 4 | 1 |
| hl_40 | GlowBlock -[lightGlowQuadCount] | 0x00ca9500 | 23 | 0 | 0 | 1 | 0 | 0 | 2 |
| hl_41 | GlowBlock -[lightPos] | 0x00ca955c | 44 | 0 | 0 | 1 | 0 | 3 | 0 |
| hl_42 | GlowBlock -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:] | 0x00ca960c | 29 | 1 | 1 | 1 | 0 | 1 | 0 |
| hl_43 | tileIsBurnableBlock | 0x00a140ec | 37 | 0 | 0 | 0 | 0 | 0 | 4 |
| hl_44 | tileIsBurnable | 0x00a14180 | 123 | 3 | 1 | 0 | 0 | 8 | 11 |
| hl_45 | baseTemperatureForWorldPos | 0x00a14f28 | 170 | 1 | 1 | 0 | 0 | 5 | 3 |
| hl_46 | currentTemperatureForTileAtWorldPos | 0x00a15404 | 69 | 0 | 0 | 0 | 0 | 1 | 0 |
| hl_47 | customRulesBaseTemp | 0x00a14ba0 | 126 | 1 | 1 | 0 | 0 | 5 | 14 |
| hl_48 | customRulesPoleOffset | 0x00a14d98 | 99 | 1 | 1 | 0 | 0 | 5 | 12 |
| hl_49 | seasonForWorldX | 0x00a14a48 | 86 | 1 | 0 | 0 | 0 | 5 | 3 |

## Findings (E120)

- **The temperature model is closed end to end** (the two C functions + the two
  custom-rules helpers): `T_tile = base * cov + 20.0 * (1 - cov) + tile.artificialHeat`
  with `cov = sunLight/255 * 0.8 + 0.2`; `base = customRulesBaseTemp - hemi *
  customRulesPoleOffset - min(arg, 5.0) + argB * (1 - hemi*0.8) + cos(2pi*argA - pi) *
  5.0 * (1 - hemi*0.8) - (y > 512 ? (y-512)/512 * 50 : 0)`; `hemi =
  |fmod(x/32 / worldWidthMacro, 5) - 2| / 2`. The five custom-rules climate presets:
  base {0:0.0, 1:1.0, 2:3.0, 3:37.0, 4:45.0} default 3.0, pole offset {0,1,3,4}:2.0 /
  {2}:45.0 / default 45.0, and the `seasonForWorldX` far-longitude band.
- **The fire loop is complete**: FireObject seeds `burnTimer` + the `spreadTimers`
  quad (PRNG 0x674678, reset rand/2^31 + 2.0), polls neighbours and calls
  `DynamicWorld placeFireAtPosition:`; the burnable sets are `tileIsBurnableBlock`
  {9, 0x15, 0x16, 0x17, 0x20} plus trees/dead trees/plants/the 'B' marker, and an
  interaction object of type 3 (itemType != 0xAA) can catch fire; the Workbench
  self-checks `tileIsBurnable` in its own update.
- **The light engine carries the heat**: `ArtificialLight` holds
  color/maxHeat/radius/lightDirection + the contributionGrid/addedGrid pair;
  `addContributionForPhysicalBlockLoadedAtXPos:yPos:` writes the per-tile
  artificialLight*/artificialHeat; Torch / FireObject / GlowBlock / NormalPlant all
  forward through `addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:`;
  `GlowBlock` (type 18) is the glow overlay for tileRequiresGlowBlock materials.
- The C targets run the pipeline through a new `addr`/`symbol` route: their bounds
  come from the dynsym sizes (the exidx ranges span several C functions), so
  hl_45..hl_49 are trimmed at the measured sizes (170/69/126/99/86 words).

## Boundaries

- hl_13/hl_14/hl_17/hl_18 are census-grade; the other 46 read in full at the
  instruction level (the small ones completely).
- The 0xAA(170) itemType sentinel and the 'B' marker semantics stay observed-only;
  the hl_14 draw internals (uniform names) stay at the selector level.
- The seasonal far-longitude band thresholds ((mw*64, mw*224)) are recorded as
  observed; the exact wrap presentation of (abs + 5.0) mod 1.0 is a numeric no-op
  modulo 1 and is kept as the code executes it.
