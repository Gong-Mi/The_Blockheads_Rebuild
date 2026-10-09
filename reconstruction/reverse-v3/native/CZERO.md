# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 34140 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| cz_00 | blockheadNamesInit | 0x00cc7690 | 17646 | 2 | 1997 | 0 | 1 | 8 | 7 |
| cz_01 | checkCanEnterTile | 0x00bde520 | 6200 | 11 | 2 | 0 | 0 | 410 | 928 |
| cz_02 | getRandomWorldName | 0x00b2bba0 | 1818 | 8 | 232 | 0 | 3 | 14 | 3 |
| cz_03 | signConnectionTypeAndOffsetForPos | 0x005f85a0 | 1361 | 13 | 2 | 0 | 0 | 77 | 258 |
| cz_04 | fillQuadBufferMultiTexture | 0x00d92db0 | 1305 | 0 | 0 | 0 | 0 | 30 | 2 |
| cz_05 | dpadFindPath | 0x00be4600 | 904 | 2 | 0 | 0 | 0 | 51 | 90 |
| cz_06 | drawClock | 0x007c4860 | 378 | 0 | 0 | 0 | 0 | 9 | 13 |
| cz_07 | fillQuadBufferDodoEgg | 0x00d94218 | 314 | 0 | 0 | 0 | 0 | 2 | 2 |
| cz_08 | drawCleverQuad | 0x007c4e48 | 252 | 0 | 0 | 0 | 0 | 3 | 0 |
| cz_09 | prefixNameForDodoBreed | 0x006a4b18 | 246 | 0 | 32 | 0 | 0 | 0 | 34 |
| cz_10 | cpLookAt | 0x007c3a6c | 228 | 0 | 0 | 0 | 0 | 5 | 3 |
| cz_11 | cpProject | 0x007c3f18 | 222 | 0 | 0 | 0 | 0 | 0 | 2 |
| cz_12 | q_sort | 0x0086915c | 178 | 0 | 0 | 0 | 0 | 2 | 14 |
| cz_13 | quadIndices | 0x007c37dc | 164 | 0 | 0 | 0 | 0 | 3 | 8 |
| cz_14 | init_by_array | 0x0096a4e8 | 159 | 0 | 0 | 0 | 0 | 1 | 11 |
| cz_15 | cardinalSplineInterpolate | 0x00c37b58 | 121 | 0 | 0 | 0 | 0 | 11 | 0 |
| cz_16 | imageTypeEmitsParticles | 0x00a15a74 | 120 | 0 | 0 | 0 | 0 | 0 | 32 |
| cz_17 | tileForegroundContentsCanCoExistWithBlocksAndElevatorShafts | 0x00a12434 | 117 | 0 | 0 | 0 | 0 | 0 | 17 |
| cz_18 | particleGravityTypeForImage | 0x00a15c54 | 117 | 0 | 0 | 0 | 0 | 0 | 30 |
| cz_19 | randomMeditationBonus | 0x00a178f8 | 89 | 0 | 0 | 0 | 0 | 3 | 10 |
| cz_20 | drawQuad | 0x007c4290 | 83 | 0 | 0 | 0 | 0 | 3 | 0 |
| cz_21 | CreateDispatchTimer | 0x009176f8 | 72 | 0 | 1 | 0 | 0 | 7 | 1 |
| cz_22 | cpPerspective | 0x007c3e00 | 70 | 0 | 0 | 0 | 0 | 2 | 0 |
| cz_23 | tileIsDeadTreeTrunk | 0x00a137e8 | 69 | 0 | 0 | 0 | 0 | 0 | 9 |
| cz_24 | genrand_int31 | 0x0096ab6c | 67 | 0 | 0 | 0 | 0 | 1 | 1 |
| cz_25 | tileTexCoordsForWorkbenchTypeAndLevel | 0x005effb8 | 67 | 0 | 0 | 0 | 0 | 4 | 2 |
| cz_26 | genrand_int32 | 0x0096aa6c | 64 | 0 | 0 | 0 | 0 | 1 | 1 |
| cz_27 | genrand_real3 | 0x0096ad40 | 52 | 0 | 0 | 0 | 0 | 1 | 1 |
| cz_28 | genrand_real2 | 0x0096ac78 | 50 | 0 | 0 | 0 | 0 | 1 | 1 |
| cz_29 | nameForDodoBreed | 0x00a7ffd0 | 49 | 1 | 3 | 0 | 1 | 2 | 2 |
| cz_30 | windParticlesImageTypeForSurfaceEmittingTile | 0x00a159c8 | 43 | 0 | 0 | 0 | 0 | 0 | 11 |
| cz_31 | tileIsInteractionObject | 0x00a143d8 | 30 | 0 | 0 | 0 | 0 | 1 | 2 |
| cz_32 | genrand_res53 | 0x0096ae10 | 26 | 0 | 0 | 0 | 0 | 2 | 0 |
| cz_33 | releasePixelsMainMenu | 0x009fdf50 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| cz_34 | releasePixelsPaintMix | 0x00663254 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| cz_35 | clearLineOfSightBetweenTiles | 0x00a19820 | 251 | 0 | 0 | 0 | 0 | 20 | 19 |
| cz_36 | transparencyLevelForTile | 0x00a30e68 | 249 | 0 | 0 | 0 | 0 | 4 | 66 |
| cz_37 | tileContainsUsableElevator | 0x00a12bd8 | 211 | 4 | 1 | 0 | 0 | 6 | 17 |
| cz_38 | drawShaderQuadMultiTexture | 0x007c4554 | 143 | 0 | 0 | 0 | 0 | 4 | 0 |
| cz_39 | tileIsClimable | 0x00a1311c | 62 | 0 | 0 | 0 | 0 | 2 | 4 |
| cz_40 | tileContainsUsableGate | 0x00a12b04 | 53 | 2 | 0 | 0 | 0 | 3 | 5 |
| cz_41 | Vector::operator/(float) | 0x00a31284 | 33 | 0 | 0 | 0 | 0 | 1 | 0 |
| cz_42 | reloadDrawBlockDynamicObjectStaticCylindersForTile | 0x00a19604 | 27 | 0 | 0 | 0 | 0 | 1 | 3 |
| cz_43 | reloadDrawBlockDynamicObjectItemQuadsForTile | 0x00a19748 | 27 | 0 | 0 | 0 | 0 | 1 | 3 |
| cz_44 | reloadDrawBlockDodoEggQuadsForTile | 0x00a196dc | 27 | 0 | 0 | 0 | 0 | 1 | 3 |
| cz_45 | Vector::dotProduct(Vector) | 0x006689d0 | 25 | 0 | 0 | 0 | 0 | 0 | 0 |
| cz_46 | FreeBlockCreationCount::FreeBlockCreationCount() | 0x00bb4798 | 14 | 0 | 0 | 0 | 0 | 1 | 0 |
| cz_47 | BlockParticleEmitter::BlockParticleEmitter() | 0x00a3124c | 14 | 0 | 0 | 0 | 0 | 1 | 0 |
| cz_48 | Vector2::operator const float*() | 0x00ce8dd8 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| cz_49 | macroTileHasDynamicObjectsThatNeedPhysicalBlock | 0x00a31b44 | 152 | 3 | 1 | 0 | 0 | 6 | 12 |
| cz_50 | tileContainsUsableDoor | 0x00a1295c | 53 | 2 | 0 | 0 | 0 | 3 | 5 |
| cz_51 | tileContainsUsableTrapDoor | 0x00a12a30 | 53 | 2 | 0 | 0 | 0 | 3 | 5 |
| cz_52 | tileIsSwimmable | 0x00a116dc | 48 | 0 | 0 | 0 | 0 | 0 | 5 |

## Findings (E123)

- **The last un-connected game functions are on the books**: the six giants plus
  47 zero-trace / dump-only strays - 53 bodies, 34140 words. The C layer's
  never-touched list (301) is down to pure STL instantiations and the iOS shims.
- **The giants decoded**: `blockheadNamesInit` and `getRandomWorldName` are
  generated table-builders (thousands of unrolled pc-relative pointer stores
  assembling the name-element string arrays - no logic; the string data interleaves
  the code as literal pools); `checkCanEnterTile` is the movement gate (6200 words,
  928 branches; probe inventory: tileIsSolid 64x, tileIsAirOrSnow 32x,
  tileContainsUsableDoor 31x, tileIsSwimmable 24x, tileIsWater 19x,
  tileContainsUsableTrapDoor 16x, tileContainsUsableElevator 11x, tileIsClimable
  7x; result struct {0x19, 8, 999999, 0} - the 999999 cost sentinel);
  `dpadFindPath` is the frontier search over it (vector<intpair>, checkCanEnterTile
  x4); `signConnectionTypeAndOffsetForPos` scans the neighbour ring.
- **The callee closure lands**: tileContainsUsableDoor / TrapDoor / Gate /
  Elevator + tileIsSwimmable + tileIsClimable + tileIsDeadTreeTrunk - the exact
  gates checkCanEnterTile leans on; the door/gate/trapdoor "usable" pattern is
  tileContains* && byte0xa == 0xff + the object dispatch.
- **The MT19937 family**: init_by_array + genrand_int31/int32/real2/real3/res53
  (standard tempering constants; the 0x96a830 reload on index wrap).
- **The render leftovers**: drawClock (4 tanf hands + drawQuad), drawCleverQuad
  (the elements-path draw), the multi-texture shader quad, the three remaining
  reload flags ([obj+0x1ac] dodo-egg quads / 0x1c0 item quads / 0x1d8 static
  cylinders), quadIndices (the shared 6-index-per-quad buffer).
- **The system extras**: clearLineOfSightBetweenTiles (the normalized Vector2
  walk + tile probes), transparencyLevelForTile (null -> 5), cardinalSplineInterpolate,
  imageTypeEmitsParticles (the 4 image bands + singletons),
  particleGravityTypeForImage, CreateDispatchTimer (GCD), the cpLookAt / cpProject
  / cpPerspective camera trio, the dodo-breed names, the wind-particle map,
  the no-op releasePixels stubs and the two ctors.

## Boundaries

- blockheadNamesInit / getRandomWorldName are census: generated table-builders
  whose bulk is the string-pointer stores (the data sits in the listings).
- checkCanEnterTile / signConnectionTypeAndOffsetForPos / dpadFindPath /
  transparencyLevelForTile / tileContainsUsableElevator are census-lite (gates +
  call inventories recorded; the full branch trees are in the listings).
