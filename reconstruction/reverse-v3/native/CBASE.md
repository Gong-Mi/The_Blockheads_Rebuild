# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 4059 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| cx_00 | Vector2::operator float*() | 0x004bdaac | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_01 | Vector::operator float*() | 0x004b5c08 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_02 | makeIntpair | 0x004b49fc | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_03 | Vector::Vector(float,float,float) | 0x004b52ac | 21 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_04 | Vector2::Vector2(float,float) | 0x004d0480 | 13 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_05 | clamp(float,float,float) | 0x004be068 | 27 | 0 | 0 | 0 | 0 | 0 | 2 |
| cx_06 | linearInterpolate(float,float,float) | 0x00582a14 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_07 | Vector2::operator+(Vector2) | 0x004d0418 | 26 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_08 | Vector::Vector(float,float,float,float) | 0x004d0d08 | 21 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_09 | Vector2::operator*(float) | 0x004d0368 | 22 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_10 | clamp(int,int,int,int) | 0x004c0b70 | 21 | 0 | 0 | 0 | 0 | 0 | 2 |
| cx_11 | Vector2::operator-(Vector2) | 0x004d04b4 | 26 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_12 | Vector::Vector() | 0x004bed60 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_13 | Vector2::Vector2() | 0x004d5170 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| cx_14 | Vector::operator+(Vector) | 0x004d6538 | 43 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_15 | reverseLinearInterpolate(float,float,float) | 0x005ac12c | 30 | 0 | 0 | 0 | 0 | 0 | 2 |
| cx_16 | Vector::operator*(float) | 0x004da9cc | 33 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_17 | Vector2::normal() | 0x00575108 | 60 | 0 | 0 | 0 | 0 | 6 | 3 |
| cx_18 | Vector::normal() | 0x005be75c | 75 | 0 | 0 | 0 | 0 | 8 | 3 |
| cx_19 | Vector::length() | 0x0057509c | 27 | 0 | 0 | 0 | 0 | 2 | 2 |
| cx_20 | Vector::cross(Vector) | 0x005be888 | 68 | 0 | 0 | 0 | 0 | 4 | 0 |
| cx_21 | Vector::normalize() | 0x005bf2b4 | 49 | 0 | 0 | 0 | 0 | 1 | 3 |
| cx_22 | Vector::multiplyMatrix(float*) | 0x005bf378 | 108 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_23 | Vector::operator-(Vector) | 0x00668924 | 43 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_24 | Vector2::operator*(Vector2) | 0x00820690 | 26 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_25 | Vector2::operator/(float) | 0x004d03c0 | 22 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_26 | tileIsSolid | 0x00a1179c | 31 | 0 | 0 | 0 | 0 | 0 | 3 |
| cx_27 | tileIsWater | 0x00a11690 | 19 | 0 | 0 | 0 | 0 | 0 | 1 |
| cx_28 | tileIsAirWaterOrSnow | 0x00a126dc | 33 | 0 | 0 | 0 | 0 | 0 | 3 |
| cx_29 | tileIsAirOrSnow | 0x00a12760 | 27 | 0 | 0 | 0 | 0 | 0 | 2 |
| cx_30 | tileIsTree | 0x00a13214 | 114 | 0 | 0 | 0 | 0 | 1 | 16 |
| cx_31 | tileIsSemiTransparentSolidBlock | 0x00a128b0 | 43 | 0 | 0 | 0 | 0 | 1 | 4 |
| cx_32 | tileIsDeadTree | 0x00a138fc | 84 | 0 | 0 | 0 | 0 | 1 | 11 |
| cx_33 | tileIsAir | 0x00a12300 | 19 | 0 | 0 | 0 | 0 | 0 | 1 |
| cx_34 | tileContainsGate | 0x00a127cc | 19 | 0 | 0 | 0 | 0 | 0 | 1 |
| cx_35 | tileIsHalfDepth | 0x00a14450 | 148 | 4 | 1 | 0 | 0 | 6 | 24 |
| cx_36 | tileIsBush | 0x00a13a4c | 165 | 0 | 0 | 0 | 0 | 0 | 25 |
| cx_37 | tileIsTreeTrunk | 0x00a11390 | 192 | 0 | 0 | 0 | 0 | 1 | 29 |
| cx_38 | tileContainsDoor | 0x00a12818 | 19 | 0 | 0 | 0 | 0 | 0 | 1 |
| cx_39 | tileIsPlant | 0x00a13ce0 | 99 | 0 | 0 | 0 | 0 | 0 | 14 |
| cx_40 | tileIsWorkbench | 0x00a1436c | 27 | 0 | 0 | 0 | 0 | 0 | 2 |
| cx_41 | tileRequiresGlowBlock | 0x00a14824 | 34 | 0 | 0 | 0 | 0 | 1 | 6 |
| cx_42 | tileConductsElectricity | 0x00a11818 | 51 | 0 | 0 | 0 | 0 | 0 | 12 |
| cx_43 | backWallIsMutable | 0x00a1234c | 49 | 0 | 0 | 0 | 0 | 0 | 6 |
| cx_44 | tileContainsTrapDoor | 0x00a12864 | 19 | 0 | 0 | 0 | 0 | 0 | 1 |
| cx_45 | tileTypeIsPortalBaseStone | 0x00a146a0 | 97 | 0 | 0 | 0 | 0 | 0 | 17 |
| cx_46 | tileIsUnplacedBlockMinableWithPickaxe | 0x00a13694 | 57 | 0 | 0 | 0 | 0 | 0 | 7 |
| cx_47 | tileAllowsPlacingOfSolidBlocks | 0x00a12608 | 53 | 0 | 0 | 0 | 0 | 1 | 11 |
| cx_48 | backWallRemovesWithRepairTool | 0x00a12410 | 9 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_49 | tileIsNotUnminedBlockSoCanBeRemovedOnRepair | 0x00a13778 | 28 | 0 | 0 | 0 | 0 | 1 | 5 |
| cx_50 | tileAtWorldPositionLoaded | 0x00a12f24 | 126 | 1 | 0 | 0 | 0 | 5 | 11 |
| cx_51 | tileAtWorldPosition | 0x00a16e68 | 147 | 1 | 0 | 0 | 0 | 5 | 11 |
| cx_52 | worldIndexAtWorldPosition | 0x00a156a8 | 100 | 1 | 0 | 0 | 0 | 4 | 9 |
| cx_53 | worldIndexAtWorldPos | 0x00a15838 | 100 | 1 | 0 | 0 | 0 | 4 | 9 |
| cx_54 | macroTileAtMacroPostion | 0x00a16ccc | 103 | 1 | 1 | 0 | 0 | 4 | 9 |
| cx_55 | macroTileAtWorldPostion | 0x00a1770c | 122 | 1 | 1 | 0 | 0 | 6 | 8 |
| cx_56 | macroPosForWorldPos | 0x00a16594 | 99 | 1 | 0 | 0 | 0 | 6 | 10 |
| cx_57 | macroIndexAtMacroPosition | 0x00a174a4 | 83 | 1 | 1 | 0 | 0 | 4 | 5 |
| cx_58 | macroIndexAtWorldIndex | 0x00a173c4 | 56 | 1 | 0 | 0 | 0 | 6 | 0 |
| cx_59 | tileAtWorldIndexLoaded | 0x00a16944 | 226 | 3 | 1 | 0 | 0 | 12 | 8 |
| cx_60 | getWorldPosForWorldIndex | 0x00a15518 | 49 | 1 | 0 | 0 | 0 | 4 | 0 |
| cx_61 | absoluteSeasonFraction | 0x00a149f8 | 20 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_62 | freezingLevelForWorldX | 0x00a151d0 | 141 | 1 | 1 | 0 | 0 | 5 | 2 |
| cx_63 | getWorldUpVectorForX | 0x00a148b0 | 82 | 1 | 0 | 0 | 0 | 2 | 2 |
| cx_64 | objectTypeIsInteractionObject | 0x008bcacc | 43 | 0 | 0 | 0 | 0 | 0 | 5 |
| cx_65 | objectTypeHasStaticPosition | 0x008b68ac | 120 | 0 | 0 | 0 | 0 | 3 | 20 |
| cx_66 | objectTypeCanBeLoadedOnlyWhenClientOwnerOnline | 0x008ba904 | 9 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_67 | objectTypeMayHaveArtificalLight | 0x00903420 | 38 | 0 | 0 | 0 | 0 | 2 | 4 |
| cx_68 | objectTypeRequiresPartialUpdate | 0x008b6a8c | 13 | 0 | 0 | 0 | 0 | 1 | 0 |
| cx_69 | objectTypeIsTree | 0x008bc974 | 43 | 0 | 0 | 0 | 0 | 0 | 5 |
| cx_70 | objectTypeIsPlant | 0x008bca20 | 43 | 0 | 0 | 0 | 0 | 0 | 5 |
| cx_71 | objectTypeIsNPC | 0x008c4b74 | 43 | 0 | 0 | 0 | 0 | 0 | 5 |

## Findings (E121)

- **The world geometry core is explicit**: `worldIndex = y * (worldWidthMacro << 5) + x`
  (x wrapped into [0, worldWidthMacro*32), y in [0, 1024)); the in-block index is
  `(x & 31) + ((y & 31) << 5)`; tiles are 64-byte records at `block->tiles + idx*64`;
  MacroTiles are 20-byte records at `macroArray + (my * worldWidthMacro + mx) * 20`
  with my in [0, 32). macroPosForWorldPos CLAMPS y (0..1023) while the loaded-tile
  accessors return NULL / -1.
- **The tile predicate layer closes**: solid = type not in {2 (air), 3 (water),
  5 (snow)}; water = 3; air = 2; semi-transparent solids {0x18, 0x3b, 4} + gem
  blocks; the foreground/background sets for trees, bushes, trunks, dead trees,
  doors, gates, trapdoors and workbenches; electricity = contents 0x60 or type in
  {0x35, 0x36, 0x38, 0x39, 0x1a, 0x43, 0x44}.
- **The object-type tables are pinned AND cross-checked**: tree {1..9, 0x25,
  0x39}, plant {0xa, 0xb, 0xc, 0x1b, 0x21, 0x22, 0x3a, 0x3b, 0x3d, 0x3e}, NPC
  {0xd, 0x19, 0x1c, 0x23, 0x24, 0x27, 0x33, 0x3f} - exactly the
  dynamicObjectTypeForNPCType image for NPCType 1..8 - interaction objects
  {0x17, 0x2d, 0x2e, 0x2f, 0x3c, 0x30, 0x31, 0x32, 0x40}; all four tables sit
  back to back at 0xe4aa1c..0xe4aab4.
- **The math core**: clamp/lerp and the reverse variant ((a-b)/(t-b) with t==b ->
  0); Vector/Vector2 ctors (default = all ones), componentwise ops, cross,
  normal()/normalize() zero guards, length() sqrt guard, multiplyMatrix =
  row-vector x column-major 4x4.
- **Climate helpers**: `absoluteSeasonFraction(d) = fmod(d / 900.0 / 4.0, 1.0)`
  (the 3600-unit season year); `getWorldUpVectorForX` folds the longitude angle
  into +/-pi/2 before polarToRectangular; `freezingLevelForWorldX` shares the E120
  hemi (|fmod(x/32/mw, 5) - 2|/2) and maps `v/50.0*512.0 + 512.0` with
  `v = customRulesBaseTemp - hemi*pole - min(c, 5.0) + b*(1 - hemi*0.8) +
  cos(2*pi*a - pi)*5.0`.
- These 72 bodies are the callgraph hot list: 782 + 567 + 502 + 463 call sites
  land on the Vector2/Vector conversions, makeIntpair and tileAtWorldPositionLoaded
  alone; 4,657 call sites point into this layer overall.

## Boundaries

- cx_35's second half stays at the vtable level (a DerivedTileProperties pair:
  u16 == 2 then a virtual value in {0, 1, 3, 4, 5, 6}); those selectors are not
  named in this batch.
- cx_62's a/b/c argument roles are recorded from the formula shape (season phase /
  scale / cap) - naming deferred.
- The Apportable per-class selector-index dispatch (r0 = selector slot) carries the
  worldWidthMacro reads; individual slots are not resolved beyond that (E120).
