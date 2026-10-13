# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 15100 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| cy_00 | reloadDrawBlockGeometryForTile | 0x00a1915c | 146 | 0 | 0 | 0 | 0 | 7 | 30 |
| cy_01 | reloadDrawBlockDynamicObjectQuadsForTile | 0x00a19670 | 27 | 0 | 0 | 0 | 0 | 1 | 3 |
| cy_02 | reloadDrawBlockLightGlowQuadsForTile | 0x00a197b4 | 27 | 0 | 0 | 0 | 0 | 1 | 3 |
| cy_03 | reloadDrawBlockDynamicObjectStaticGeometryForTile | 0x00a19598 | 27 | 0 | 0 | 0 | 0 | 1 | 3 |
| cy_04 | recalculateDrawBlockLightingForTile | 0x00a18f68 | 125 | 1 | 0 | 0 | 0 | 8 | 16 |
| cy_05 | reloadDrawBlockWaterForTile | 0x00a193a4 | 125 | 0 | 0 | 0 | 0 | 7 | 21 |
| cy_06 | fillQuadBuffer | 0x00d948fc | 227 | 0 | 0 | 0 | 0 | 2 | 0 |
| cy_07 | fillQuadBufferColored | 0x00d94c88 | 1297 | 0 | 0 | 0 | 0 | 35 | 2 |
| cy_08 | updateQuadBufferTexCoords | 0x00d91b30 | 79 | 0 | 0 | 0 | 0 | 0 | 0 |
| cy_09 | updateQuadBufferVertsAndMatrix | 0x00d91c6c | 744 | 0 | 0 | 0 | 0 | 10 | 2 |
| cy_10 | fillArbitraryQuadBuffer | 0x00d96f5c | 1165 | 0 | 0 | 0 | 0 | 27 | 2 |
| cy_11 | updateArbitraryQuadVertsAndMatrix | 0x00d98190 | 762 | 0 | 0 | 0 | 0 | 6 | 2 |
| cy_12 | pushDepthMaskState | 0x007c55e4 | 130 | 0 | 1 | 0 | 0 | 4 | 10 |
| cy_13 | popDepthMaskState | 0x007c57ec | 109 | 0 | 0 | 0 | 0 | 2 | 9 |
| cy_14 | pushDepthTestState | 0x007c5238 | 128 | 0 | 1 | 0 | 0 | 4 | 10 |
| cy_15 | popDepthTestState | 0x007c5438 | 107 | 0 | 0 | 0 | 0 | 2 | 9 |
| cy_16 | drawShaderQuad | 0x007c43dc | 94 | 0 | 0 | 0 | 0 | 3 | 0 |
| cy_17 | drawShaderQuadNoTexture | 0x007c4790 | 52 | 0 | 0 | 0 | 0 | 2 | 0 |
| cy_18 | texCoordsForImageIndex | 0x004d6820 | 49 | 0 | 0 | 0 | 0 | 2 | 0 |
| cy_19 | texCoordsForItemType | 0x004d6040 | 58 | 0 | 0 | 0 | 0 | 2 | 0 |
| cy_20 | growthVigorForTreeTypeAtPos | 0x004c0bd4 | 1196 | 4 | 4 | 0 | 0 | 53 | 45 |
| cy_21 | growthVigorForPlantTypeAtPos | 0x00854138 | 362 | 2 | 2 | 0 | 0 | 14 | 13 |
| cy_22 | baseGrowthRateForTreeType | 0x004c1e84 | 64 | 0 | 0 | 0 | 0 | 0 | 11 |
| cy_23 | classForDynamicObjectType | 0x00b597bc | 1115 | 1 | 1 | 0 | 64 | 64 | 66 |
| cy_24 | classForInteractionObjectType | 0x005f3f50 | 178 | 1 | 1 | 0 | 9 | 9 | 10 |
| cy_25 | dynamicObjectTypeForInteractionObjectType | 0x008bc89c | 54 | 0 | 0 | 0 | 0 | 0 | 11 |
| cy_26 | dynamicObjectTypeForNPCType | 0x006495a0 | 52 | 0 | 0 | 0 | 0 | 0 | 10 |
| cy_27 | classForNPCType | 0x006437e4 | 161 | 1 | 1 | 0 | 8 | 8 | 10 |
| cy_28 | tameCountRequirementForNPCType | 0x0064be74 | 46 | 0 | 0 | 0 | 0 | 0 | 9 |
| cy_29 | nameForDonkeyBreed | 0x006caf24 | 61 | 1 | 4 | 0 | 1 | 2 | 3 |
| cy_30 | npcTypeFromCageItemType | 0x00580e5c | 50 | 0 | 0 | 0 | 0 | 0 | 11 |
| cy_31 | contentsTypeForPlantType | 0x00a653d8 | 71 | 0 | 0 | 0 | 0 | 0 | 11 |
| cy_32 | treeTypeForSeedItemType | 0x008e4b2c | 91 | 0 | 0 | 0 | 0 | 0 | 29 |
| cy_33 | plantTypeForSeedItemType | 0x008e4c98 | 107 | 0 | 0 | 0 | 0 | 0 | 42 |
| cy_34 | treeTypeForTreePromise | 0x008c3a88 | 96 | 0 | 0 | 0 | 0 | 0 | 17 |
| cy_35 | itemTypeIsStackable | 0x004ea3cc | 61 | 0 | 0 | 0 | 0 | 2 | 5 |
| cy_36 | itemTypeIsSowable | 0x0056871c | 76 | 0 | 0 | 0 | 0 | 0 | 22 |
| cy_37 | itemTypeIsPainting | 0x005b902c | 37 | 0 | 0 | 0 | 0 | 0 | 10 |
| cy_38 | itemTypeCanBeColored | 0x004d6128 | 62 | 0 | 0 | 0 | 0 | 0 | 10 |
| cy_39 | itemTypeIsTwoBlocksWide | 0x0057b5e4 | 19 | 0 | 0 | 0 | 0 | 0 | 4 |
| cy_40 | itemTypeOccupiesForegroundContents | 0x0057b630 | 35 | 0 | 0 | 0 | 0 | 2 | 7 |
| cy_41 | interactionObjectItemTypeOccupiesForeground | 0x0057b6bc | 17 | 0 | 0 | 0 | 0 | 0 | 3 |
| cy_42 | itemTypeIsColumn | 0x005b291c | 97 | 0 | 0 | 0 | 0 | 0 | 28 |
| cy_43 | itemTypeIsStairs | 0x005b2b0c | 101 | 0 | 0 | 0 | 0 | 0 | 28 |
| cy_44 | itemTypeIsBlock | 0x004cc11c | 153 | 0 | 0 | 0 | 0 | 1 | 38 |
| cy_45 | itemTypeIsSolid | 0x004daf58 | 196 | 0 | 0 | 0 | 0 | 0 | 49 |
| cy_46 | itemTypeIsTrainCar | 0x0057bd18 | 22 | 0 | 0 | 0 | 0 | 0 | 5 |
| cy_47 | itemTypeOccupiesBackgroundContents | 0x00580be0 | 16 | 0 | 0 | 0 | 0 | 0 | 3 |
| cy_48 | itemTypeIsPlacableOnTrees | 0x00580c20 | 47 | 0 | 0 | 0 | 0 | 0 | 13 |
| cy_49 | itemTypeIsValidFillItem | 0x00580cdc | 96 | 0 | 0 | 0 | 0 | 0 | 26 |
| cy_50 | itemTypeIsLightEmittingBlock | 0x00580f24 | 25 | 0 | 0 | 0 | 0 | 1 | 4 |
| cy_51 | itemTypeIsHangable | 0x005b23b8 | 345 | 0 | 0 | 0 | 0 | 0 | 89 |
| cy_52 | itemTypeIsWorkbench | 0x005b2aa0 | 13 | 0 | 0 | 0 | 0 | 1 | 0 |
| cy_53 | itemTypeIsInteractionObject | 0x005b2ad4 | 14 | 0 | 0 | 0 | 0 | 1 | 0 |
| cy_54 | itemTypeIsPlacableOnBackWall | 0x005b2ca0 | 266 | 0 | 0 | 0 | 0 | 3 | 44 |
| cy_55 | itemTypeIsTorch | 0x005df794 | 62 | 0 | 0 | 0 | 0 | 0 | 18 |
| cy_56 | tileIsPaintable | 0x00a118e4 | 622 | 8 | 1 | 0 | 0 | 19 | 110 |
| cy_57 | paintedIndexForImageIndex | 0x00a15e28 | 475 | 0 | 0 | 0 | 0 | 0 | 104 |
| cy_58 | particleColorForTile | 0x00a10a48 | 563 | 0 | 0 | 0 | 0 | 28 | 29 |
| cy_59 | itemTypeFromTileIsForegorund | 0x00a18044 | 874 | 5 | 1 | 0 | 0 | 11 | 227 |
| cy_60 | torchConnectionTypeForPos | 0x004b4444 | 366 | 0 | 0 | 0 | 0 | 24 | 73 |
| cy_61 | testTile | 0x00db222c | 281 | 9 | 1 | 0 | 0 | 14 | 22 |
| cy_62 | preserveItemDataAInCraftedItem | 0x00aed208 | 68 | 0 | 0 | 0 | 0 | 0 | 22 |
| cy_63 | polarToRectangular | 0x00582e00 | 45 | 0 | 0 | 0 | 0 | 5 | 0 |
| cy_64 | closestPointOnLineToPoint | 0x00668a34 | 165 | 0 | 0 | 0 | 0 | 6 | 4 |
| cy_65 | quickSort | 0x008546e0 | 31 | 0 | 0 | 0 | 0 | 1 | 2 |
| cy_66 | linearInterpolate(Vector) | 0x00c38b6c | 56 | 0 | 0 | 0 | 0 | 3 | 0 |
| cy_67 | getStarPoints | 0x005aa394 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| cy_68 | Vector::operator*(Vector) | 0x0058198c | 43 | 0 | 0 | 0 | 0 | 1 | 0 |
| cy_69 | GLKMathUnproject | 0x0020ca1c | 562 | 0 | 3 | 0 | 0 | 9 | 4 |

## Findings (E122)

- **The callgraph's remaining non-STL C targets are closed**: the render
  dirty-flag reload family (geometry/fg/bg, dyn-object quads, light glow,
  static geometry, lighting, water), the GL state push/pop pairs
  (depth mask/test via the 0x89a4f8 / 0x89a8a4 trackers) and the quad
  packers (fillQuadBuffer*/updateQuadBuffer*/fillArbitraryQuadBuffer), the
  item-type predicate families, the tree/plant/NPC classification resolvers,
  the paint/particle/torch-connection helpers and testTile (the WirePath
  tester).
- **Cross-checks land**: `dynamicObjectTypeForInteractionObjectType` =
  {0x2d, 0x2e, 0x17, 0x2f, 0x30, 0x31, 0x32, 0x3c, 0x40} and
  `dynamicObjectTypeForNPCType` = {0xd, 0x19, 0x1c, 0x23, 0x24, 0x27, 0x33,
  0x3f} reproduce the E121 objectType tables exactly;
  `tameCountRequirementForNPCType` = {2, 4, 4, 2, 8, 10, 4, 4} closes the
  E117 feed gate; `preserveItemDataAInCraftedItem` = the bit-mask set
  (0x9a85 over 0x73..0x82, 0xbb..0xc6, 0x1fe01 over 0x116..0x126) closing the
  E75/E78 slices' referenced helper.
- **The seed maps**: tree seeds {0x15, 0x16, 0x17, 0x18, 0x1b, 0x2e, 0x3c,
  0x4d, 0x4e, 0xa0} -> TreeType 1..10; plant seeds {0x36, 0x3d, 0x3e, 0x47,
  0x70, 0x90, 0x127, 0x128, 0x129, 0x136, 0x13c} -> PlantType 1..10;
  `itemTypeIsSowable` is the 21-item union; `contentsTypeForPlantType` maps
  PlantType 1..10 onto the foreground contents family (0x43..0x7c, the
  flowering pairs 0x43/0x44, 0x47/0x48, 0x49/0x4a, 0x4f/0x50).
- **Item-type tables pinned**: solid (47 values), hangable (the 86-value
  wall-mount set), block = solid minus {0x34, 0x45, 0xa4, 0xa5} plus its
  31-value list, column / stairs (27 each), torch (17), stackability with the
  colour-gene rule, the fill-item range rule (0x400..0x451 true, 0x158..0x400
  false) and the colour/painting/train-car/two-wide sets.
- **Growth + geometry**: `baseGrowthRateForTreeType` = {2, 5, 2, 1, 2, 5,
  0.35, 0.2, 2, 0.1} (default 1); the `growthVigor*AtPos` pair = the
  seasonal position-dependent vigor model (census); `closestPointOnLineToPoint`
  = the clamped segment projection; `polarToRectangular`, `linearInterpolatev`,
  the componentwise `Vector::operator*`, `quickSort` -> q_sort and
  `GLKMathUnproject` (the GLKit port) close the math set.

## Boundaries

- The 0x5deeb8 / 0x5dec98 item helpers behind `itemTypeIsWorkbench` /
  `itemTypeIsInteractionObject` stay at the call-site level (not named here).
- Fourteen bodies are census-grade: the quad packers (~16 KB of vertex
  packing), growthVigor x2, classForDynamicObjectType (the 66-entry table),
  tileIsPaintable, paintedIndexForImageIndex, particleColorForTile,
  itemTypeFromTileIsForegorund, torchConnectionTypeForPos, testTile and
  GLKMathUnproject - their full case data lives in the listings.
