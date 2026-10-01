# Blockhead clothing and accessory mesh pipeline (R52)

Recovered from `Blockhead -[updateClothingCubes]` (0x00b8cc0c..0x00b8fccc, 3,120 instruction words).

## Overview

`Blockhead -updateClothingCubes` is called whenever a blockhead equips or unequips wearables (headwear, shirts, pants, shoes, or jetpacks) or on full skin/geometry refresh from `updateSkin` (0x00b8fccc).

The method checks the current equipped item type for each wearable slot against the cached equipped type, releases stale `DrawCube` objects, loads required textures via `[cache textureNamed:]`, and instantiates the composite 3D clothing cubes.

## Clothing Slots and Geometric Components

| Slot | ItemType Ivar | Texture Ivar | Primary Mesh Ivar | Auxiliary Meshes |
|---|---|---|---|---|
| **Headwear** | `hatItemType` (312) | `hatTexture` (248) | `hatCube` (252) | `hatRimCube` (256), `hatPomPomCubes` (260) |
| **Shirt** | `shirtItemType` (314) | `shirtBodyTexture` (296)<br>`shirtArmTexture` (304) | `shirtBodyCube` (300) | `shirtArmCube` (308) |
| **Pants** | `pantsItemType` (316) | `pantsTexture` (288) | `pantsCube` (292) | - |
| **Shoes** | `shoesItemType` (318) | `shoesTexture` (276) | `shoesCube` (280) | `shoesToeCube` (284) |
| **Jetpack** | (mode-dependent) | `jetTextures` (408) | `jetpackCubes` (392) | Animation frames `jet1.png`, `jet2.png`, `jet3.png` |

## Construction Flow

1. **Stale Geometry Teardown**:
   - For each slot, if `currentItemType != slotItemType`, sends `release` to the existing cube(s) and texture object(s).
2. **Texture Binding**:
   - Queries `[cache textureNamed:]` (via `DynamicObject.cache` at offset 32).
   - Jetpack frames load `jet1.png`, `jet2.png`, `jet3.png` into `jetTextures`.
3. **Parametric Mesh Allocation**:
   - Invokes `[DrawCube alloc]` followed by `initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:` or the UV-mapped variant `initWithWidth:...:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:`.
   - The auxiliary meshes (`hatRimCube` for brim, `hatPomPomCubes` for beanie pom-pom, `shoesToeCube` for shoes front) are instantiated conditionally based on `hatItemType` and `shoesItemType`.
