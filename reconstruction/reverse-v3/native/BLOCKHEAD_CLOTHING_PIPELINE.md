# Blockhead clothing and accessory mesh pipeline (R52)

Recovered from `Blockhead -[updateClothingCubes]` (0x00b8cc0c..0x00b8fccc, 3,120 instruction words).

## Overview

`Blockhead -updateClothingCubes` is called whenever a blockhead equips or unequips wearables (headwear, shirts, pants, shoes, or jetpacks) or on full skin/geometry refresh from `updateSkin` (0x00b8fccc).

The method checks the current equipped item type for each wearable slot against the cached equipped type, releases stale `DrawCube` objects, loads required textures via `[cache textureNamed:]`, and instantiates the composite 3D clothing cubes.

## Clothing Slots and Geometric Components

**Provenance warning**: the numbers in parentheses below are the values the annotated listing
prints for each `OBJC_IVAR_$_Blockhead.*` storage cell. Those are **file-content** readings,
and 98.5% of ivar cells differ between the file and the running process
(`IVAR_OFFSET_READING.md`), so these numbers identify *which* ivar a method touches but must
not be used as runtime field offsets. The measurement that would promote them is an
object-graph walk, which has not been run yet.

| Slot | ItemType Ivar | Texture Ivar | Primary Mesh Ivar | Auxiliary Meshes |
|---|---|---|---|---|
| **Headwear** | `hatItemType` | `hatTexture` | `hatCube` | `hatRimCube`, `hatPomPomCubes` |
| **Shirt** | `shirtItemType` | `shirtBodyTexture`, `shirtArmTexture` | `shirtBodyCube` | `shirtArmCube` |
| **Pants** | `pantsItemType` | `pantsTexture` | `pantsCube` | - |
| **Shoes** | `shoesItemType` | `shoesTexture` | `shoesCube` | `shoesToeCube` |
| **Jetpack** | (mode-dependent) | `jetTextures` | `jetpackCubes` | Animation frames `jet1.png`, `jet2.png`, `jet3.png` |

## Construction Flow

1. **Stale Geometry Teardown**:
   - For each slot, if `currentItemType != slotItemType`, sends `release` to the existing cube(s) and texture object(s).
2. **Texture Binding**:
   - Queries `[cache textureNamed:]` (via `DynamicObject.cache` at offset 32).
   - Jetpack frames load `jet1.png`, `jet2.png`, `jet3.png` into `jetTextures`.
3. **Parametric Mesh Allocation**:
   - Invokes `[DrawCube alloc]` followed by `initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:` or the UV-mapped variant `initWithWidth:...:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:`.
   - The auxiliary meshes (`hatRimCube` for brim, `hatPomPomCubes` for beanie pom-pom, `shoesToeCube` for shoes front) are instantiated conditionally based on `hatItemType` and `shoesItemType`.
