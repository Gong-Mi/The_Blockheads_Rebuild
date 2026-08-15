# Static baseline: original 1.7.6 native APK

Source APK SHA-256:

```text
cae0371354dfda125793ba974c1f7a55b2161ed6d9c458f962da9eb468f8ec54
```

## Native layout

The APK contains 24 ARMv7 native libraries. The primary application library is:

```text
lib/armeabi-v7a/libApplication.so
ELF32 ARM EABI5
size: 17,174,960 bytes
```

`libApplication.so` has 27 dynamic dependencies, including the Apportable-style
Foundation/CoreFoundation/CoreGraphics/GL compatibility layer and the game's
own `libNoodleFoundation.so` and `libNoodleCompatibility.so`.

This is not a small Android-native game library. The Android package carries a
ported Objective-C++ application runtime with native Objective-C metadata.

## Native metadata inventory

Generated from the original `libApplication.so`:

```text
Objective-C classes: 646
Objective-C ivars:   3796
C++ symbols:         393
```

Artifacts:

```text
native/libApplication_inventory.json
native/libApplication_symbols.txt
native/libApplication_sections.txt
native/libApplication_target_strings.txt
native/symbols_world_save_renderer.txt
```

Relevant named classes/objects observed in the binary include:

```text
World
DynamicWorld
WorldTileLoader
ClientTileLoader
WorldUI
WorldDatabase / database conversion objects
Blockhead
BlockheadAI
BlockheadUI
MainMenuUI
LoadWorldUI
CreateWorldUI
CPTexture2D
Shader
```

Relevant renderer metadata includes:

```text
BlockheadBody
BlockheadFace
BlockheadHair
BlockheadClothing
Block.vsh / Block.fsh
BlockTransparent.vsh / BlockTransparent.fsh
BlackTile.vsh / BlackTile.fsh
ColoredNPC.vsh / ColoredNPC.fsh
DrawCube.vsh / DrawCube.fsh
```

## Save-path evidence

The original binary contains exact save-path format strings:

```text
%@/saves/
%@/saves/%@/
%@/saves/%@/world
%@/saves/%@/worldv2
%@/saves/%@/world_db/
%@/saves/%@/server_db/
%@/saves/%@/blocks/
%@/saves/%@/lightBlocks/
%@/saves/%@/map/%@/
%@/saves/%@/map/%@/%d_%d.png
%@/saves/%@/players/
%@/saves/%@/players/%@/%@/%@/
%@/saves/%@/allPlayers.plist
%@/saves/%@/recentPlayers.plist
%@/saves/%@/adminlist.txt
%@/saves/%@/blacklist.txt
%@/saves/%@/whitelist.txt
%@/saves/%@/modlist.txt
%@/saves/%@/worldPrices
%@/saves/%@/portalChestTransaction
```

This directly contradicts treating the replacement's single `world.bin` as an
original save-format implementation. The v2 file may remain a prototype format,
but it is not evidence of 1.7.6 compatibility.

## Entity evidence

The binary contains both:

```text
DropBear
GrizRat resource family
```

and separate native/resource evidence for many other entities, including Dodo,
CaveTroll, donkey, fish, and train-related objects. The presence of a grizrat
sprite family does not by itself establish that it is the DropBear sprite family.
That mapping remains unresolved until native call/data references or controlled
original-App observations establish it.

## Immediate reverse-v3 consequence

The first implementation target is not a new procedural world generator. It is
recovering the original world/save lifecycle:

1. identify the save root and world directory selected by the Android port;
2. obtain an original save directory after one controlled world creation;
3. compare `world`, `worldv2`, `world_db`, `blocks`, `lightBlocks`, and `map` before
   and after one block action;
4. map the native `World`, `DynamicWorld`, and tile-loader functions to those files;
5. only then define a replacement save/world contract.
