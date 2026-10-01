# Live runtime ivar offsets extracted from official Android process

Extracted directly from live process memory (`/proc/<pid>/mem`) of `com.noodlecake.blockheads` (1.7.6 armeabi-v7a running on HyperOS translator).

## Background and Methodology

Objective-C ivar offsets for classes with complex inheritance (e.g., `Blockhead -> DynamicObject -> NSObject`) are resolved dynamically at load/runtime by the Objective-C runtime and stored in the global `.data` section under symbols named `OBJC_IVAR_$_<Class>.<ivar>`.

In this build:
- Static ELF symbols define the relative offsets in `.data`.
- At process start, the dynamic linker relocates the global data segment (`rw-p` mapping of `libApplication.so`).
- By reading `/proc/<pid>/mem` at the live relocated address `base_rw + (sym_addr - 0xe32000)`, we extract the exact integer offsets used by the running game without guessing or disassembly heuristics.

## Scope of Extracted Ivars

A total of **527 live ivar offsets** were extracted across four core classes:

| Class | Live Ivar Count | Key Structural Roles |
|---|---:|---|
| `Blockhead` | 221 | Bones, shaders, matrices, animation states, tools, inventory |
| `DynamicObject` | 13 | Position, float position, cache, net flag, dynamic unique ID |
| `World` | 227 | Database environments, random seed, time of day, camera bounds |
| `DynamicWorld` | 66 | Blockhead array, dynamic object index, world pointer, save path |

## Critical Field Offsets (Pinned)

### Blockhead (Character Bones & Animation)
- `Blockhead.skinOptions` = 200
- `Blockhead.headCube` = 712, `headTexture` = 452, `headHairTexture` = 440
- `Blockhead.hairCubeA` = 1968, `hairCubeB` = 1964
- `Blockhead.bodyCube` = 516, `bodyTexture` = 524
- `Blockhead.armCube` = 540, `armTexture` = 532
- `Blockhead.legCube` = 496, `legTexture` = 644
- `Blockhead.state` = 728
- `Blockhead.toSquare` = 2012
- `Blockhead.traverseToKeyFrame` = 2384
- `Blockhead.walkTimer` = 2365
- `Blockhead.isInJetPackFreeFlightMode` = 2156

### DynamicWorld (Entity Container & World Bridge)
- `DynamicWorld.world` = 9496
- `DynamicWorld.blockheads` = 7370
- `DynamicWorld.dynamicObjects` = 2432
- `DynamicWorld.worldDatabase` = 7892
- `DynamicWorld.worldSaveDirectory` = 6084

### World (World Clock & Persistence)
- `World.worldWidthMacro` = 240
- `World.databaseEnvironment` = 572
- `World.mainDatabase` = 552
- `World.blockDatabase` = 576
- `World.dynamicObjectDatabase` = 604
- `World.timeOfDayFraction` = 3036
- `World.randomSeed` = 3380
- `World.saveID` = 3460

## Artifacts and Verification

- JSON data: `reconstruction/reverse-v3/native/live_runtime_ivar_offsets.json`
- Contract test: `tools/test_live_runtime_ivars.py` (verifies all 527 counts and pinned offsets without requiring live process access).
