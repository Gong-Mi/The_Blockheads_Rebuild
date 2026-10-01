# Live runtime ivar offsets extracted from official Android process

Extracted directly from live process memory (`/proc/<pid>/mem`) of `com.noodlecake.blockheads` (1.7.6 armeabi-v7a running on HyperOS translator).

## Background and Methodology

Objective-C ivar offsets for classes with complex inheritance (e.g., `Blockhead -> DynamicObject -> NSObject`) are resolved dynamically at load/runtime by the Objective-C runtime and stored in the global `.data` section under symbols named `OBJC_IVAR_$_<Class>.<ivar>`.

In this build:
- Static ELF symbols define the relative offsets in `.data`.
- At process start, the dynamic linker relocates the global data segment (`rw-p` mapping of `libApplication.so`).
- By reading `/proc/<pid>/mem` at the live relocated address `base_rw + (sym_addr - 0xe32000)`, we read the 4-byte storage cell the runtime leaves there.

**Status of these numbers (corrected): candidate, not verified.** A later measurement
(`IVAR_OFFSET_READING.md`) compared the same 3793 cells read from the ELF file against the
running process and found **3735 of them differ** (98.5%). The numbers in this file are the
process-content reading, which is *one of two* mutually exclusive candidate readings, and no
test has yet separated them: the value-based probes attempted so far were either
state-dependent (a net-controlled blockhead skips the write) or relied on instance discovery
by 4-byte class-pointer search, which returns metadata references rather than object headers.
Do not present these offsets as the verified runtime layout; use them as candidates until the
object-graph walk in `IVAR_OFFSET_READING.md` validates a chain end to end.

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
