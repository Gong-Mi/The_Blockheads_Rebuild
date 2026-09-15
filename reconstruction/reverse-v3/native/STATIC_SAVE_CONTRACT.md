# Static save/world contract recovered from 1.7.6

Evidence source: original `lib/armeabi-v7a/libApplication.so` from the APK pinned
in `../apk/ORIGINAL_APK.md`. Addresses below are virtual addresses in that ELF.
All claims in the A sections are direct Objective-C metadata, selector, CFString,
or ARM instruction evidence. They are not inferred from the replacement code.

## Evidence products

The binary is stripped but retains Objective-C 2 metadata. The checked-in tools
recover 10,478 file-backed Objective-C methods and bind selected method bodies
to exact ARM unwind ranges:

- `libApplication_objc_methods.tsv`: complete method/IMP/type map;
- `refs_world_lifecycle.tsv`: selectors and CFStrings used by world load/save;
- `refs_persistence.tsv`: dynamic-world and migration references;
- `refs_tile_storage.tsv`: physical/light block storage references;
- `disasm_world_lifecycle.txt`: exact ARM bodies for five lifecycle methods;
- `disasm_persistence.txt`: exact ARM bodies for seven persistence methods;
- `disasm_tile_storage.txt`: exact ARM bodies for five tile-storage methods.

The disassembly files use the next `.ARM.exidx` function address as the end
boundary. They therefore do not guess method sizes from selector order.

## A: application-support save root and database layout

`World -[initializeDatabases]` at `0x0055b698` directly references:

```text
%@/saves/%@/world_db/
main
blocks
dw
initWithPath:maxDatabases:maxMapSizeInMB:
initWithEnvironment:name:
```

Its ARM body calls `NSSearchPathForDirectoriesInDomains` with directory value
`0x0e`, domain value `1`, and expansion enabled, then constructs the save path.
It passes constants `4` and `0x40` to the database-environment initializer.
The observed database contract is therefore:

```text
Application Support
└── saves/<saveID>/world_db/
    ├── main
    ├── blocks
    └── dw

database environment: maxDatabases=4, maxMapSizeInMB=64
```

The names are logical database names managed by the bundled `Database` /
`DatabaseEnvironment` classes; this evidence does not imply that each name is a
single ordinary filesystem file.

## A: world lifecycle method chain

The original native chain and implementation addresses are:

```text
World saveAll                 0x00555a84
World loadGame                0x00557c40
World loadDefaultGame         0x0055b2e8
World initializeDatabases     0x0055b698
World incrementalLoad         0x0055bac8
```

`loadGame` directly references both the legacy archive and v2 path:

```text
%@/saves/%@/world
%@/saves/%@/worldv2
```

It uses these selectors in the same method body:

```text
dataWithContentsOfFile:
unarchiveObjectWithData:
unarchiveObjectWithFile:
removeItemAtPath:error:
```

This proves a legacy archive migration/load path exists. It does not prove that
`worldv2` remains the primary post-migration store in every mode.

`incrementalLoad` directly invokes or constructs:

```text
initializeDatabases
WorldTileLoader initWithWorld:randomSeed:isNewWorld:saveID:loadedVersion:blockDatabase:
DynamicWorld initWithWorld:worldTileLoader:clientTileLoader:server:client:
  serverClients:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:
  appDatabase:worldDatabase:dynamicObjectDatabase:
DatabaseConvertor initWithWorld:worldDatabase:dynamicObjectDatabase:
  blockDatabase:lightBlockDatabase:serverDatabase:
```

The replacement must preserve this ordering as separate world metadata, tile
storage, dynamic-object storage, migration, and renderer reconstruction stages.
A single `world.bin` read followed by immediate rendering is not this lifecycle.

## A: world-v2 metadata keys

`DynamicWorld -[saveGameWithWorldData:signOwnershipData:]` at `0x008b29bc`
directly references these metadata keys:

```text
dynamicWorldv2
dynamicObjectIDCount
activeBlockheadIndex
workbenchHasBeenCrafted
poleItemTakenTimes
saveVersion
savedGlowIndices
portalPositionIndexSet
signOwnershipData
```

It constructs the database key:

```text
<saveID>_worldv2
```

The method uses `NSKeyedArchiver`-style encoding and property-list serialization,
then calls `setData:forKey:`. In the same save transaction it calls:

```text
saveBlockheadInventory:
saveBlockheads
saveDynamicObjects
savePhysicalBlockForMacroTile:sendReliably:dontSend:onlySaveIfClientsNeedIt:
commitSaveIfNeeded
saveIfNeeded
```

This is direct evidence that world metadata, inventories, blockheads, dynamic
objects, and dirty physical blocks are distinct records coordinated by one save
operation.

## A: blockhead records

`DynamicWorld -[saveBlockheads]` at `0x008b6f0c` uses:

```text
blockheads
<saveID>_blockheads
local_blockheads
dynamicObjects
uniqueID
gzipDeflate
setData:forKey:
```

`DynamicWorld -[saveBlockheadInventory:]` at `0x008b8634` uses:

```text
blockhead_<uniqueID>_inventory
<saveID>_blockhead_<uniqueID>_inventory
saveItemSlotsArray
dataWithPropertyList:format:options:error:
gzipDeflate
setData:forKey:
```

The inventory and blockhead collections are therefore independently keyed,
property-list-derived, gzip-compressed records rather than fields embedded only
inside one monolithic world file.

## A: physical block storage

The relevant method/type metadata is:

```text
World -[savePhysicalBlockForMacroTile:sendReliably:dontSend:onlySaveIfClientsNeedIt:]
WorldTileLoader -[savePhysicalBlock:macroTile:sendToClients:server:sendReliably:]
WorldTileLoader -[loadPhysicalBlock:atXPos:yPos:createIfNotCreated:]
ClientTileLoader -[loadPhysicalBlock:atPos:withTilesData:lightData:extraDataDict:]
```

The Objective-C type encoding exposes:

```text
PhysicalBlock = ii^{Tile}cCdII[32*][32C]
Tile = CCCCCCCCCCCCCSSSsCISSSSSQ[8S]
```

The server save method directly uses:

```text
dataWithBytes:length:
appendData:
gzipDeflate
setData:forKey:
```

The load method directly uses:

```text
%d_%d_compressedBlock
dataForKey:
gzipInflate
dataWithContentsOfFile:
getBytes:range:
```

This proves the current database-backed format retains a legacy
`<x>_<y>_compressedBlock` fallback/migration path and stores compressed binary
physical-block data.

Instruction-level mapping of `WorldTileLoader
-[savePhysicalBlock:macroTile:sendToClients:server:sendReliably:]` proves the
base gzip input is built in this exact order:

```text
offset 0       65536 bytes  PhysicalBlock.tiles: 1024 contiguous Tiles
offset 65536       1 byte   PhysicalBlock byte offset 13
offset 65537       4 bytes  PhysicalBlock bytes at offset 24 (little endian)
total          65541 bytes
```

The first `dataWithBytes:length:` receives `PhysicalBlock+8` (the `Tile*`) and
`0x10000`. The next two appends receive `PhysicalBlock+0x0d`/length 1 and
`PhysicalBlock+0x18`/length 4, after which `gzipDeflate` is called. Because a
physical block is 32×32, each serialized original Tile is exactly 64 bytes.

Static predicates additionally prove these Tile offsets:

```text
byte 0       TileType (`tileIsAir`, `tileIsWater`, `tileIsSolid`)
byte 1       back-wall type (`backWallIsMutable`)
byte 3       contents type (`tileIsTree`, `tileRequiresGlowBlock`)
byte 7       temperature scale byte (`currentTemperatureForTileAtWorldPos`)
bytes 20-21 signed temperature offset (`currentTemperatureForTileAtWorldPos`)
```

`app/src/main/cpp/original_save_format.*` implements an exact-size gzip
decoder for this recovered 65,541-byte record while retaining unproven fields
under offset-based names. The host test rejects any inflated size mismatch.
The current runtime `Tile` remains a prototype model and is intentionally not
cast onto this original structure.

## A: migration from directory records into databases

`DatabaseConvertor -[convertWorld]` at `0x00aa51b8` walks directory entries and
uses these directly referenced names:

```text
playerLightBlocks
path
key
_info
21
17
dynamicObjects
lightDict
contributionGridData
addedToTiles
trainchest
compressedBlock
physicalBlock
```

It uses:

```text
contentsOfDirectoryAtPath:error:
componentsSeparatedByString:
safeDataWithContentsOfFile:
gzipDeflate
setData:forKey:
hasKey:
removeObjectForKey:
```

`DatabaseConvertor -[convertLightBlocks]` additionally maps:

```text
archive
index
remove
playerID
<id>_archiveData
<id>_archiveKeys
```

into database records. `removeWorldFiles` deletes old files only after the
conversion worklists have been processed.

## Compatibility consequence

The replacement persistence contract must be split at least into:

```text
world metadata
physical blocks
light blocks
dynamic objects
blockhead collection
per-blockhead inventory
server/player records
migration state
```

The current `world.bin` implementation remains a prototype-only format until it
can import/export the recovered records above. Build success or successful
relaunch of `world.bin` is not original-format acceptance.

## Remaining static work

The next static pass must map:

1. semantic names for the remaining original Tile fields;
2. database key formula for each physical/light macro block;
3. property-list format constant and gzip framing for blockhead inventories;
4. dirty-block selection and transaction boundaries in `saveAll`;
5. load ordering and version branches inside `incrementalLoad`;
6. renderer method/texture/shader bindings using the same IMP/reference method.
