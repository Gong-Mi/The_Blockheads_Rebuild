# Electricity net-sync pair + wire forwarding + WirePathCreator lifecycle

The network boundary of the electricity domain: how an electricity particle
path travels between a server and its clients, how wire objects are addressed
by position, and how the `WirePathCreator` search engine allocates its
512-slot property array. 8 bodies, **1912 verified words** total, recovered
from the pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_power_sync.py`; JSON: `power_sync.json`).

## Bodies

1. **World `sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:`**
   (`0x005ca058` .. `0x005ca9c4`, 603 words). Gate 1: `World.client@960 == nil
   && World.server@964 == nil` -> return (standalone session, no net). Gate 2:
   `(paths.end - paths.begin)/8 <= 2` -> return (needs more than 2 path
   entries). The 8-byte header at `[sp,0xd0]` carries `strh (int)size`
   (`vcvt.s32.f32`) and `strh (end-begin)>>3` = path count; the packed
   `{x,y}*count` blob (`__wrap_malloc(count<<3)`, 8-byte pair copy loop
   `0x5ca674`..`0x5ca788`) is passed through `dataWithBytes:length:` /
   `appendBytes:length:` (8) / `appendData:` and compressed with
   **`gzipDeflate`**. Recipients: the `World.serverClients@956` dictionary is
   enumerated (`countByEnumeratingWithState:` guard), per-client state via
   `connected`/`isEqualToString:`, per-path macro screening via
   `blockIsWired:` / `macroIndexAtWorldIndex` + `addObject:`. Server route
   ends in **`sendNetworkData:toPeers:reliable:`**, client route in
   **`sendDataToServer:reliable:`** (two final call sites keyed on the field
   compare at `0x5ca880`). Blob freed via `__wrap_free` (`0x5ca954`).

2. **World `electricityPathDataRecieved:fromClient:`** (`0x005ca9c4` ..
   `0x005caef8`, 333 words). `length == 8` -> return (header-only message).
   Else `gzipInflate` -> `subdataWithRange:` -> `UInt16` count read from the
   buffer (`ldrh`; `lsl <<3`), `__wrap_malloc(count<<3)`, `getBytes:length:`;
   a local `vector<ElectrictyParticlePathIndex>` is built by `push_back`
   (slow path `bl 0x5db5b4`; `~vector` helper `0x5cb054`) of each 8-byte pair (loop `0x5cabc8`..
   `0x5cad2c`); then **`[[ParticleEmitter instance]
   doAddElectricityParticleWithPath:(vector copy) size:(float)uint16]`**
   spawns the visual; when `World.server@964 != nil` the same vector + size is
   forwarded via `[self
   sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:]` using
   `fromClient` as the ignore tag (loop prevention). Three `~vector` unwind
   paths (`0x5cadac`..`0x5caea8`) + `_Unwind_Resume` (`0x5caeb8`).

3. **DynamicWorld `initialDynamicObjectsNetDataForMacroTileIndex:wireForClient:`**
   (`0x008b5300` .. `0x008b5e54`, 725 words). Early gates: World refs nil /
   `serverClients@24` count `<= 0` -> return nil.
   `loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:`
   on `world@4`; macro x/y derived via `__modsi3` / `__aeabi_idiv`
   (`worldWidthMacro`) then `<<5` world coords -> `tileAtWorldPositionLoaded`.
   Per dynamic object: `isKindOfClass:` with `OBJC_CLASS_$_Blockhead` screens
   blockheads out; wires flow through **`wireDynamicObject:`** (variant chosen
   by `wireForClient`) into an `NSMutableArray` (`array`/`addObject:`);
   per-object net identity from `objectType`/`uniqueID`
   (`numberWithUnsignedInt:`) and payloads **`creationNetDataForClient:`** /
   **`updateNetDataForClient:`**; a `macroTiles` dictionary record is
   maintained (`dictionary`/`setObject:forKey:`); final wrap returns the
   assembled net data or nil (`0x8b5d84`..).

4. **DynamicWorld `addWireAtPos:ofType:saveDict:placedByClient:`**
   (`0x008eb9c0` .. `0x008eba64`, 41 words). Thin forwarder:
   `[self addStandardObjectAtPos:pos objectType:0x26 itemType:type
   saveDict:saveDict placedByClient:placedByClient]` - the constant **`0x26`**
   is the wire dynamic-object type tag (`mov r1, 0x26; str r1, [r5]`);
   position struct `{x,y}` and remaining args re-staged at `[sp,4..0xc]`.

5. **DynamicWorld `wireAtPos:`** (`0x008eba64` .. `0x008ebad4`, 28 words).
   Thin forward read: `[self objectOfType:0x26 atPos:pos]` - wire tag `0x26`
   again; returns the wire dynamic object at that position (nil if none).

6. **DynamicWorld `removeWireAtPos:`** (`0x008ebad4` .. `0x008ebb88`, 45
   words). Removal pair: `wire = [self wireAtPos:pos]`; when non-nil ->
   `[self removeStandardObject:wire]` (`objc_msgSend` trampoline `blx`);
   `0x26` wire tag reused through `wireAtPos:`.

7. **WirePathCreator `initWithWorld:`** (`0x00db1e90` .. `0x00db1f84`, 61
   words). `objc_msgSendSuper2(super, init)` -> nil guard; `self.world@4 =
   world`; `self.derivedTilePropertiesArray@20 = __wrap_malloc(0x1800)` =
   6144 bytes = **512 x 12-byte** property slots (matches the `0x1ff`=511 full
   check in `tileDerivedPropertiesAtWorldIndex:`); return self.

8. **WirePathCreator `dealloc`** (`0x00db1f84` .. `0x00db20b4`, 76 words).
   Teardown: `__wrap_free(derivedTilePropertiesArray@20)`;
   `release(openList@8)`; `release(closedList@12)`;
   `objc_msgSendSuper2(dealloc)`. `derivedTileIndices@28` map is empty at
   dealloc time (find engine clears it on entry).

## Anchors

- Dispatch table: 46 selector cells, 7 import cells (8 distinct routines:
  `objc_msgSend`, `objc_msgSendSuper2`, `__wrap_malloc`, `__wrap_free`,
  `memset`, `__modsi3`, `__aeabi_idiv`, `objc_enumerationMutation`), 11 ivar
  descriptor cells
  (`World.client`@960 / `World.server`@964 / `World.serverClients`@956,
  `DynamicWorld.world`@4 / `serverClients`@24, `WirePathCreator.world`@4 /
  `openList`@8 / `closedList`@12 / `derivedTilePropertiesArray`@20), 4 class
  cells (`ParticleEmitter`, `Blockhead`, `WirePathCreator` x2).
- All 96 call sites pinned (24/19/43/1/1/2/2/4), all 67 branches pinned.
- Key cells: `gzipDeflate`/`appendBytes:length:`/`sendNetworkData:toPeers:
  reliable:`/`sendDataToServer:reliable:` (send); `doAddElectricityParticle
  WithPath:size:` (`0xe7e78c`) + forwarding SEL (`0xe7e790`) (recv);
  `addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:`
  (`0xe83118`) + `objectOfType:atPos:` (`0xe830e4`) + `removeStandardObject:`
  (`0xe830f4`) (forwards); `init` (`0xe88f0c`) + `dealloc` (`0xe88f14`) +
  `release` (`0xe88f10`) (lifecycle).
- The `0x26` wire tag pairs with the E1 wire configuration flow: the same tag
  family used by `Wire`/`addWireAtPos:` in the electricity core batch.

## Boundaries

- All 8 bodies are ARM.exidx-bounded (own-bound ends: send `0x005ca9c4` ==
  recv IMP; recv `0x005caef8` == vector dtor region; dw_initial `0x008b5e54`;
  addwire/wireatpos/removewire consecutive IMPs `0x008eba64` / `0x008ebad4` /
  `0x008ebb88`; wpc init `0x00db1f84`; wpc dealloc `0x00db20b4`).
- The transport consumers of `sendNetworkData:toPeers:reliable:` /
  `sendDataToServer:reliable:` and the `ParticleEmitter` renderer consuming
  `doAddElectricityParticleWithPath:size:` are out of scope.
