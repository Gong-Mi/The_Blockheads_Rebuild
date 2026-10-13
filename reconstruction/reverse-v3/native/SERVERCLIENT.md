# ServerClient (E150)

The ServerClient state container lands: the five send queues, the heartbeat tracking and the per-client light database. 42 bodies, 4913 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| svc_00 | ServerClient -[.cxx_construct] | 0x00d0bc64 | 27 | 0 | 0 | 1 | 0 | 1 | 0 |
| svc_01 | ServerClient -[.cxx_destruct] | 0x00d0bbec | 30 | 0 | 0 | 1 | 0 | 2 | 0 |
| svc_02 | ServerClient -[addCreationDataUpdateObjectDataToSend:ofType:] | 0x00d090f8 | 65 | 3 | 1 | 1 | 1 | 3 | 0 |
| svc_03 | ServerClient -[addCreationObjectDataToSend:ofType:objectID:] | 0x00d08c8c | 283 | 9 | 1 | 2 | 2 | 14 | 8 |
| svc_04 | ServerClient -[addFillRequest:] | 0x00d0af10 | 48 | 2 | 1 | 1 | 1 | 2 | 0 |
| svc_05 | ServerClient -[addRemovalObjectDataToSend:ofType:objectID:] | 0x00d093e4 | 695 | 9 | 1 | 4 | 2 | 36 | 24 |
| svc_06 | ServerClient -[addUpdateObjectDataToSend:ofType:reliable:] | 0x00d091fc | 122 | 3 | 1 | 2 | 1 | 6 | 2 |
| svc_07 | ServerClient -[allLightBlockIndices] | 0x00d0bba8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_08 | ServerClient -[blockIsRequested:] | 0x00d08944 | 28 | 0 | 0 | 1 | 0 | 1 | 0 |
| svc_09 | ServerClient -[blockIsWired:] | 0x00d088d4 | 28 | 1 | 1 | 1 | 0 | 1 | 0 |
| svc_10 | ServerClient -[blockRemoved:] | 0x00d08ad8 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| svc_11 | ServerClient -[clientID] | 0x00d0b804 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_12 | ServerClient -[clientReconnected] | 0x00d07870 | 443 | 8 | 2 | 13 | 2 | 27 | 2 |
| svc_13 | ServerClient -[connected] | 0x00d0b704 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_14 | ServerClient -[createIfNotCreatedForBlockRequest:] | 0x00d08a68 | 28 | 0 | 0 | 1 | 0 | 1 | 0 |
| svc_15 | ServerClient -[dealloc] | 0x00d07f5c | 252 | 2 | 2 | 12 | 1 | 17 | 5 |
| svc_16 | ServerClient -[dynamicObjectIsWired:] | 0x00d08b44 | 28 | 1 | 1 | 1 | 0 | 1 | 0 |
| svc_17 | ServerClient -[foundItemsList] | 0x00d0bb64 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_18 | ServerClient -[getAndRemoveAllRecieptDataForMacroPos:world:] | 0x00d0afd0 | 251 | 7 | 1 | 1 | 1 | 15 | 10 |
| svc_19 | ServerClient -[hasEverRequestedHeartbeat] | 0x00d0b98c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_20 | ServerClient -[initWithClientID:server:lightBlockIndex:lightBlockDatabase:] | 0x00d06a80 | 892 | 17 | 5 | 18 | 7 | 57 | 6 |
| svc_21 | ServerClient -[isAdmin] | 0x00d0b848 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_22 | ServerClient -[lightBlockIndex] | 0x00d0baa0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_23 | ServerClient -[paused] | 0x00d0b784 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_24 | ServerClient -[removeBlockRequest:] | 0x00d089b4 | 45 | 1 | 1 | 2 | 0 | 2 | 0 |
| svc_25 | ServerClient -[requestForBlock:] | 0x00d083ac | 90 | 1 | 1 | 3 | 0 | 4 | 1 |
| svc_26 | ServerClient -[requestedBlockIndices] | 0x00d0b740 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_27 | ServerClient -[requestsHeartBeat] | 0x00d0b90c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_28 | ServerClient -[saveLightBlockIndices] | 0x00d0b3bc | 166 | 8 | 3 | 3 | 3 | 8 | 0 |
| svc_29 | ServerClient -[sendAllObjectData] | 0x00d09ec0 | 953 | 10 | 1 | 8 | 3 | 55 | 10 |
| svc_30 | ServerClient -[setConnected:] | 0x00d0b654 | 44 | 1 | 1 | 1 | 0 | 1 | 1 |
| svc_31 | ServerClient -[setHasEverRequestedHeartbeat:] | 0x00d0b9c8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_32 | ServerClient -[setIsAdmin:] | 0x00d0b884 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_33 | ServerClient -[setPaused:] | 0x00d0b7c0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_34 | ServerClient -[setRequestsHeartBeat:] | 0x00d0b948 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_35 | ServerClient -[setTimeSinceLastHeartbeatRequest:] | 0x00d0ba54 | 19 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_36 | ServerClient -[setWorldIndicesContainingTamedAnimals:] | 0x00d0bb20 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_37 | ServerClient -[timeSinceLastHeartbeatRequest] | 0x00d0ba0c | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_38 | ServerClient -[unwireDynamicObject:] | 0x00d08c20 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| svc_39 | ServerClient -[wireDynamicObject:] | 0x00d08bb4 | 27 | 1 | 1 | 1 | 0 | 1 | 0 |
| svc_40 | ServerClient -[wiredDynamicObjects] | 0x00d0b8c8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| svc_41 | ServerClient -[worldIndicesContainingTamedAnimals] | 0x00d0badc | 17 | 0 | 0 | 1 | 0 | 0 | 0 |

## Findings (E150)

- **The ServerClient batch lands**: 42 bodies / 4913 words / 69 in-body branch rows / 257 call rows / 18 routes of `ServerClient` (**root class**, super = none, `instance_size` 92; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). The tsv holds exactly 42 instance methods for this class, so the batch is the **complete class**. Roster names svc_00..svc_41 (targets ordered by selector name, not address), 0 name collisions. Mechanical layer regenerated this run: `gen_listings.py` ("bodies 42 words 4913", entrypoint warnings only) + `build_specs.py` (42 bodies, 257 call rows, 18 routes). Listing rows == roster word count for every body (verified programmatically: 0 mismatches). Grades: **0 census bodies**; 4 [census-lite]: svc_29 (953w), svc_20 (892w), svc_05 (695w), svc_12 (443w); the remaining 38 are <=283w and were fully read. 10 bodies are TRIMMED at the next IMP (svc_01, svc_08, svc_17, svc_24, svc_31, svc_32, svc_33, svc_36, svc_37, svc_41 -- see Boundaries).

- **What the class is**: the host-side per-client state container that World/BHServer holds per connected player (BHServer E133: `[self.world serverClients]`). It carries identity (`clientID@4` NSString, `server@8` BHServer), the block-stream request queue (`requestedBlockIndices@12` NSMutableIndexSet + `requestedBlockRequestTypes@16` std::map<uint,uchar>), interest sets (`wiredBlocks@28`, `wiredDynamicObjects@32`), the five per-type send queues (`creationArraysToSend@36` / `updateArraysToSend@40` / `creationDataUpdateArraysToSend@44` / `updateUnreliableArraysToSend@48` / `removalArraysToSend@52`, all NSMutableDictionary keyed by NSNumber(type) -> NSMutableArray), the heartbeat trio (`requestsHeartBeat@56`, `hasEverRequestedHeartbeat@57`, `timeSinceLastHeartbeatRequest@60` float), light-block state (`lightBlockIndex@64` int, `allLightBlockIndices@84`, `lightBlockDatabase@88` Database), fill receipts (`fillIndices@68`), the tamed-animal index map (`worldIndicesContainingTamedAnimals@72` map<uint,set<uint>*>*), `foundItemsList@80` and the flags `paused@76` / `connected@77` / `isAdmin@78`. `cxx_construct`/`cxx_destruct` (svc_00/svc_01) only touch the one C++ map ivar; every getter reads through the Apportable offset-cell chain (cell -> PIC base -> descriptor -> offset -> self+off, behind `dmb ish`) and every tiny setter is `strb`/`str` behind a `dmb ish` pair.

- **Type space = 0x41 keys**: init (svc_20), clientReconnected (svc_12), sendAllObjectData (svc_29) and dealloc (svc_15) all iterate `i in 0..0x40` (65) over the five queue dicts and the tamed-animal map -- the compiled object-type cardinality used by this class.

- **Queue consistency rules (svc_03 / svc_05)**: appending a creation to `creationArraysToSend[type]` cancels pending **removal** records of the same objectID; appending a removal to `removalArraysToSend[type]` cancels pending **creation + update + creationDataUpdate** records of the same objectID (unreliable updates are not scanned). All scan paths fast-enumerate the per-type array, `getBytes:length:8` per NSData record and compare the first 8 bytes with the 64-bit objectID (`Q16` arg, halves at fp-0x38/fp-0x34 low/high). The add-paths assume the per-type array already exists (svc_02/03/05/06 do not create it; svc_20/svc_12 (re)build all 5x65 arrays).

- **The wire format (svc_29 sendAllObjectData, census-lite)**: early-out when `!connected@77`; then per type i, five scenes in fixed order, each building `pack = NSMutableData{typeByte, i}` + `gzipDeflate(plistFromObject(array))` and sending `[server sendNetworkData:pack toPeers:[NSArray arrayWithObject:clientID] reliable:flag]`, then `removeAllObjects`: **creation -> byte 7 (reliable)**, **creationDataUpdate -> byte 0x46 (reliable)**, **update -> byte 8 (reliable)**, **updateUnreliable -> byte 8 (reliable=0)**, **removal -> byte 9 (reliable)**. `plistFromObject` = out-of-batch local helper **0xd0ada4** (verified: `OBJC_CLASS_$_NSPropertyListSerialization` + SEL `dataWithPropertyList:format:options:error:`, format 100, options 0, error out-ptr; @try/@catch reads the exception's name/reason on the catch path). The 55 call sites execute 65x at runtime.

- **Block request lifecycle**: `requestForBlock:` (svc_25, arg struct ClientMacroBlockRequest {int index; byte kind}): early-return when `requestedBlockRequestTypes[index] != 0`; else `requestedBlockIndices += index`, `map[index] = (kind != 0) ? 1 : 2`, `wiredBlocks += index`. `removeBlockRequest:` (svc_24): `map[index] = 0`, `requestedBlockIndices -= index`. `blockIsRequested:` = `map[i] != 0`; `createIfNotCreatedForBlockRequest:` = `map[i] == 1` (its operator[] call inserts the 0 entry for a missing key -- the compiled "create"); `blockIsWired:`/`blockRemoved:` are `wiredBlocks containsIndex:`/`removeIndex:`. `dynamicObjectIsWired:`/`wireDynamicObject:`/`unwireDynamicObject:` are the same on `wiredDynamicObjects@32`.

- **Heartbeat + connection flags**: char getters/setters for `requestsHeartBeat@56` and `hasEverRequestedHeartbeat@57`; float `timeSinceLastHeartbeatRequest@60` (setter `vmov s0,r2`; getter `vldr`+`vmov r0,s0`). `setConnected:` writes `connected@77` and, when the new value is 0, additionally calls `[self setPaused:0]` -- the only cross-setter coupling found in the class.

- **Identity / admin / reconnect**: both svc_20 (init) and svc_12 (clientReconnected) refresh `isAdmin@78 = [server playerIsAdminWithAlias:[[server playerInfoForPeerID:clientID] objectForKey:@"alias"]]` (CFString "alias" slot 0xfade38, cstr 0xf485ab len 5; matches BHServer E133 admin ladder bs_35). `clientReconnected` = connected=1, clear the 9 collections (removeAllIndexes: wiredBlocks/wiredDynamicObjects/requestedBlockIndices; removeAllObjects: fillIndices + the five queue dicts), then rebuild 5x65 fresh `[NSMutableArray array]` entries. It does not touch `paused@76`.

- **Light-block persistence (svc_20 load / svc_28 save)**: `allLightBlockIndices@84` is keyed-archived ("all" slot 0xfade58) into `lightBlockDatabase@88` under key `[NSString stringWithFormat:@"%@_allIndexes", clientID@4]` (format slot 0xfade48, cstr 0xf576ee) -- NSKeyedUnarchiver/NSKeyedArchiver pair, plus the `lightBlockIndex@64` int and Database instance received in init. `getAndRemoveAllRecieptDataForMacroPos:world:` (svc_18) derives macro coords per fill receipt as `x=(idx%(W*32))/32`, `y=(idx/(W*32))/32` with `W=[world worldWidthMacro]` and returns nil when nothing matched.

- **dealloc (svc_15)**: deletes every tamed-animal set (`map.at(i)`; if non-null `~set()` + `operator delete`), then `~map()` + `operator delete` the map and NULLs the ivar, then releases exactly 11 ObjC ivars (clientID, wiredBlocks, requestedBlockIndices, wiredDynamicObjects, creation, update, creationDataUpdate, updateUnreliable, removal, fillIndices, allLightBlockIndices) and calls super dealloc (`objc_msgSendSuper2`, struct {self, ServerClient cls 0x00E919D0}). `server@8`, `foundItemsList@80` and `lightBlockDatabase@88` are deliberately NOT released here (back-pointer + externally-owned handles).

| body | method | words | branches | calls | grade |
|---|---|---|---|---|---|
| svc_00 | `-[.cxx_construct]` | 27 | 0 | 1 | read |
| svc_01 | `-[.cxx_destruct]` | 30 | 0 | 2 | read (TRIMMED) |
| svc_02 | `-[addCreationDataUpdateObjectDataToSend:ofType:]` | 65 | 0 | 3 | read |
| svc_03 | `-[addCreationObjectDataToSend:ofType:objectID:]` | 283 | 8 | 14 | read |
| svc_04 | `-[addFillRequest:]` | 48 | 0 | 2 | read |
| svc_05 | `-[addRemovalObjectDataToSend:ofType:objectID:]` | 695 | 24 | 36 | census-lite |
| svc_06 | `-[addUpdateObjectDataToSend:ofType:reliable:]` | 122 | 2 | 6 | read |
| svc_07 | `-[allLightBlockIndices]` | 17 | 0 | 0 | read |
| svc_08 | `-[blockIsRequested:]` | 28 | 0 | 1 | read (TRIMMED) |
| svc_09 | `-[blockIsWired:]` | 28 | 0 | 1 | read |
| svc_10 | `-[blockRemoved:]` | 27 | 0 | 1 | read |
| svc_11 | `-[clientID]` | 17 | 0 | 0 | read |
| svc_12 | `-[clientReconnected]` | 443 | 2 | 27 | census-lite |
| svc_13 | `-[connected]` | 15 | 0 | 0 | read |
| svc_14 | `-[createIfNotCreatedForBlockRequest:]` | 28 | 0 | 1 | read |
| svc_15 | `-[dealloc]` | 252 | 5 | 17 | read |
| svc_16 | `-[dynamicObjectIsWired:]` | 28 | 0 | 1 | read |
| svc_17 | `-[foundItemsList]` | 17 | 0 | 0 | read (TRIMMED) |
| svc_18 | `-[getAndRemoveAllRecieptDataForMacroPos:world:]` | 251 | 10 | 15 | read |
| svc_19 | `-[hasEverRequestedHeartbeat]` | 15 | 0 | 0 | read |
| svc_20 | `-[initWithClientID:server:lightBlockIndex:lightBlockDatabase:]` | 892 | 6 | 57 | census-lite |
| svc_21 | `-[isAdmin]` | 15 | 0 | 0 | read |
| svc_22 | `-[lightBlockIndex]` | 15 | 0 | 0 | read |
| svc_23 | `-[paused]` | 15 | 0 | 0 | read |
| svc_24 | `-[removeBlockRequest:]` | 45 | 0 | 2 | read (TRIMMED) |
| svc_25 | `-[requestForBlock:]` | 90 | 1 | 4 | read |
| svc_26 | `-[requestedBlockIndices]` | 17 | 0 | 0 | read |
| svc_27 | `-[requestsHeartBeat]` | 15 | 0 | 0 | read |
| svc_28 | `-[saveLightBlockIndices]` | 166 | 0 | 8 | read |
| svc_29 | `-[sendAllObjectData]` | 953 | 10 | 55 | census-lite |
| svc_30 | `-[setConnected:]` | 44 | 1 | 1 | read |
| svc_31 | `-[setHasEverRequestedHeartbeat:]` | 17 | 0 | 0 | read (TRIMMED) |
| svc_32 | `-[setIsAdmin:]` | 17 | 0 | 0 | read (TRIMMED) |
| svc_33 | `-[setPaused:]` | 17 | 0 | 0 | read (TRIMMED) |
| svc_34 | `-[setRequestsHeartBeat:]` | 17 | 0 | 0 | read |
| svc_35 | `-[setTimeSinceLastHeartbeatRequest:]` | 19 | 0 | 0 | read |
| svc_36 | `-[setWorldIndicesContainingTamedAnimals:]` | 17 | 0 | 0 | read (TRIMMED) |
| svc_37 | `-[timeSinceLastHeartbeatRequest]` | 18 | 0 | 0 | read (TRIMMED) |
| svc_38 | `-[unwireDynamicObject:]` | 27 | 0 | 1 | read |
| svc_39 | `-[wireDynamicObject:]` | 27 | 0 | 1 | read |
| svc_40 | `-[wiredDynamicObjects]` | 17 | 0 | 0 | read |
| svc_41 | `-[worldIndicesContainingTamedAnimals]` | 17 | 0 | 0 | read (TRIMMED) |

## Boundaries

- **Grades**: 0 [census] (>1000w) bodies; 4 [census-lite] (svc_29 953w, svc_20 892w, svc_05 695w, svc_12 443w) traced end to end (every branch and call row read, scenes/order mapped); the other 38 (<=283w) read line by line. Call/branch counts in the table are the mechanical-layer counts from `specs_serverclient.json` (branches = `b*` rows landing inside [start,end); calls = every bl/blx row); a couple of tiny getters' only branch-like row is `bx lr`, which is not counted (register target, not an in-body address).
- **Trimmed bodies (10)**: svc_01, svc_08, svc_17, svc_24, svc_31, svc_32, svc_33, svc_36, svc_37, svc_41 -- each ARM.exidx range runs past the next ObjC IMP, so the listing was cut at that IMP (boundary case 2). In all but svc_01 the extra rows are just the body's own pool words; **svc_01** additionally swallows the out-of-batch helper 0xd0bc34..0xd0bc60 (`std::map<uint,uchar>::~map()`, the bl target of the destructor itself) inside its window. Listing rows == word count for all 42 (verified programmatically), so no instruction rows were dropped.
- **Pool-word truth**: every constant quoted (packet bytes 7/0x46/8/9, format 100, W*32 math, release wall) was read from the listings + direct ELF struct reads (file offset == vaddr); CFStrings were value-verified as CFString structs (flags 0x7c8): "alias" (slot 0xfade38, cstr 0xf485ab, len 5), "%@_allIndexes" (0xfade48, cstr 0xf576ee, len 13), "all" (0xfade58, cstr 0xf576fc, len 3). The Apportable offset-cell chain was re-verified end-to-end on svc_11 (cell 0xd0b840 delta 0xfffffbf8 -> slot 0x105f6ec -> descriptor 0xf35a80 -> offset 4). PC-delta cells (`add rX,pc,rX`) were paired and self-checked (all recompute to PIC base 0x105FAF4) before any value statement; r2 pool annotations were not used as truth. r2 renders a few `[sp, #imm]` operands as section/segment names (e.g. "section..dynsym" = 0x16c); the true imm12 was recovered from the instruction encoding for every such row.
- **Out-of-batch helpers (read-only cross-refs)**: 0xd0ada4 plist-from-object (NSPropertyListSerialization wrapper, @try/@catch; class/sel verified via ELF relocs); 0xd0bcd0 std::__tree<...,map_value_compare const> ctor; 0xd0bc34 map<uint,uchar>::~map(); 0xd0d0c4 __tree ctor + 0xd0c520 __insert_unique + 0xd0cfe4 __tree<unsigned int> ctor for the tamed-animal map; 0xd0837c map dtors and 0xd08514/0x008ba928 map operator[]/at (shared C++ instantiations); route table in specs_serverclient.json pins all 18. These helpers are described at signature level only (their bodies were not decoded).
- **Not traced / open**: the C++ std::map/set internals behind `operator[]`/`at`/`~map`/`__insert_unique` (semantics = standard libc++ behaviour, not unfolded instruction-by-instruction); the exact meaning of the recorded request types 1 vs 2 (svc_25) beyond the compiled `(kind != 0) ? 1 : 2` expression; `setPaused:`/`sendNetworkData:toPeers:reliable:`/`setData:forKey:`/`dataForKey:`/`worldWidthMacro`/`playerIsAdminWithAlias:`/`playerInfoForPeerID:` receivers (other classes/system -- call targets and argument routing only); whether `server@8` is a weak/unowned back-pointer (inferred from the missing release in dealloc, no retain seen in init).
- **Formula transcription vs runtime**: the x/y macro math in svc_18, the queue-scan order in svc_03/svc_05, the packet byte order in svc_29 and the reconnect/init sequences are mechanical transcriptions of compiled control flow; no runtime roundtrip, device-side or cross-client claim is made. Static level-A evidence only (r2 pD + GNU objdump + ELF struct reads + tsv types + class_metadata + item-adjacent batches E103/E133 as cited).
