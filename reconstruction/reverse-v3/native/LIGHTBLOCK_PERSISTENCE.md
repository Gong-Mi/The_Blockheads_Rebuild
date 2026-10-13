# Light-block persistence batch (E13) — the WorldTileLoader light-block store

Recovers the `WorldTileLoader` light-block storage family the project inventory
listed as the unmapped piece that **intersects the save line** ("光块存储 … 未映射
—与存档线交汇"): the legacy-archive migration, the archive/unarchive pair, the
per-block load and save paths, the client send path and the bulk-transaction
open/close pair. All 7 bodies are statically recovered from the SHA-256-pinned
original `libApplication.so` (1.7.6, armeabi-v7a,
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`) and re-verified
word by word by `tools/recover_lightblock_persistence.py` (**7 bodies, 2260
instruction words**, 122 call sites, 58 branches). The artifact is
`native/lightblock_persistence.json`.

The two ivars this family lives in are adjacent: `lightBlockDatabase@252` and
`lightBlockDatabaseEnvironment@248` (declared `@\"DatabaseEnvironment\"`).

## The two database generations

The family supports two on-disk shapes and migrates between them.

**Legacy (combined).** `<client>_archiveKeys` holds a gzipped plist array of
`"a_b"` strings and `<client>_archiveData` holds the concatenated packed records —
one 1024-byte chunk per entry, in the array's order. The invariant enforced by the
migrator is exact: `[data2 length] == 1024 * [plist count]` (0x00866888) or the
whole migration is skipped.

**Current (per-block).** Each block is its own key `"<client>_<macroX>_<macroY>"`
(or `"<client>_<item>"` during migration), plus `<client>_allIndexes` holding an
NSKeyedArchiver blob whose decoded `NSIndexSet` (inner key `@"all"`) names every
block that has data.

## The bodies

`unarchiveLightBlocksForClient:` (0x0086652c, 632w) is the migrator. It builds
`key1 = "<client>_archiveKeys"` (0x008665e4), inflates it (`gzipInflate`,
0x00866620), returns when nil, stamps `t0 = [NSDate timeIntervalSinceReferenceDate]`
(0x008666a8), resolves `clientObj = [[self->world@4 serverClients] objectForKey:client]`
(0x008666f4), opens the write window with `[self startBulkLightBlockTransaction]`
(0x00866740) and parses the keys through the out-of-body helper at 0x00866f0c =
`[NSPropertyListSerialization propertyListWithData:options:0 format:NULL error:NULL]`.
It then inflates `<client>_archiveData` (0x00866810) and, per plist item
(fast enumeration, batch 16): `comps = [item componentsSeparatedByString:@"_"]`
(0x008669f0) must split into exactly 2 parts (0x00866a10); `itemkey = "<client>_<item>"`
(0x00866a80); when the key is absent (0x00866ab8) it stores
`[data2 subdataWithRange:(1024*i, 1024)]` (0x00866b2c) as the i-th packed light
block, computes `macroIndexAtMacroPosition(comps[0].intValue, comps[1].intValue,
world)` (0x00866c38) and adds that index to `[clientObj allLightBlockIndices]`
(0x00866c90). Afterwards `[clientObj saveLightBlockIndices]` (0x00866d50) and the
success log `"unarchived %d LightBlocks for client:%@"` (0x00866d98). The tail
(0x00866da0) removes **both** legacy keys (0x00866dec) and logs
`"unarchiveTime: %.4f"` (0x00866e7c).

**Measured caveat.** The nil-`data2` and length-mismatch paths branch to that same
tail (0x00866898 → 0x00866da0), so the legacy keys are deleted even when the
migration did not happen. Recorded as observed; the body does not say why.

`archiveLightBlocksForClient:` (0x00866f30, 456w) is the pair's writer. It logs
`"archiveLightBlocksForClient:%@"` (0x00866f64), calls
`[self unarchiveLightBlocksForClient:client]` first (0x00866fec) so legacy data is
materialised, then reads `<client>_allIndexes` (0x0086704c) and returns when nil
(0x00867060). The blob is NSKeyedUnarchiver-decoded (`initForReadingWithData:`
0x00867110, `decodeObjectForKey:@"all"` 0x0086712c) into an NSIndexSet;
`buf = malloc([set count] << 10)` (0x008671dc) is filled by
`enumerateIndexesUsingBlock:` (0x0086727c, block at 0x008675e8/0x008675ec) whose body
maps each index through `macroPosForMacroIndex(int, World*)` (0x008676b0) and
`memcpy` 0x400 bytes to `buf + count*1024` (0x008678a4), incrementing a captured
`__block` counter (0x008678bc). A counter <= 0 skips the write (0x00867290).
Otherwise it stores `[NSData dataWithBytes:buf length:count<<10] gzipDeflate`
(0x008672bc/0x008672dc) as `<client>_archiveData` (0x0086737c) and the keys array as
a **binary plist** (`dataWithPropertyList:format:100` in helper 0x859918) gzipped
(0x008672f4/0x00867314) as `<client>_archiveKeys` (0x00867428), then removes
`<client>_allIndexes` (0x0086749c) — the index set is consumed by the archive.

`loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:` (0x00867a58,
483w) resolves one block into a `PhysicalBlock`. Cache key
`"%@_%d_%d"` from `clientID`, `physicalBlock->x` (offset 0) and `->y` (offset 4)
(0x00867b48), read with `[lightBlockDatabase dataForKey:]` (0x00867b9c); a non-nil
hit skips the file path. Otherwise, when the world exists and
`![world hasFinishedDatabaseMigrationTo17]`, the shard path is built as
`"playerLightBlocks/%@/%@/%@/"` with the client id split
`[0,1] / [1,1] / [2,len-2]` (0x00867d90) and the name `"%@%d_%d_lightBlock"`
(0x00f925c8) under `self->blockDirectory@12`, probed with
`[[NSFileManager defaultManager] fileExistsAtPath:]` (0x00867e44) and read with
`[[NSData dataWithContentsOfFile:] gzipInflate]` (0x00867eb0). This body is also
where the **PhysicalBlock record layout** is pinned: `x@0`, `y@4`, `tiles[32]@0x20`
(a 32-entry pointer array, `add r1, r2, r1, lsl 2` at 0x00867f20) and `flags[32]@0xA0`
(`add r1, r1, 0xa0` at 0x00867f9c). With data:
`tiles[i] = malloc(0x400)` (0x00867f24) + `memcpy([data bytes], [data length])` and
`flags[i] = 1` (0x00867fa8); without data: `tiles[i] = calloc(1, 0x400)`
(0x00868008) and `flags[i] = 0` (0x00868020). When the block contains
`world.startPortalPos` (32 tiles per block, `lsl r2, r2, 5` at 0x00868098) it calls
`[world fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:nil]`
(0x0086816c).

`saveLightBlockForClientLightBlockIndex:clientID:physicalBlock:sendNow:` (0x00868700,
284w) gates on `tiles[idx] != 0` (0x0086874c) and the client record (0x008687f4),
then writes **unconditionally**:
`[lightBlockDatabase setData:[NSData dataWithBytes:elem length:0x400] forKey:@"<x>_<y>"]`
(0x008688cc / 0x0086894c). It maps the block with `macroIndexAtMacroPosition`
(0x00868984) and, when `![record.allLightBlockIndices containsIndex:M]` (0x008689e8),
adds it and calls `[record saveLightBlockIndices]` (0x00868a50/0x00868a64). The
`sendNow` char (stored at 0x00868738) only controls the re-broadcast
(0x00868a70 → 0x00868b0c): the database write is **not** gated by it.

`sendLightBlockToClientWithoutSavingForBlock:pos:sendToClient:server:` (0x008681e4,
327w) sends without persisting. Six guards each return 0: `sendToClient != nil`
(0x00868230), the client record exists (0x008682b8/0x008682d8), the record's
`lightBlockIndex` (0x008682f0), its `connected` flag (0x0086833c), `server != nil`
(0x0086834c) and `tiles[idx] != 0` (0x00868368). It copies the 1024-byte chunk into
an `NSMutableData` (`dataWithBytes:length:` 0x008686e8 with length 0x400,
`appendBytes:length:`/`appendData:` 0x008686e4/0x008686dc, `gzipDeflate` 0x008686e0)
and sends `[server sendNetworkData:<data> toPeers:[NSArray arrayWithObject:sendToClient]
reliable:(sxtb [fp,-0x88] = 0)]` (0x008686a0), returning the BOOL at `[fp,-0x3d]`.

`startBulkLightBlockTransaction` (0x00868b70, 52w) and
`finishBulkLightBlockTransaction` (0x00868bd8, 26w) are the thinnest bodies in the
whole project: each loads `self->lightBlockDatabaseEnvironment@248` (ivar cells
0x00868bd0 / 0x00868c38) and forwards `-startBulkTransaction` / `-finishBulkTransaction`
(selector cells 0x00868bcc / 0x00868c34). The opener discards the void result
(`str r0, [sp,4]`, `v8@0:4`); the closer sign-extends the char result
(`sxtb r0, r0` at 0x00868c24, `c8@0:4`).

## Anchors

| body | IMP | words | sel/imp/class | ivars | calls | branches |
|---|---|---:|---|---:|---:|---:|
| wtl_unarchivelightblocksfo | 0x0086652c | 632 | 20 / 7 / 2 | 2 | 37 | 14 |
| wtl_archivelightblocksforc | 0x00866f30 | 456 | 18 / 9 / 5 | 1 | 32 | 19 |
| wtl_loadlightblockforclien | 0x00867a58 | 483 | 13 / 4 / 3 | 3 | 22 | 13 |
| wtl_sendlightblocktoclient | 0x008681e4 | 327 | 11 / 1 / 3 | 1 | 14 | 6 |
| wtl_savelightblockforclien | 0x00868700 | 284 | 11 / 2 / 2 | 2 | 14 | 6 |
| wtl_startbulklightblocktra | 0x00868b70 | 52 | 2 / 2 / 0 | 2 | 2 | 0 |
| wtl_finishbulklightblocktr | 0x00868bd8 | 26 | 1 / 1 / 0 | 1 | 1 | 0 |

Total: **7 bodies, 2260 verified words, 122 call sites, 58 branches**, 102
selector-side cells (76 selectors + 26 imports + 15 classrefs) and 12 ivar cells.
Every body's PIC base (0x0105faf4) is recomputed from its own pool literal and no
pool word in this batch misdecodes as a branch.

## Boundaries

- **`DatabaseEnvironment` is a foreign class.** Only the forwarding pair touches it;
  the concrete implementation of `-startBulkTransaction` / `-finishBulkTransaction`
  is outside these bodies, so the transaction's isolation/atomicity guarantees are
  not established here.
- **The 1024-byte chunk is opaque.** This family moves exactly 1024 bytes per block
  (`malloc(0x400)`, `length 0x400`, `1024 * count`) and the `PhysicalBlock` record
  puts them in `tiles[32]@0x20` with a parallel `flags[32]@0xA0`, but the chunk's
  internal layout is not recovered here.
- **The shard path is constructed, not validated.** The
  `playerLightBlocks/<id[0]>/<id[1]>/<id[2:]>` layout and the
  `%@%d_%d_lightBlock` name are read from the format strings; what writes those
  files is not in this batch.
- **The client object is untyped.** `client` is used as a format argument, a
  `serverClients` key and the receiver namespace for the light-block keys; its class
  and the meaning of its `lightBlockIndex` / `connected` / `allLightBlockIndices`
  fields come only from the selectors attested in these bodies.
- **Helper 0x859918 and 0x00866f0c are out of body.** The former is a
  `dataWithPropertyList:format:100` wrapper, the latter a
  `propertyListWithData:options:0` wrapper; both are named from their selectors plus
  an adjacent class-name string, not from a decoded receiver cell (`0xffe2add0`
  reads 0 pre-relocation).
- **The migration can delete without migrating.** The length-mismatch and nil paths
  reach the same removal tail; that is a property of the code as written, and whether
  it ever triggers in practice is a runtime question, not a static one.
