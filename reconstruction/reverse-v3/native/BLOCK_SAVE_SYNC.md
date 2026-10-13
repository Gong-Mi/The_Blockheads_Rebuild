# The physical-block save/sync pair (E14) — the main-block counterpart of the light-block line

Recovers `WorldTileLoader`'s physical-block **writer** and its **client-sync** path — the
two bodies that move the 32×32 terrain blocks the light-block family (E13) sits on top of.
All bodies are statically recovered from the SHA-256-pinned original `libApplication.so`
(1.7.6, armeabi-v7a,
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`) and re-verified word by
word by `tools/recover_block_save_sync.py` (**2 bodies, 2079 instruction words**, 112 call
sites, 50 branches). The artifact is `native/block_save_sync.json`.

| body | IMP | words | sel/imp/class | ivars | calls | branches |
|---|---|---:|---|---:|---:|---:|
| `wtl_savephysicalblock_macr` | 0x00859a84 | 882 | 21 / 9 / 6 | 2 | 47 | 21 |
| `wtl_sendblocktoclientwitho` | 0x00858664 | 1197 | 25 / 12 / 6 | 2 | 65 | 29 |

Both bodies' PIC base (0x0105faf4) is recomputed from a pool literal at a verified
`add rX, pc, rX` site, and no pool word in this batch misdecodes as a branch
(`disjoint_branch_rows` is empty everywhere).

## What each body does

### `savePhysicalBlock:macroTile:sendToClients:server:sendReliably:` (0x00859a84, 882w)

The server-side writer. It gzips the block's tile image plus two scalar fields, persists
the result in `blockDatabase`, and then pushes per-client packets to the connected
clients in `sendToClients`.

- **The gzip input is built from the block in three pieces** (this batch's per-instruction
  confirmation of the plan `STATIC_SAVE_CONTRACT.md` records from partial evidence):
  `[NSMutableData dataWithBytes:<the Tile pointer read from physicalBlock+8> length:0x10000]`
  (call at 0x00859b80; the length is the pool literal moved at 0x00859b68), then
  `appendData:[NSData dataWithBytes:physicalBlock+13 length:1]` (0x00859bb8/0x00859bd8) and
  `appendData:[NSData dataWithBytes:physicalBlock+24 length:4]` (0x00859c0c/0x00859c2c) —
  **65536 + 1 + 4 = 65541 bytes** sourced from the `'C'` byte at offset 13 and the `'I'`
  word at offset 24 of `^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}`.
- `gzipDeflate` at 0x00859c40; **a nil result raises** `[NSException raise:format:]`
  (0x00859cb0, cells 0x0085a7c8/0x0085a7cc) — the compared-against-zero register is the 0
  spilled at 0x00859b70, and `bne 0x00859c54` skips the raise when non-nil.
- The offset-24 word is **incremented in place right after being copied into the input**
  (0x00859cf4-0x00859cfc): the saved copy carries the pre-increment value.
- **Per-client light-block piggyback.** A first 16-per-batch NSFastEnumeration pass over
  `sendToClients` (0x00859d74): per element `item` it resolves
  `[[self->world serverClients] objectForKey:item]` (0x00859e2c/0x00859e40), reads its
  `lightBlockIndex` (0x00859e54), loads the light block on demand via
  `[self loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:]` (0x00859ec0;
  the E13 loader, result unused), skips the element while the slot is still empty, and
  otherwise copies the 0x400-byte tile (`dataWithBytes:length:`, 0x00859f34), builds an
  admin/format key (`playerIsAdminWithID:` + `stringWithFormat:` + `stringFromMD5`,
  0x00859f90-0x0085a008) and a receipt slot
  (`getAndRemoveAllRecieptDataForMacroPos:world:`, 0x0085a05c), serializes that dictionary
  through the local function at 0x00859918 and registers the extended copy in the send
  dictionary.
- **Persist.** After the pass drains it stores `[blockDatabase setData:<gzip payload>
  forKey:<stringWithFormat: x, y>]` (0x0085a288; `blockDatabase` at ivar cell 0x0085a824).
- **Broadcast.** Only when `server != nil` and `[sendToClients count] > 0` a second batched
  pass sends per client: header = `dataWithBytes:&4 length:1` (0x0085a514) +
  `appendBytes:&linear length:4`, where `linear = physicalBlock->y * worldWidthMacro +
  physicalBlock->x` (0x0085a358-0x0085a368); payload dictionary = gzip payload + the
  per-client gzipped light block (0x0085a5b4-0x0085a634); serialized via 0x00859918, sent as
  `[server sendNetworkData:header toPeers:[NSArray arrayWithObject:item] reliable:1]`
  (0x0085a718) — **reliable:1 is a constant; the `sendReliably:` argument spilled at
  0x00859b2c is never read by this body** (recorded as measured).
- Dead spills recorded: `_cmd` ([fp,-0x24]) and `macroTile` ([fp,-0x2c]) are each written
  exactly once and never read again (verified by exhaustive slot scan).

### `sendBlockToClientWithoutSavingForBlock:pos:sendToClient:server:sendDynamicObjects:reliable:` (0x00858664, 1197w)

The client-sync sender — the light-block send's bigger sibling: same payload shape plus a
dynamic-objects path, and **nothing is written to `lightBlockDatabase`** in this body.

- **Guards before anything is built**: `server == nil` (0x008586cc) and
  `sendToClient == nil` (0x008586dc) short-circuit to the flag copy at 0x859868; then
  `[[self->world serverClients] objectForKey:sendToClient]` (0x008588c0) with nil → NSLog
  path 0x858c30, `[record connected]` false → 0x0085890c, the `tiles[idx]` slot empty →
  one `loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:` retry (0x008589a8)
  and, still empty → NSLog path 0x858c10, and a nil serialization → 0x858bf0. Every failure
  returns 0 through the same flag copy.
- **Payload**: `dataWithBytes:<Tile* from block+8> length:0x10000` (0x008587b0) +
  `appendData:[NSData dataWithBytes:block+13 length:1]` + `[NSData dataWithBytes:block+24
  length:4]` (0x008587e8/0x0085883c), and **the offset-24 word is incremented in place**
  (0x00858860-0x0085886c) exactly as in the writer.
- **Per-tile payload**: `dataWithBytes:<tiles[idx]> length:0x400` (0x00858a1c) with the
  receipt dictionary (`getAndRemoveAllRecieptDataForMacroPos:world:`, 0x00858b40; key from
  `stringWithFormat:` + `stringFromMD5`, 0x00858af0/0x00858ab0) serialized through 0x00859918
  and appended (0x00858be8).
- **The wire message**: header = `dataWithBytes:&4 length:1` (0x00858e5c) +
  `appendBytes:&macroIndex length:4` (0x00858e88), where
  `macroIndex = pos word0 + pos word1 * [world worldWidthMacro]` (0x00858cc4-0x00858cd8);
  the payload dictionary then takes `gzipDeflate(block payload)` (0x00858ed0/0x00858ef4) and
  `gzipDeflate(per-tile payload)` (0x00858f50/0x00858f74), is serialized via 0x00859918 and
  appended (0x00858ff0), and is sent as
  `[server sendNetworkData:... toPeers:[NSArray arrayWithObject:sendToClient] reliable:(char)[fp,-0x3e]]`
  (0x00859064) — **`reliable` controls exactly this message**.
- **The `sendDynamicObjects` flag gates only the dynamic-object fetch** (0x00858cec):
  non-zero runs `[[world dynamicWorld] initialDynamicObjectsNetDataForMacroTileIndex:macroIndex
  wireForClient:sendToClient]` (0x00858d40/0x00858d58) into [fp,-0x74]; the method's return
  value is still 1 for every run that got past 0x00858e04.
- **Two dynamic-object passes** over the returned collection (keyed by cells 0x0085990c and
  0x00859914): 16-per-batch enumeration (0x00859134 and the second pass), per entry a
  1-byte-tagged header — **pass 1 tags 7** (movw r3,7 at 0x008591e0 → 0x00859244 →
  0x00859278; message 0x0085929c), **pass 2 tags 8** (movw r3,8 at 0x008595d8 → 0x0085963c →
  0x00859670; message 0x00859694) — plus the entry's 1-byte index and the gzipped serialized
  entry, sent with **reliable:1 hardcoded** (0x008593e8 / 0x008597e0), not the argument.

## The four unclassified pool words per body (measured mechanism, not a gap)

Every pool word is resolved as a PIC-relative cell (`slot = base + signed(word)`); four
words per body do not fit that model and are left unclassified **by the classifier, not by
the code** — each one is accounted for:

- **One is a plain literal**: `0x10000` (65536 — the tile-payload length) is loaded
  *without* an `add pc` step (savePhysicalBlock at 0x00859afc → `str r0, [fp, -0x170]`,
  sendBlock at 0x00858740 → `str r0, [fp, -0x194]`) and feeds the `dataWithBytes:length:`
  construction (selector cell 0x0085a7b0, first call site 0x00859b80 in savePhysicalBlock).
  Resolving it through the base lands past the end of the image — which is why the
  classifier rejects it.
- **Three are per-site re-materialisations of the PIC base**: `ldr rX, [pc, #k]` followed
  immediately by `add rX, pc, rX`, recomputing 0x0105faf4 exactly —
  savePhysicalBlock at 0x00859a90→0x00859a94 (the roster's base anchor), 0x00859dfc→0x00859e00,
  0x00859ef4→0x00859ef8; sendBlock at 0x00858674→0x00858678 (its base anchor),
  0x00858920→0x00858924, 0x008589dc→0x008589e0.

Both routes were re-computed from the listing during recovery; the numbers above are the
measurements, recorded so the next reader does not re-derive them.

## Boundaries

- The concrete database and network implementations behind `setData:forKey:`,
  `gzipDeflate` and `sendNetworkData:` are outside these bodies (dynamic dispatch).
- **CFString contents are not recovered here** (the spec's cfstring map is empty for this
  batch): the format/key texts behind the `__CFConstantStringClassReference` cells —
  including the `STATIC_SAVE_CONTRACT.md` blockDatabase-key text `%d_%d_compressedBlock` —
  can be neither confirmed nor refuted from these listings; only argument counts and
  positions are proven.
- The local function at 0x00859918 (target of `bl 0x859918`) is unnamed and outside both
  IMPs; only its interface is observable (dictionary in r0; nil-checked object out;
  consumed via `appendData:`). Note the dict2 call at 0x00858f7c has no nil check while the
  dict1 call at 0x00858ba0 does.
- The client-record class, the receipt-data meaning and the MD5-key construction are not
  determined here; the runtime layout is known only at the offsets these bodies touch.
- The `sendReliably:` argument is never read by the writer (reliable:1 constant), while in
  the sender it gates only the block message; the dynamic packets hardcode 1. Whether the
  game ever needs the caller's flag for the dynamic packets cannot be determined from
  these bodies.
