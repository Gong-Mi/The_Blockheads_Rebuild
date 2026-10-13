# PortalChestManager closure (E11) — the server-backed portal chest

Closes `PortalChestManager` (14 methods, all of them were at `cfg` 0 before this
batch). All 14 bodies are statically recovered from the SHA-256-pinned original
`libApplication.so` (1.7.6, armeabi-v7a,
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`) and re-verified
word by word by `tools/recover_portal_chest_closure.py` (**14 bodies, 3820
instruction words**, 202 call sites, 137 branches). The artifact is
`native/portalchest_closure.json`; the tool refuses to emit when any instruction
word, PIC-base literal, cell target, call target or branch destination drifts.

The class is the client side of a server-authoritative chest: items are moved in
local slots, a transaction is written to disk and sent to the server, and the
server's answer is replayed against the persisted transaction file.

## The transaction protocol

Everything the class does online revolves around one file under Application Support:
`<ApplicationSupport>/saves/<saveID>/portalChestTransaction` (built with
`[NSString stringWithFormat:@"%@/saves/%@/portalChestTransaction", dirs[0], [world saveID]]`
— format CFString 0x00f955c8, resolved from the cell table).

**Request** — `-saveTransactionWithFailureCreation:itemsWereAdded:` (0x009595a4, 625w)
first refuses to run in three cases: a non-zero first byte of the world's
`customRules` struct (0x00959620/0x00959650), a transaction already pending
(`pendingTransaction@12`, ldrsb at 0x0095966c), or no client
(`[world client] == nil`, 0x009596c0/0x009596cc). It then arms the state —
`pendingTransaction@12 = 1` (0x00959794), `pendingTransactionIsResend@13 = 0`
(0x009597ac) and a **post-incremented** u16 `transactionIdentifierCount@14`
(ldrh 0x009597c0, strh 0x009597ec) — and builds the payload dictionary:
`numberWithBool:itemsWereAdded` under CFString 0x00f95618 (0x00959870),
`numberWithUnsignedInt:<old count>` under CFString 0x00f955d8 (0x009598c0), and,
when the failure array is non-empty, an array of `[item saveData]` under CFString
0x00f95628 (0x00959970/0x00959a80/0x00959b60). The dictionary goes through the
out-of-body plist serialiser at 0x00959b70 (`bl 0x95926c`); a nil result logs
CFString 0x00f95638 and raises `[NSException raise:@"DataSaveException"
format:@"Failed to save portal chest data."]` (0x00959c00). On success the data is
written to the transaction path and sent as
`[NSMutableData dataWithBytes:&0x3e length:1] + appendBytes:&count16 length:8`
via `[[world client] sendDataToServer:… reliable:YES]` (0x00959e14/0x00959e4c/0x00959e98).

**Acknowledgement** — `-portalChestServerAckReceivedWithSuccess:transactionIdentifier:`
(0x0095a108, 523w) reloads that file (path 0x0095a254, `[NSData dataWithContentsOfFile:]`
0x0095a284, parsed by the out-of-body helper at 0x0095a2a0 / 0x95894c) and applies
the answer. Two measured facts matter here:

- the `success` char is read exactly once (0x0095a2b0), and
- the **unsigned-short `transactionIdentifier` argument is stored at fp-0x30
  (0x0095a13c) and never read** — the handler keys only off the persisted plist.

A local flag decides whether the failure items are migrated: on success it is set
when `pendingTransactionIsResend@13` (ldrsb 0x0095a33c) is set *and* the plist's
`itemsWereAdded` is true, otherwise the handler calls
`[self saveWithMainThreadBlock:YES]` instead (0x0095a390); on failure it is set only
when resend is set *and* `itemsWereAdded` is false (0x0095a424). With the flag set it
reads `plist[@"failureCreationItems"]` (0x0095a45c) and, when non-empty
(`bls` 0x0095a4ac), re-creates each element with
`[[[InventoryItem alloc] initWithSaveData:] autorelease]` (0x0095a530/0x0095a658),
applies them through
`[self moveInventoryItemsFromArray:arr toIndex:-1 count:[arr count] movedItems:nil
assignedIndexes:&set<int>]` (`mvn r3, 0` at 0x0095a7a4, call 0x0095a7b0) and calls
`[self saveWithMainThreadBlock:YES]`. **Both paths converge** on the same tail:
`[[NSFileManager defaultManager] removeItemAtPath:path error:NULL]` (0x0095a880)
and `pendingTransaction@12 = 0` (0x0095a898).

**Resend** — `-initWithWorld:` (0x00957db4, 742w) is what arms a resend at load
time: after wiring `world@4`, seeding `transactionIdentifierCount@14` from
`(uint16)[world worldTime]` (`vcvt.s32.f64` at 0x00957efc), building
`portalChestInventoryItems@8 = [[NSMutableArray alloc] init]`, gating on the world's
`customRules` first byte, and restoring the 16 chest slots from the on-disk file
(see below), it checks `[world client] != nil` (0x009584cc): when a client exists and
the transaction file loads, it sets `pendingTransaction@12 = 1` (0x00958754) **and
`pendingTransactionIsResend@13 = 1`** (0x0095876c) and sends the same 1-byte-marked
message — with marker **0x40** where the request path sends **0x3e** (0x009587bc/
0x00958818/0x00958864, identifier taken from `txData[@"identifier"]`).

## Chest persistence

- `-saveWithMainThreadBlock:` (0x00958a34, 526w) **takes a char/BOOL, not a block**
  (types `v12@0:4c8`; the argument is stored at 0x00958a74 and only read at
  0x009590a0) — the CrystalManager `NSOperationQueue` + `addOperationWithBlock:`
  idiom is explicitly *not* used here. It gate-returns on `customRules` byte 0
  (0x00958aac/0x00958adc), builds `dict[@"saveItemSlots"]` by nested fast
  enumeration (one `[NSMutableArray array]` per slot, each filled with
  `[item saveData]`; 0x00958bec/0x00958d54/0x00958f8c), serialises it with the same
  plist helper (0x00958fa0) and raises `DataSaveException` / logs
  "Failed to save portal chest data." on a nil result (0x00958fc8/0x00958ff4).
  Then it branches: flag set → write `<ApplicationSupport>/portalChest` now
  (0x009590e8/0x0095917c); flag clear → park `pendingSaveData@16 = [data retain]`
  (0x009590a0/0x0095919c) for the deferred writer.
- `-saveAnyPendingDataToDisk` (0x009593d8, 115w) is that deferred writer: it returns
  when `pendingSaveData@16` is nil (0x00959410), otherwise resolves the same
  Application Support directory (`NSSearchPathForDirectoriesInDomains(0xe = 14 =
  NSApplicationSupportDirectory, 1, YES)` at 0x00959440), builds
  `@"%@/portalChest"` (CFString cell 0x00959590 -> slot 0x00f95ab4), writes with
  `[pendingSaveData writeToFile:path atomically:YES]` (0x0095952c) and clears
  `pendingSaveData@16` (0x00959574).
- `-initWithWorld:` restores: `saveItemSlots = [data objectForKey:@"saveItemSlots"]`
  (0x00958118) and a 16-iteration loop (cmp #0x10 at 0x00958130) appends one
  `[NSMutableArray array]` per slot (0x009581c8) and, only when the stored slot count
  is 16 (0x009581e4), decodes each entry with
  `[[[InventoryItem alloc] initWithSaveData:item] autorelease]` (0x00958398).
- `-portalChestInventoryItems` (0x0095a934, 34w) hands out `[[ivar@8 copy]
  autorelease]` (0x0095a98c/0x0095a99c) — the only accessor that copies.

## Inventory movement

Five bodies move items between the chest's slot arrays; the four small ones are thin
wrappers around the two big ones, and they all share one rule:

| body | IMP | what it does |
|---|---|---|
| `moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:` | 0x0095ae70 (786w) | the slot picker and the only real mover |
| `moveInventoryItemsWithinChestFromArray:toIndex:count:assignedIndexes:` | 0x0095ad94 (55w) | forwards to the mover with the arguments, then `[self saveWithMainThreadBlock:0]` |
| `moveInventoryItemsWithinChestFromArray:toIndex:count:` | 0x0095a038 (52w) | builds a stack `std::set<int>` and forwards to the 5-arg variant |
| `takeIncomingInventoryItemsFromArray:toIndex:count:assignedIndexes:` | 0x0095a9bc (122w) | moves into a fresh `[NSMutableArray array]` accumulator, then branches on the client |
| `takeIncomingInventoryItemsFromArray:toIndex:count:` | 0x00959f68 (52w) | builds a stack `std::set<int>` and forwards to the 5-arg variant |
| `itemsRemovedToInventory:andOrDropped:` | 0x0095aba4 (124w) | copies the removed items, adds the dropped ones, then branches on the client |

The two 4-arg forwarders are the same shape: a `std::__1::set<int>` is
default-constructed on the frame (0x00959fa8 / 0x0095a078), its address is placed in
the `assignedIndexes` argument slot, the 5-arg method is called, the set is destroyed
(0x00959ff8 / 0x0095a0c8) and the callee's int result is returned — with a second
destructor plus `_Unwind_Resume` on the unwind path (0x0095a020/0x0095a02c and
0x0095a0f0/0x0095a0fc).

`moveInventoryItemsFromArray:…` itself is the destination-slot chooser. It returns 0
when `count == 0`, when `[fromArray count] == 0` (0x0095af08), or when no slot was
resolved (`cmn r0, 1` at 0x0095b554). With `toIndex == -1` (flag byte fp-0x71 at
0x0095aec0) it looks for a destination: if `[fromArray[0] itemType]` is stackable
(`itemTypeIsStackable(type, 0, 0)` at 0x0095afa0) it scans the chest slots
(`portalChestInventoryItems@8`, cell 0x0095baa0) for one with `0 < count < 99`
(caps at 0x0095b13c) whose head item matches and which is stackable with the source's
`dataB` (0x0095b2a0/0x0095b2b4); otherwise — and as the fallback — it takes the first
slot whose `count == 0` (0x0095b4b8). `dest = [portalChestInventoryItems
objectAtIndex:toIndex]` (0x0095b5d8); when `[dest count] > 0` the source type must
equal `[dest[0] itemType]` and be stackable with the destination's `dataB`, otherwise
the method returns 0 (0x0095b5f0/0x0095b61c). Then `count = MIN(count, [fromArray
count])` and **`num = MIN(count, 99 - [dest count])`** (0x0095b7e0) — a hard 99-item
cap per slot. The last `num` elements of `fromArray` are popped, appended to `dest`
and to `movedItems`. When the caller's `toIndex` was -1 and `0 < num < count` it
recurses with `toIndex -1` and `count - num`, adding the returned count (0x0095b9cc),
and when `num > 0` it records the chosen slot with `assignedIndexes->insert(toIndex)`
(`std::__1::__tree::__insert_unique` at 0x0095ba14).

## The client branch rule

Three bodies make the same decision, and it is the class's whole online/offline
switch: **`[self->world@4 client] == nil` means "no server", and the write is deferred
instead of transacted.**

| body | no client | with client |
|---|---|---|
| `takeIncoming…assignedIndexes:` | `[self saveWithMainThreadBlock:0]` (0x0095ab24) | `[self saveTransactionWithFailureCreation:(moved items) itemsWereAdded:1]` (0x0095ab70) |
| `itemsRemovedToInventory:andOrDropped:` | `[self saveWithMainThreadBlock:0]` (0x0095ac4c) | `[NSArray arrayWithArray:arg1]` (+ `arrayByAddingObjectsFromArray:andOrDropped` when non-nil) then `[self saveTransactionWithFailureCreation:items itemsWereAdded:0]` (0x0095ab70-equivalent at 0x0095ad64) |
| `moveInventoryItemsWithinChest…assignedIndexes:` | — | forwards, then `[self saveWithMainThreadBlock:0]` (0x0095ae50) |

## Accessors, flags and teardown

`-hasPendingTransaction` (0x0095bab8, 15w) is an `ldrsb` of `pendingTransaction@12`
(0x0095bae0). `-dealloc` (0x00958970, 49w) releases `portalChestInventoryItems@8`
(0x009589e4) and calls `objc_msgSendSuper2` dealloc (0x00958a0c) — nothing else.
`transactionIdentifierCount@14` is a u16 used as a monotonic counter (the request path
post-increments it and puts the old value in the payload).

## Anchors

| body | IMP | words | sel/imp/class | ivars | calls | branches |
|---|---|---:|---|---:|---:|---:|
| pcm_initwithworld_ | 0x00957db4 | 742 | 20 / 7 / 6 | 5 | 38 | 22 |
| pcm_dealloc | 0x00958970 | 49 | 2 / 2 / 1 | 1 | 2 | 0 |
| pcm_savewithmainthreadbloc | 0x00958a34 | 526 | 13 / 7 / 4 | 3 | 27 | 22 |
| pcm_saveanypendingdatatodi | 0x009593d8 | 115 | 4 / 2 / 1 | 1 | 5 | 1 |
| pcm_savetransactionwithfai | 0x009595a4 | 625 | 19 / 9 / 6 | 4 | 30 | 18 |
| pcm_takeincominginventoryi | 0x00959f68 | 52 | 1 / 0 / 0 | 0 | 5 | 1 |
| pcm_moveinventoryitemswith | 0x0095a038 | 52 | 1 / 0 / 0 | 0 | 5 | 1 |
| pcm_portalchestserverackre | 0x0095a108 | 523 | 17 / 4 / 5 | 3 | 31 | 24 |
| pcm_portalchestinventoryit | 0x0095a934 | 34 | 2 / 1 / 0 | 1 | 2 | 0 |
| pcm_takeincominginventoryi_a9bc | 0x0095a9bc | 122 | 5 / 1 / 1 | 1 | 5 | 2 |
| pcm_itemsremovedtoinventor | 0x0095aba4 | 124 | 5 / 1 / 1 | 1 | 6 | 3 |
| pcm_moveinventoryitemswith_ad94 | 0x0095ad94 | 55 | 2 / 1 / 0 | 0 | 2 | 0 |
| pcm_moveinventoryitemsfrom | 0x0095ae70 | 786 | 8 / 1 / 0 | 1 | 44 | 43 |
| pcm_haspendingtransaction | 0x0095bab8 | 15 | 0 / 0 / 0 | 1 | 0 | 0 |

Total: **14 bodies, 3820 verified words, 202 call sites, 137 branches**, 160
selector-side cells (99 selectors + 36 imports + 25 classrefs) and 22 ivar cells.
Every body's PIC base (0x0105faf4) is recomputed from its own pool literal; no
literal-pool word in this batch misdecodes as a branch, so
`disjoint_branch_rows` is empty everywhere.

## Boundaries

- **The two plist codecs are out of body.** Both `-saveWithMainThreadBlock:` and the
  transaction request serialise through `bl 0x95926c`, which begins exactly at
  `-saveWithMainThreadBlock:`'s ARM.exidx end; its selector set
  (`dataWithPropertyList:format:options:error:` with format 100 = binary) and its
  error CFString are readable from that neighbouring code, but its host class/name is
  not part of these 14 bodies. Likewise `0x95894c` (used by `-initWithWorld:` and the
  ack handler) wraps `propertyListWithData:`. Both are recorded here as boundaries, not
  as recovered methods.
- **The `customRules` gate is a black box.** Four bodies return early on the first
  byte of the 64-byte struct returned by `[world customRules]`; the rest of that
  struct is not decoded in this batch and is not claimed.
- **The ack's `transactionIdentifier` argument is dead** in this binary (stored at
  fp-0x30, never read). Whether it was validated in an earlier build is not something
  these bodies can answer.
- **`appendBytes:length:8` over a 16-bit store.** Both the request path (0x00959e4c)
  and the resend path (0x00958818) append 8 bytes from a buffer whose low 2 bytes were
  written with `strh`, so bytes 2..7 are not initialised by these listings. Two
  independent readings hit this; it is recorded as an open question (either a genuine
  8-byte field with a partly-initialised path, or a compiler artifact), not resolved.
- **Two dead immediates.** `movw r3/r7, #2` written to frame slots that are never
  reloaded in `moveInventoryItemsFromArray:…` (0x0095b0d0/0x0095b478) and
  `-saveWithMainThreadBlock:` (0x00958ca4/0x00958ddc) — meaning unknown.
- **No floating point in the batch.** The only FP operation is
  `vcvt.s32.f64` on the runtime `[world worldTime]` double in `-initWithWorld:`.
