# InteractionObject (E146)

The InteractionObject base class lands: the ownership protocol, the net blob round-trip and the one-line defaults. 33 bodies, 2146 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| io_00 | InteractionObject -[actionTitle] | 0x005f6738 | 19 | 1 | 1 | 0 | 0 | 1 | 0 |
| io_01 | InteractionObject -[blockheadUnloaded:] | 0x005f741c | 94 | 2 | 1 | 4 | 0 | 2 | 4 |
| io_02 | InteractionObject -[blockheadWouldLikeToTakeOwnership:withSaveDict:] | 0x005f6ffc | 198 | 8 | 1 | 7 | 0 | 8 | 4 |
| io_03 | InteractionObject -[blockheadsLoaded] | 0x005f4d4c | 219 | 6 | 1 | 5 | 0 | 7 | 10 |
| io_04 | InteractionObject -[canBeUsedByBlockhead:] | 0x005f6f44 | 39 | 0 | 0 | 2 | 0 | 0 | 1 |
| io_05 | InteractionObject -[canBeUsedInExpertModeWhenNotOwned] | 0x005f6fe0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_06 | InteractionObject -[creationNetDataForClient:] | 0x005f5bf0 | 21 | 1 | 1 | 0 | 0 | 1 | 0 |
| io_07 | InteractionObject -[currentBlockhead] | 0x005f75f4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| io_08 | InteractionObject -[dealloc] | 0x005f5c44 | 97 | 3 | 2 | 3 | 1 | 5 | 0 |
| io_09 | InteractionObject -[destroyItemType] | 0x005f6620 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_10 | InteractionObject -[flipped] | 0x005f7674 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| io_11 | InteractionObject -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:] | 0x005f4234 | 256 | 4 | 4 | 4 | 1 | 10 | 8 |
| io_12 | InteractionObject -[initWithWorld:dynamicWorld:cache:netData:] | 0x005f4bb4 | 102 | 2 | 1 | 4 | 1 | 2 | 2 |
| io_13 | InteractionObject -[interactionObjectCreationNetData] | 0x005f58c0 | 148 | 3 | 1 | 5 | 0 | 5 | 8 |
| io_14 | InteractionObject -[interactionObjectType] | 0x005f66ec | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_15 | InteractionObject -[interactionRenderItemType] | 0x005f6658 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_16 | InteractionObject -[isDoubleHeight] | 0x005f6604 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_17 | InteractionObject -[isInUse] | 0x005f7638 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| io_18 | InteractionObject -[isPaintable] | 0x005f7594 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_19 | InteractionObject -[ownerName] | 0x005f76b0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| io_20 | InteractionObject -[paint:] | 0x005f75b0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| io_21 | InteractionObject -[remoteBlockheadRemovedWithID:] | 0x005f6de4 | 81 | 1 | 1 | 4 | 0 | 1 | 4 |
| io_22 | InteractionObject -[remoteUpdate:] | 0x005f6784 | 408 | 8 | 2 | 8 | 1 | 12 | 23 |
| io_23 | InteractionObject -[remove:] | 0x005f6674 | 30 | 0 | 0 | 2 | 0 | 0 | 3 |
| io_24 | InteractionObject -[requiresHumanInteraction] | 0x005f6f28 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_25 | InteractionObject -[requiresPhysicalBlock] | 0x005f5dc8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_26 | InteractionObject -[setPaused:] | 0x005f7314 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_27 | InteractionObject -[setProxyObjectOwner:] | 0x005f7384 | 38 | 1 | 1 | 1 | 0 | 1 | 1 |
| io_28 | InteractionObject -[shouldAddToMacroBlock] | 0x005f732c | 22 | 0 | 0 | 1 | 0 | 0 | 0 |
| io_29 | InteractionObject -[startInteractionWithBlockhead:] | 0x005f6394 | 156 | 6 | 1 | 6 | 0 | 6 | 3 |
| io_30 | InteractionObject -[title] | 0x005f6708 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| io_31 | InteractionObject -[twoBlocksWide] | 0x005f663c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| io_32 | InteractionObject -[updateNetDataForClient:] | 0x005f5b10 | 56 | 2 | 1 | 0 | 1 | 3 | 2 |

## Findings (E146)

- **The InteractionObject batch lands**: 33 bodies / 2,146 words / 73 branches / 64 call rows of `InteractionObject` (DynamicObject subclass, instance_size 97; Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). Implementation span 0x5f4234..0x5f76f4 (targets are ordered by selector name, not by address; the 33 IMPs are interleaved with other functions of the same TU, e.g. `classForInteractionObjectType` which owns the symbol the io_30/io_00 listings sit under); roster names io_00..io_32, 0 collisions, 7 bodies TRIMMED at the next IMP (io_09/14/16/17/20/31/32, boundary case 2). Grades: **no body >1000w**, io_22 [census-lite] (408w, decoded fully anyway), 32 bodies <=300w fully read. Mechanical layer regenerated this run: `gen_listings.py` (`bodies 33 words 2146`, entrypoint-warning lines only) + `build_specs.py` (33 bodies, 64 call rows, 6 routes). Row count == word count for every body (no dropped listing rows).

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | io_00 | `InteractionObject -[actionTitle]` | 19 | 0 | 1 | read |
  | io_01 | `InteractionObject -[blockheadUnloaded:]` | 94 | 4 | 2 | read |
  | io_02 | `InteractionObject -[blockheadWouldLikeToTakeOwnership:withSaveDict:]` | 198 | 4 | 8 | read |
  | io_03 | `InteractionObject -[blockheadsLoaded]` | 219 | 10 | 7 | read |
  | io_04 | `InteractionObject -[canBeUsedByBlockhead:]` | 39 | 1 | 0 | read |
  | io_05 | `InteractionObject -[canBeUsedInExpertModeWhenNotOwned]` | 7 | 0 | 0 | read |
  | io_06 | `InteractionObject -[creationNetDataForClient:]` | 21 | 0 | 1 | read |
  | io_07 | `InteractionObject -[currentBlockhead]` | 17 | 0 | 0 | read |
  | io_08 | `InteractionObject -[dealloc]` | 97 | 0 | 5 | read |
  | io_09 | `InteractionObject -[destroyItemType]` | 7 | 0 | 0 | read |
  | io_10 | `InteractionObject -[flipped]` | 15 | 0 | 0 | read |
  | io_11 | `InteractionObject -[initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:]` | 256 | 8 | 10 | read |
  | io_12 | `InteractionObject -[initWithWorld:dynamicWorld:cache:netData:]` | 102 | 2 | 2 | read |
  | io_13 | `InteractionObject -[interactionObjectCreationNetData]` | 148 | 8 | 5 | read |
  | io_14 | `InteractionObject -[interactionObjectType]` | 7 | 0 | 0 | read |
  | io_15 | `InteractionObject -[interactionRenderItemType]` | 7 | 0 | 0 | read |
  | io_16 | `InteractionObject -[isDoubleHeight]` | 7 | 0 | 0 | read |
  | io_17 | `InteractionObject -[isInUse]` | 15 | 0 | 0 | read |
  | io_18 | `InteractionObject -[isPaintable]` | 7 | 0 | 0 | read |
  | io_19 | `InteractionObject -[ownerName]` | 17 | 0 | 0 | read |
  | io_20 | `InteractionObject -[paint:]` | 17 | 0 | 0 | read |
  | io_21 | `InteractionObject -[remoteBlockheadRemovedWithID:]` | 81 | 4 | 1 | read |
  | io_22 | `InteractionObject -[remoteUpdate:]` | 408 | 23 | 12 | census-lite |
  | io_23 | `InteractionObject -[remove:]` | 30 | 3 | 0 | read |
  | io_24 | `InteractionObject -[requiresHumanInteraction]` | 7 | 0 | 0 | read |
  | io_25 | `InteractionObject -[requiresPhysicalBlock]` | 7 | 0 | 0 | read |
  | io_26 | `InteractionObject -[setPaused:]` | 6 | 0 | 0 | read |
  | io_27 | `InteractionObject -[setProxyObjectOwner:]` | 38 | 1 | 1 | read |
  | io_28 | `InteractionObject -[shouldAddToMacroBlock]` | 22 | 0 | 0 | read |
  | io_29 | `InteractionObject -[startInteractionWithBlockhead:]` | 156 | 3 | 6 | read |
  | io_30 | `InteractionObject -[title]` | 12 | 0 | 0 | read |
  | io_31 | `InteractionObject -[twoBlocksWide]` | 7 | 0 | 0 | read |
  | io_32 | `InteractionObject -[updateNetDataForClient:]` | 56 | 2 | 3 | read |

- **What the class is**: InteractionObject is the base class of every placeable interaction object (Chest/Workbench/Window/Torch/DropBear-cage family all subclass it). This batch is the class's own 33 methods: 19 of them are one-line defaults (io_05/14/15/16/17/18/24/25/26/28/30/31 + accessors), 6 are lifecycle/net, and the rest are the ownership/interaction protocol. Ivar table (all offsets confirmed against class_metadata): currentBlockhead@56 / shader@60 / texture@64 / isInUse@68(c) / flipped@69(c) / remoteBlockheadInUseUniqueID@72(Q) / savedBlockheadIndex@80(i) / ownerName@84 / paintColor@88(S) / proxyObjectOwner@92 / needsToBeRemovedWhenInteractionEnds@96(c); plus DynamicObject's isNet@52 / updateNeedsToBeSent@49 / needsRemoved@48 / pos@16 / world@4 / dynamicWorld@8 / ownerID@36.
- **Defaults / constants**: `interactionObjectType` = 0 (io_14, uxth), `destroyItemType` = 0 (io_09), `interactionRenderItemType` = 1 (io_15), `canBeUsedInExpertModeWhenNotOwned` = YES (io_05), `isDoubleHeight` = NO, `isPaintable` = NO, `requiresHumanInteraction` = NO, `requiresPhysicalBlock` = NO, `twoBlocksWide` = NO (all sxtb of movw), `setPaused:` is a **complete no-op** (io_26, arg stored to stack only), `title` = **@""** (io_30 returns static CFString @0x00F7E248, flags 0x7c8 len 0), and `actionTitle` (io_00) is just `return [self title]`. Subclasses override these to give each object its type id/title/render item.
- **Ownership / interaction protocol**: `canBeUsedByBlockhead:` (io_04) = `isInUse ? (currentBlockhead == bh) : YES`. `startInteractionWithBlockhead:` (io_29): sets `isInUse = YES`, then `if (currentBlockhead != bh) { [currentBlockhead release]; currentBlockhead = [bh retain]; }`, then `if (proxyObjectOwner) [proxyObjectOwner childNeedsSaving:self] else [[self.dynamicWorld] dynamicWorldChangedAtPos:self.pos objectType:[self objectType]]`, sets `updateNeedsToBeSent = 1` and finishes with `[self.currentBlockhead setInteractionObject:self]`. `blockheadWouldLikeToTakeOwnership:withSaveDict:` (io_02) is the same shape plus a leading `if (currentBlockhead != nil) return;` guard and a trailing `[[self.world uiManager] blockhead:bh tookOwnershipOfInteractionObject:self]` notification (its saveDict arg is never read in the body).
- **Interaction teardown**: `blockheadUnloaded:` (io_01) releases/nils currentBlockhead, clears isInUse, then `if (!isNet && needsToBeRemovedWhenInteractionEnds) [self remove:0]`. `remoteBlockheadRemovedWithID:` (io_21) XOR-pair compares the incoming 64-bit ID against `remoteBlockheadInUseUniqueID@72`, clears isInUse, calls `[self remove:0]` under the same `!isNet && needsToBeRemovedWhenInteractionEnds` gate, then zeroes the ID. `blockheadsLoaded` (io_03) resolves the pending `savedBlockheadIndex@80` (only when != -1, bounds-checked against `[[self.dynamicWorld blockheads] count]`) into a retained currentBlockhead, sets the index to -1, re-links the blockhead via `setInteractionObject:` if in use, and at the end clears `isInUse` when there is neither a currentBlockhead nor a remote-blockhead ID.
- **Net blob protocol** (`InteractionObjectCreationNetData`, tsv `{DynamicObjectNetData=QIIC[7C]}QSCCS[2C]` = 0x28 bytes): writer io_13 (sret) copies `[self dynamicObjectNetData]` (0x18) then fills +0x20 u16 `interactionObjectType`, +0x22 `isInUse`, +0x23 `flipped`, +0x24 u16 `paintColor`, and +0x18 Q `uniqueID` = `isInUse ? (currentBlockhead ? [currentBlockhead uniqueID] : remoteBlockheadInUseUniqueID) : 0`. Reader io_12 (net ctor) gets 0x28 bytes and applies +0x18 Q -> remoteBlockheadInUseUniqueID, +0x22 -> isInUse, +0x23 -> flipped, +0x24 -> paintColor. io_32 wraps io_13 in `[NSData dataWithBytes:... length:0x28]` and io_06 is a pure forward to io_32. Placement ctor io_11 (9 args, atPosition passed as 2 stack words) supers `initWithWorld:dynamicWorld:atPosition:cache:`, then sets flipped, `ownerName = clientName ? [clientName retain] : [[saveDict objectForKey:@"ownerName"] retain]`, `ownerID = placedByClient ? [placedByClient retain] : (x = [saveDict objectForKey:@"ownerID"]; x ? [x retain] : leave untouched)`, `paintColor = (u16)[[saveDict objectForKey:@"paintColor"] unsignedIntValue]` (keys = CFStrings @0xF7E1C8/D8/E8).
- **remoteUpdate: (io_22, the batch's heaviest)**: supers, snapshots old isInUse, reads the 0x28-byte blob, stores the new isInUse. If **both new and old** isInUse are set and `[self.currentBlockhead uniqueID] != blob.uniqueID(+0x18)`, it kicks the local holder: `[currentBlockhead stopInteracting]`, `[currentBlockhead release]`, currentBlockhead = nil, isInUse = YES. If `isInUse && !currentBlockhead`, it stores `blob.uniqueID` into remoteBlockheadInUseUniqueID; uid==0 -> `{isInUse = NO; updateNeedsToBeSent = YES}`, else it fast-enumerates `[self.dynamicWorld blockheads]` and, on a blockhead whose `uniqueID` equals the stored uid, clears `{remoteBlockheadInUseUniqueID = 0; isInUse = NO; updateNeedsToBeSent = YES}` (no break; 0x10-per-batch NSFastEnumeration with the objc_enumerationMutation guard). Tail (always reached): `if (!isInUse && !isNet && needsToBeRemovedWhenInteractionEnds) [self remove:0]`, then `paintColor = blob+0x24` unconditionally. Blob fields NOT applied by this reader: flipped (+0x23) and interactionObjectType (+0x20).
- **dealloc / proxy / macro block**: io_08 releases `ownerID`, `ownerName`, `currentBlockhead` and calls `objc_msgSendSuper2(&super{self, InteractionObject}, @selector(dealloc))` - proxyObjectOwner/shader/texture untouched, no ivar nil-ing. io_27 `setProxyObjectOwner:` = `if (owner) [self removeFromMacroBlock]; self.proxyObjectOwner = owner` (plain store, no retain/release), and io_28 `shouldAddToMacroBlock` = `proxyObjectOwner == nil` - consistent pair: only proxy-free objects live in macro-block data.
- **`remove:` (io_23) is a stub in this class**: the compiled body only reads `DynamicObject.needsRemoved@48` (nonzero -> return) and `isNet@52` (zero -> return) and then returns; there is no store, no call, no super. The concrete removal lives in subclasses - cross-ref (read-only) `Chest -[remove:]` ce_32 @0xcbd2ac (158w) has the same guard shape with a real tail (stopInteracting / needsToBeRemovedWhenInteractionEnds=1 / removeTileAtWorldX:... / setNeedsRemoved:1). All in-batch callers of `[self remove:0]` (io_01/io_21/io_22) gate it on `!isNet && needsToBeRemovedWhenInteractionEnds`.
- **Mechanism notes**: every ivar access is the Apportable two-level unloc chain (pool cell -> GOT slot -> offset word -> `self+offset`), resolved by build_specs and cross-checked against class_metadata; **no out-of-table ivar cell appears in the batch**. There are **no VFP instructions anywhere** in this batch (no vldr/vmov/vstr), so all pool words are pointer/PIC cells and every quoted string was resolved by direct ELF struct reads at the computed object address (PIC base 0x0105FAF4 + signed pool word, add-pc pairing self-checked against the known DropBear speciesName computation).

## Boundaries

- **Grades**: no body in this batch exceeds 1000 words, so there is **no [census] body**; io_22 (408w) carries the [census-lite] grade by the size rule but was nevertheless read instruction-by-instruction (all 23 branches and 12 call rows traced); the other 32 bodies are <=300w and fully read. The class's real per-tick weight is outside this batch (see "Out-of-batch" below).
- **Trimmed bodies (7)**: io_09, io_14, io_16, io_17, io_20, io_31, io_32 end at the next ObjC IMP, not at the ARM.exidx bound (boundary case 2; e.g. io_32's exidx end 0x5f5c44 vs body end 0x5f5bf0). All other 26 bodies ended on exidx bounds. Listing rows == word count for all 33 bodies (verified programmatically), so no rows were lost in any body.
- **io_23 `remove:`**: reported strictly as compiled (two guard loads, both arms converge to the epilogue, empty tail). The compiler keeps the loads because the source condition exists, but the base-class body is observably empty - intent beyond the guard is not inferable from this body, and the Chest cross-reference (ce_32) is quoted from the earlier E139 batch, not re-derived here.
- **io_02 dead argument**: `withSaveDict:` (r3) is spilled to `[fp,-0x20]` and never reloaded anywhere in the 198w body - recorded as "arg unused in this body" rather than "the method has no dict concept" (the subclass overrides may use it).
- **io_22 client/server semantics**: the takeover block (kick local currentBlockhead when the blob uid differs), the `remoteBlockheadInUseUniqueID` placeholder write, and the blockheads-scan clearing are mechanical transcriptions; which side (client vs server, local vs remote player) drives which branch is not runtime-verified. The fast-enumeration scaffolding (state at fp-0x88, objects buffer sp+0x78, count 0x10, `objc_enumerationMutation` guard, the state+8 items-pointer cache idioms at 0x5f6b30-0x5f6b88) is compiler-generated boilerplate; only the loop *body* semantics are claimed. `[b uniqueID]`'s 64-bit return convention (r0 lo / r1 hi) is inferred from the XOR pairing with the stored Q.
- **Out-of-batch neighbours** (pre-covered by earlier evidence, NOT claimed decoded here): `-[initWithWorld:dynamicWorld:saveDict:cache:]` (0x5f4634), `-[getSaveDict]` (0x5f50b8), `-[update:accurateDT:isSimulation:]` (0x5f5de4) are the only InteractionObject methods missing from this batch - the per-tick consumption/normalisation of isInUse/currentBlockhead/remoteBlockheadInUseUniqueID (e.g. who else clears the remote UID, when savedBlockheadIndex is written) is expected there.
- **Cross-class receivers were not traced**: `childNeedsSaving:`, `dynamicWorldChangedAtPos:objectType:`, `uiManager`, `blockhead:tookOwnershipOfInteractionObject:`, `stopInteracting`, `setInteractionObject:`, `uniqueID`, `blockheads`, `countByEnumeratingWithState:...`, `removeFromMacroBlock` are call *targets* on other classes (Blockhead/DynamicWorld/World/UI manager) - only the selector and argument routing are evidence here, their implementations are not part of this batch.
- **No VFP / no float constants**: the whole batch contains zero vector-register instructions, so the "VFP immediate truth via _gl.txt" convention is vacuous here; conversely, string/const truth was taken from direct ELF word reads (CFString struct {isa(0 in file), flags 0x7c8, cstr, len}) with the add-pc pairing verified against a known-good case (DropBear speciesName -> 0xF907F8). r2's pool-row disassembly was not used for any value statement.
- **Struct/field naming**: the `InteractionObjectCreationNetData` layout is pinned by the tsv type string and the writer/reader offsets (+0x18 Q, +0x20 S, +0x22 C, +0x23 C, +0x24 S, +0x26 [2C] pad); field *names* for DynamicObject's part (isNet/updateNeedsToBeSent/needsRemoved/ownerID) come from class_metadata, the offsets are confirmed by the unloc cells. Whether +0x26 char[2] is meaningful padding is not resolvable from this batch (never read/written by any batch body).
- Static level-A evidence only (r2 pD + GNU objdump + ELF struct reads + tsv type strings + class_metadata): no runtime roundtrip, no device-side claims.
