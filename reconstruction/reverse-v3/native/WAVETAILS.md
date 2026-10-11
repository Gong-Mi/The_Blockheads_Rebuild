# WaveTails (E153)

The wave-tails sweep lands: the objectType/getSaveDict/update: ticks that the coverage crosswalk silently skipped across twelve wave classes. 28 bodies, 42012 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wtx_00 | Boat -[objectType] | 0x0096b52c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| wtx_01 | Boat -[update:accurateDT:isSimulation:] | 0x0096de60 | 2233 | 14 | 2 | 24 | 0 | 74 | 109 |
| wtx_02 | Chest -[objectType] | 0x00cb4ec4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| wtx_03 | Chest -[getSaveDict] | 0x00cb95b0 | 34 | 1 | 1 | 1 | 0 | 1 | 0 |
| wtx_04 | Chest -[update:accurateDT:isSimulation:] | 0x00cbc4f0 | 133 | 2 | 2 | 7 | 1 | 2 | 7 |
| wtx_05 | ClownFish -[getSaveDict] | 0x0078e76c | 31 | 1 | 1 | 0 | 1 | 1 | 0 |
| wtx_06 | ClownFish -[update:accurateDT:isSimulation:] | 0x00797300 | 4153 | 32 | 4 | 53 | 2 | 130 | 266 |
| wtx_07 | Dodo -[getSaveDict] | 0x00a6bb04 | 31 | 1 | 1 | 0 | 1 | 1 | 0 |
| wtx_08 | Dodo -[update:accurateDT:isSimulation:] | 0x00a781c8 | 6542 | 48 | 8 | 76 | 5 | 267 | 351 |
| wtx_09 | DropBear -[update:accurateDT:isSimulation:] | 0x007ab240 | 6542 | 58 | 14 | 86 | 5 | 257 | 372 |
| wtx_10 | FreeBlock -[objectType] | 0x00625fe8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| wtx_11 | FreeBlock -[getSaveDict] | 0x00629804 | 814 | 12 | 14 | 11 | 3 | 40 | 15 |
| wtx_12 | FreeBlock -[update:accurateDT:isSimulation:] | 0x0062bfe8 | 3583 | 27 | 5 | 28 | 1 | 184 | 220 |
| wtx_13 | FreightCar -[objectType] | 0x00a3f85c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| wtx_14 | FreightCar -[getSaveDict] | 0x00a40940 | 31 | 1 | 1 | 0 | 1 | 1 | 0 |
| wtx_15 | FreightCar -[update:accurateDT:isSimulation:] | 0x00a41860 | 3996 | 25 | 2 | 40 | 1 | 240 | 168 |
| wtx_16 | InteractionObject -[objectType] | 0x005f4218 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| wtx_17 | InteractionObject -[update:accurateDT:isSimulation:] | 0x005f5de4 | 364 | 8 | 1 | 8 | 0 | 13 | 15 |
| wtx_18 | Scorpion -[getSaveDict] | 0x00894080 | 31 | 1 | 1 | 0 | 1 | 1 | 0 |
| wtx_19 | Scorpion -[update:accurateDT:isSimulation:] | 0x008a45f0 | 6737 | 54 | 11 | 85 | 4 | 237 | 378 |
| wtx_20 | Shark -[getSaveDict] | 0x007c8c34 | 31 | 1 | 1 | 0 | 1 | 1 | 0 |
| wtx_21 | Shark -[update:accurateDT:isSimulation:] | 0x007d6470 | 6103 | 48 | 12 | 78 | 5 | 189 | 369 |
| wtx_22 | Sign -[objectType] | 0x005f9ae4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| wtx_23 | Sign -[update:accurateDT:isSimulation:] | 0x005fca18 | 54 | 1 | 1 | 1 | 1 | 1 | 2 |
| wtx_24 | TradingPost -[objectType] | 0x005e48f8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| wtx_25 | TradingPost -[initSlotsWithSaveDict:] | 0x005e4914 | 243 | 8 | 2 | 2 | 2 | 12 | 9 |
| wtx_26 | TradingPost -[initWithWorld:dynamicWorld:saveDict:cache:] | 0x005e5718 | 223 | 6 | 6 | 4 | 1 | 11 | 3 |
| wtx_27 | TradingPost -[update:accurateDT:isSimulation:] | 0x005ebe98 | 54 | 1 | 1 | 1 | 1 | 1 | 2 |

## Findings (E153)

- **The wave-tails batch lands**: 28 bodies / 42,012 words / 2815 branch rows / 1664 call rows of 12 classes (Boat, Chest, ClownFish, Dodo, DropBear, FreeBlock, FreightCar, InteractionObject, Scorpion, Shark, Sign, TradingPost — Apportable offset-cell binary, pinned ELF sha256 733d8210...30b94c7). These are exactly the tail methods the E139–E152 class waves left behind: every class's `objectType`, the animal `getSaveDict`/`update:accurateDT:isSimulation:` pair, plus the four TradingPost methods E151 missed. Mechanical layer regenerated this run: `gen_listings.py --allow-existing` ("bodies 28 words 42012") + `build_specs.py` (28 bodies / 1664 call rows / 51 routes). Each header IMP == tsv IMP and rows == words for every body (verified programmatically: 28/28, 0 mismatches). Grades: **8 [census]** (>1000w): wtx_19 (6737), wtx_08 (6542), wtx_09 (6542), wtx_21 (6103), wtx_06 (4153), wtx_15 (3996), wtx_12 (3583), wtx_01 (2233); **2 [census-lite]**: wtx_11 (814), wtx_17 (364); **18 read** (<=243w, all fully read).

| name | method | words | branches | calls | grade |
|---|---|---|---|---|---|
| wtx_00 | `Boat -[objectType]` | 7 | 0 | 0 | read |
| wtx_01 | `Boat -[update:accurateDT:isSimulation:]` | 2233 | 109 | 74 | census |
| wtx_02 | `Chest -[objectType]` | 7 | 0 | 0 | read |
| wtx_03 | `Chest -[getSaveDict]` | 34 | 0 | 1 | read |
| wtx_04 | `Chest -[update:accurateDT:isSimulation:]` | 133 | 7 | 2 | read |
| wtx_05 | `ClownFish -[getSaveDict]` | 31 | 0 | 1 | read |
| wtx_06 | `ClownFish -[update:accurateDT:isSimulation:]` | 4153 | 266 | 130 | census |
| wtx_07 | `Dodo -[getSaveDict]` | 31 | 0 | 1 | read |
| wtx_08 | `Dodo -[update:accurateDT:isSimulation:]` | 6542 | 351 | 267 | census |
| wtx_09 | `DropBear -[update:accurateDT:isSimulation:]` | 6542 | 372 | 257 | census |
| wtx_10 | `FreeBlock -[objectType]` | 7 | 0 | 0 | read |
| wtx_11 | `FreeBlock -[getSaveDict]` | 814 | 15 | 40 | census-lite |
| wtx_12 | `FreeBlock -[update:accurateDT:isSimulation:]` | 3583 | 220 | 184 | census |
| wtx_13 | `FreightCar -[objectType]` | 7 | 0 | 0 | read |
| wtx_14 | `FreightCar -[getSaveDict]` | 31 | 0 | 1 | read |
| wtx_15 | `FreightCar -[update:accurateDT:isSimulation:]` | 3996 | 168 | 240 | census |
| wtx_16 | `InteractionObject -[objectType]` | 7 | 0 | 0 | read |
| wtx_17 | `InteractionObject -[update:accurateDT:isSimulation:]` | 364 | 15 | 13 | census-lite |
| wtx_18 | `Scorpion -[getSaveDict]` | 31 | 0 | 1 | read |
| wtx_19 | `Scorpion -[update:accurateDT:isSimulation:]` | 6737 | 378 | 237 | census |
| wtx_20 | `Shark -[getSaveDict]` | 31 | 0 | 1 | read |
| wtx_21 | `Shark -[update:accurateDT:isSimulation:]` | 6103 | 369 | 189 | census |
| wtx_22 | `Sign -[objectType]` | 7 | 0 | 0 | read |
| wtx_23 | `Sign -[update:accurateDT:isSimulation:]` | 54 | 2 | 1 | read |
| wtx_24 | `TradingPost -[objectType]` | 7 | 0 | 0 | read |
| wtx_25 | `TradingPost -[initSlotsWithSaveDict:]` | 243 | 9 | 12 | read |
| wtx_26 | `TradingPost -[initWithWorld:dynamicWorld:saveDict:cache:]` | 223 | 3 | 11 | read |
| wtx_27 | `TradingPost -[update:accurateDT:isSimulation:]` | 54 | 2 | 1 | read |

- **The objectType table is confirmed 7/7**: wtx_00 Boat=32, wtx_02 Chest=46, wtx_10 FreeBlock=14, wtx_13 FreightCar=43, wtx_16 InteractionObject=15, wtx_22 Sign=47, wtx_24 TradingPost=48 - each a 7-word `movw r2,<const>; mov r0,r2; bx lr` stub, byte-identical shape, IMPs matching the checked-in `dynamicobject_type_objecttype_matrix.json` rows exactly (independent cross-validation; the matrix already listed these IMPs, this batch supplies the listings).

- **getSaveDict tails**: the five animal overrides (wtx_05 ClownFish / wtx_07 Dodo / wtx_14 FreightCar / wtx_18 Scorpion / wtx_20 Shark) are byte-identical 31-word pure super-forwards `objc_msgSendSuper2({self, <Class>}, @selector(getSaveDict))` with zero ivar reads - all animal persistence flows through the NPC/base save dict. wtx_03 Chest is the one conditional: `return [self getSaveDictIncludingInventory:(chestType@108 != 4)]` (portal chests excluded from the inventory blob). wtx_11 FreeBlock rebuilds the full item save dict on top of super (12 keys, see semantics).

- **Fixed-object ticks**: wtx_04 Chest update = needsRemoved guard + `[super update:]` + client-side idle-inventory release (`currentBlockhead==nil && isNet && !inventoryNeedsToBeSentWithUpdate && proxyObjectOwner==nil && chestType!=4 -> [inventoryItems release]; inventoryItems=nil`). wtx_17 InteractionObject update = the interaction teardown tick with NO super call: two passes (a needsRemoved current blockhead; and a stale local non-interacting one) both releasing/nil'ing currentBlockhead, zeroing isInUse@68, notifying `childNeedsSaving:` (proxyObjectOwner) or `dynamicWorldChangedAtPos:objectType:`, setting updateNeedsToBeSent@49 and conditionally `[self remove:nil]` under needsToBeRemovedWhenInteractionEnds@96. wtx_23 Sign update and wtx_27 TradingPost update are both needsRemoved-guarded pure `[super update:...]` forwards (54w each) - so Sign/TradingPost tick work is entirely their super's.

- **The TradingPost quartet** (the 4 methods E151 explicitly missed): wtx_24 objectType=48; wtx_25 `initSlotsWithSaveDict:` = sellSlot@100 = new NSMutableArray; fast-enumerate saveDict[@"sellSlot"], skip itemType 0xb, `[[InventoryItem alloc] initWithSaveData:]` + autorelease + addObject; needsToUpdateBitmapString@124=1 at exit (bit-exact match with the repo's executed b4j Unicorn differential, `tools/test_trading_post_init_slots_arm.py`). wtx_26 `initWithWorld:dynamicWorld:saveDict:cache:` = super 4-arg -> nil->nil; **legacy ownerID fallback**: `if (ownerID@36 == nil) ownerID = [[saveDict objectForKey:@"sellerClientID"] retain]` (the cf. chest 'safeClientID' migration pattern); then sellerClientName@112 (retained), coinCount@104 / priceTier@108 via `integerValue` of saveDict keys; `[self initSlotsWithSaveDict:saveDict]`; `[self initSubDerivedItems]`.

- **The eight update: giants** (census; see semantics for send tables): they are the missing consumers/producers the earlier waves deferred - wtx_06 ClownFish and wtx_09 DropBear both contain the **4-slot net-queue consumer** (shift nextToSquare/nextWalkSpeed/nextMovementDirection [ClownFish] and nextToSquare/nextWalkSpeed/nextOnGround [DropBear] left while currentNetQueueSize>0), exactly as E144/E145 predicted; wtx_08 Dodo holds the egg-lay producer (`dict{breed, genesDict} -> fillTile:atPos:...` + eggLay.wav) and the breeding trio (canMate / npcCloseEnoughToBreedWithNPC: / mateWithNPC:); wtx_19 Scorpion and wtx_21 Shark carry the damage+kill-report blocks (`sufferDamage:...recoil:` with force*4 in sim, `stringWithFormat:@"%@ by a <species>"` + killed/attacked -> addSimulationEventOfType:forBlockhead:extraData:) and their combat timers (spit projectile fireItemType 0xff / bite+drown), plus spawn gates (getDayNightFractionForAtWorldTime, npcExistsAtPos:ignoreNPC:, tutorialActive / expertMode); wtx_01 Boat runs the run-aground destruction into freeblock itemType 0x6f with `priorityBlockhead:rider`; wtx_15 FreightCar is a Vector2-heavy rail-physics tick (101+21 operator float* calls, getRailAtPos:, wheel vel/pos/rail samplers, trainCarWithID: re-linking); wtx_12 FreeBlock is the dropped-item physics tick (fall/bounce, wind drift via xVelocityWater@120 + [world windStrength], door/trapdoor/lava probes incl. hitLava x4, and the local pickup sweep `pickupFreeblockIfPossible:inTile:intentional:` over localAndDisconnectedClientBlockheads with pickupGem.wav/littlePop.wav).

- **Recurring wire/blocks patterns cross-checked against the earlier batches**: shark scorpion/splash/jaws sounds with the 0.7+0.6*(1-age/maxAge) pitch curve (Shark) and scorpion.wav; unreliableUpdateNeedsToBeSent@51 usage concentrated in ClownFish (x11) / Dodo (x5) / Scorpion (x4); all species ticks touch the shared NPC locomotion fields (toSquare/fromSquare/travelFraction/movementDirection/walkSpeed) and the shared tile predicates (tileIsSolid/tileIsWater/tileIsAirOrSnow/tileContainsGate).

## Boundaries

- **Name collisions (E108)**: 10 of the 28 names (wtx_00..wtx_09) collide with the checked-in E108 (bh-world-trade) `disasm_worldtileloader_wtx_*.txt` files in native/. Generation therefore ran with `--allow-existing` (the same escape hatch replay_e103.py uses for regeneration); the batch writes ONLY into its own directory - nothing checked in was touched. The collision is purely nominal (E108's wtx_00..09 are World trade-price methods, different IMPs/bodies). **Delivery hazard to flag upstream**: `make_deliverables.py` copies `<name>.txt -> NATIVE/<disasm>`, so checking this batch in as-is would overwrite E108's files - the orchestrator should rename the disasm targets of wtx_00..wtx_09 (or E108's) before check-in; the batch-internal duplicate-name check passed (28 unique).
- **Census-grade bodies** (structure + send table + branch skeleton + strings + constants + anchor windows, not per-instruction reads): the eight >1000w update: ticks. Their straight-line float/vector stretches are summarised (phase sites + ivar/call tables above), and local helper subroutines just past the body ends (Boat 0x970144; Shark 0x7dc46c/0x7dc3cc; Scorpion 0x8aaf34; Dodo 0xa7e800/0xa7e83c/0xa7e968; DropBear 0x7b1878; FreeBlock 0x62/63xx family) are characterised by call site only. wtx_11 (814w) and wtx_17 (364w) are census-lite but were read instruction-by-instruction.
- **Dodo update: IMP discrepancy**: the tsv + listing pin `Dodo -[update:accurateDT:isSimulation:]` at 0xa781c8..0xa7e800 (body), while E141's DODO.md cites "update: @0xa7ea40" as the caller of the 0xa80ab8 egg-remap table (address lies past this body's end, between body and maxHealth@0xa7f11c). The egg-remap claim itself is left as E141 recorded it; this batch did not find a bl to 0xa80ab8 inside the update body (the body's post-body helper calls are 0xa7e800 x6 / 0xa7e83c x1 / 0xa7e968 x1).
- **Reading conventions / truth sources**: VFP immediates quoted from the `_gl.txt` GNU listings only (r2 pool-row comments mislabel bare literals as PIC cells; the r2 `[0x...:4]=` cell annotations were resolved through specs_wavetails.json: selector/ivar/class/import routes, and CFString contents were read from the ELF CFConstantString structs at the resolved slots - object key strings for wtx_11/wtx_25/wtx_26 were paired this way). Pool words read by direct ELF struct.unpack (file offset == vaddr). PIC base recomputed per body = 0x0105FAF4. Row counts == word counts for all 28 listings; 0 listing rows dropped.
- **Cross-batch claims not re-derived here**: the objectType ids are cross-validated against the checked-in E-matrix; the super-forward getSaveDict targets (NPC/base serialization), the plist/queue helpers shared with E139–E152, and the wire-struct field names (other than the SaveDict keys quoted above) stay at their earlier-batch evidence level. No runtime/device probes were run; static level-A evidence only (r2 pD + GNU objdump + ELF struct reads + tsv types + class_metadata + specs_wavetails.json).
- **Scope**: exactly the 28 wtx_* targets in targets.json; no make_deliverables call, no repo writes; batch directory only (`_work/` holds the analysis scripts: analyze.py, giant.py, notes.md).
