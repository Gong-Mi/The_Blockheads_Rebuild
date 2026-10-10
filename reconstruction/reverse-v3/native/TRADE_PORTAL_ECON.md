# TradePortal economics batch (E9b) — pricing, coin swaps, upgrade, crystal gating

Part 2 of 2 of the trade portal (DynamicObject objectType 0x32). All 14 bodies
below are statically recovered from the SHA-256-pinned original
`libApplication.so` (1.7.6, armeabi-v7a, `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`)
and re-verified word by word by `tools/recover_trade_portal_econ.py`
(14 bodies, 3573 instruction words). The artifact is
`native/trade_portal_econ.json`; the tool refuses to emit when any instruction
word, PIC-base literal, cell target, call target or branch destination drifts.

The batch covers the trade economics: the price-offset dictionary
(`loadPriceOffsets:`, `randomizeLocalTradeOffsets`), the current-blockhead
accessors, the two settlement paths (`sellItem:atTotalPrice:count:usageMultiplier:`,
`buyItem:atTotalPrice:count:`), the level upgrade and its particle burst
(`upgradeToNextLevel`), the craftable-item table (`upgradeCraftableItem`) and its
consumer (`takeItemsFromBlockheadForUpgradeToNextLevel`), plus the portal's
`worldChanged:` re-check and the two interaction flags.

## Price offsets

`loadPriceOffsets:` (0x00d37a78, 197w) fast-enumerates the argument dictionary
(0x20-byte NSFastEnumeration state memset at 0xd37ae0, buffer count 0x10) and for
each key runs `[dict objectForKey:]` then `[value doubleValue]`, clamps the
double into **[0.5, 2.0]** with the VFP compare pair (`vmov.f64 0.5` at 0xd37b78,
`2.0` at 0xd37c28/0xd37c44) and writes `[NSNumber numberWithDouble:]` back with
`[self.localPriceOffsets setObject:forKey:]` (ivar@128). The enumeration guard
calls `objc_enumerationMutation`. The two clamp bounds are the same constants
that the b4i contract reconstruction pins bit-exactly in
`reconstruction/recovered/trade_portal_price_offsets.cpp`, so this listing and
that C++ contract are two independent witnesses of the same rule.

`randomizeLocalTradeOffsets` (0xd3f460, 211w) re-rolls every occupied entry of the
PIC-relative **trade table at 0x00e18ee0** (cell 0xd3f778 holds -0x246c14; entry =
table + level*0x360 + slot*0x90, level 1..8, slot 0..5, occupancy word at +0 read
at 0xd3f4fc). For a non-zero entry it calls the thunk at 0xd37798 (0xd3f540) and
computes `powf(0.8f, ((float)v / 2147483648.0f - 0.5f) * 10.0f)` with the f32 pool
constants 0x3f4ccccd = 0.8f and 0x4f000000 = 2^31 at 0xd3f7a0/0xd3f7a4 and
`__wrap_powf` at 0xd3f584; the result is wrapped with `[NSNumber numberWithFloat:]`
(NSNumber class cell 0xd3f78c, NSString 0xd3f79c) and stored into
`localPriceOffsets`@128 under `[NSString stringWithFormat: CFString@0x00fae2c8]`.
A zero occupancy word advances the slot and marks the level exhausted at slot >= 6.
The tail (0xd3f6ac) stores `self.updateNeedsToBeSent`@49 = 1 and calls
`[dynamicWorld dynamicWorldChangedAtPos:(self.pos.x, self.pos.y) objectType:objType]`.

**Correction carried by this batch (0xd37798 is not a price hash).** The E9a batch
description glossed 0xd37798 as a "portal price hash" helper. GNU objdump over the
pinned original shows it is a four-instruction thunk
(`push {fp,lr}; mov fp,sp; bl lrand48@plt; pop {fp,pc}`) — i.e. **plain
`lrand48()`**. The upgrade burst and the price re-roll both consume it as a random
number, not as a hash of portal state; the E9a prose for `remoteUpdate:` should be
read with that correction.

## Coin swaps and settlement

Both settlement entry points short-circuit on the coin item types
**{0xa6, 0xa7, 0x104, 0x444}** before any price work: `sellItem:` leaves them to
`buyItem:` (0xd3d698/0xd3d6a0/0xd3d6b4/0xd3d6c0) and `buyItem:` runs the swap
matrix itself (0xd3dd48..0xd3dd74) — 0xa6 {100 x 0xa7 -> 1 x 0xa6}, 0x104
{1 x 0xa7 -> 100}, 0x444 {1 x 0xa6 -> 100 x 0xa7}, 0xa7 {100 x 0x104 -> 1}. Each
case is gated twice: `[currentBlockhead countOfInventoryItemsOfType:includeActions:0]`
must reach the required count (0xd3de40/0xd3de90) and
`[currentBlockhead subtractItemsFromInventoryOfType:count:]` must return exactly the
required count, otherwise the body logs CFString@0xfae2f8
"Error trying to subtract coins to trade." (0xd3df18) and returns.

`sellItem:atTotalPrice:count:usageMultiplier:` (0xd3d638, 430w) starts from
`dataB = -1` (0xd3d6cc), flipping it to 0 for itemType 0x5b (0xd3d6d8/0xd3d6e0),
then `[currentBlockhead subtractItemsFromInventoryOfType:count:dataB:]` (0xd3d750)
and `[result count]` (0xd3d760); a short subtraction logs CFString@0xfae2e8
"Error trying to subtract items to sell." (0xd3dc48). Only when `isNet`@52 is clear
(0xd3d790) and `![currentBlockhead isClientBlockheadBeingControlledByServer]`
(0xd3d7d8) does it report the achievement `@"grp.trade"` (CFString 0xfae2b8) to
`self.world` (0xd3d838). The multiplier for the sold item is
`[localPriceOffsets@128[key] doubleValue]` (default 1.0 at 0xd3d864) times the
double **0.997** (0x3fefe76c8b439581 at 0xd3dc60, vmul at 0xd3d948), re-clamped to
[0.5, 2.0] and written back. The price returned by
`[self.world updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:]` (0xd3da3c) is
split into `price/10000` (magic 0x68db8bad, 0xd3da44) and `price%10000` (0x2710,
0xd3da6c), and both halves are read back with **`ldrh`**, so the freeblock carries
two 16-bit fields: `[dynamicWorld createFreeBlockAtPosition:makeIntpair(pos.x, pos.y+1)
ofType:298 (0x12a) dataA:price/10000 dataB:price%10000 subItems:0
dynamicObjectSaveDict:0 hovers:0 playSound:4 priorityBlockhead:currentBlockhead]`
(0xd3db24), then `dynamicWorldChangedAtPos:pos objectType:0x32`,
`updateNeedsToBeSent`@49 = 1 (0xd3dba0) and the `sale.wav` cue through
MJSoundManager (0xd3dc34, `afterDelay:0`).

`buyItem:atTotalPrice:count:` (0xd3dcf0, 699w) takes the priced path for every
other item type (0xd3e0cc): `cash = [currentBlockhead totalCash]` (0xd3e0d8) and
`atTotalPrice > cash` returns (0xd3e11c); the achievement gate is the same
`!isNet && !isClientBlockheadBeingControlledByServer` pair (0xd3e1a4), then
`[currentBlockhead subtractCash:atTotalPrice]` (0xd3e22c). Its multiplier is
`[localPriceOffsets[key] doubleValue] / 0.997` (0xd3e338), clamped, written back and
pushed as `updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:` with the float
**-1.0f** (0xd3e39c). `dataA = dataB = itemTypeIsSowable(itemType) ? 0x7f : 0`
(0xd3e4ac/0xd3e4bc), and the purchase creates `count` freeblocks at
`(pos.x, pos.y+1)` (0xd3e584), **skipping itemType 11** (0xd3e4e8); the tail is the
sound, `dynamicWorldChangedAtPos:pos objectType:[self objectType]` and
`updateNeedsToBeSent`@49 = 1 (0xd3e72c).

## Upgrade and the craftable-item table

`upgradeToNextLevel` (0xd3cf20, 454w) returns immediately when level@132 >= 5
(0xd3cf54) and otherwise increments it (0xd3cfa4). It plays `upgrade.wav`
(CFString 0xfae268) at `Vector2(pos.x, pos.y)` (0xd3cfdc/0xd3d03c/0xd3d058), marks
the object dirty (`dynamicWorldChangedAtPos:objectType:` at 0xd3d0c4,
`updateNeedsToBeSent`@49 = 1 at 0xd3d0dc) and emits **8 particles** (loop bound 8
at 0xd3d148) around the base Vector `(pos.x+0.5, pos.y, -0.5)` (0xd3d130): colour
Vector4 `(r*1.5+0.231373, r*1.5+0.347059, 1.0, 0.5)` (0xd3d1b4), velocity
`((r-0.5)*4, (r-0.3)*4, 0)` (0xd3d2c4), position `v0 + (r-0.5, 2r, 0)` through
`Vector::operator+` (0xd3d25c), all dispatched as
`[ParticleEmitter instance addParticleAtPos:velocity:color:gravityType:2
life:r*4+1 scale:r*4+4 center:v0]` (0xd3d438) where `r = lrand48()/2^31`
(pool 0x4f000000). The tail re-renders the trade UI
(`[[self.world uiManager] updateTradePortalUIs]`, 0xd3d4a8/0xd3d4b8) and rewrites
the portal column: when `tileAtWorldPositionLoaded(pos.x, pos.y-1, world)` is
non-nil it switches on `level-1` (0..4) through the 5-word table at 0xd3d550 and
stores `tile[0] = {0x3d, 0x3e, 0x3f, 0x40, 0x41}` (0xd3d56c) — the same tile byte
sequence the placement path writes at level 0..5 (`{0x3c..0x41}`), so the portal
column re-derives its own tile type after an upgrade.

`upgradeCraftableItem` (0xd3e7dc, 222w) **returns the CraftableItem struct by
value**. It writes the constant header `{0x84@0x00, 1@0x04, 0x0b@0x10, 1@0x28}`
(0xd3e828/0xd3e838) and, when `[world expertMode]` (0xd3e860) is non-zero, raises
the @0x28 count to 0x0a (0xd3e878). Then `switch (self.level@132)` selects one of
five cases through the jump table at 0xd3e8b8 (targets 0xd3e8cc, 0xd3e940,
0xd3e9b4, 0xd3ea30, 0xd3eab0), each writing the item at +8 and the two counts at
+0x2c/+0x30: L0 {0x57, 0x0a, 0x0a}, L1 {0x56, 0x14, 0x14}, L2 {0x4c, 0x32, 0x32},
L3 {0x4b, 1, 0x64 with 0x104@0x0c}, L4 {0x58, 0x0a, 0xc8 with 0x104@0x0c}; after
each case a second `[world expertMode]` probe overrides the count (L0 -> 0x32,
L1 -> 0x63, L2 -> 0x104@0x0c plus count 5, L3 -> 0x14, L4 -> 0x63). `level > 4`
falls through with only the header written. The consumer reveals the real record
size: `takeItemsFromBlockheadForUpgradeToNextLevel` reserves **0x7c bytes** with
`types[]` at +8, `reqCounts[]` at +0x28 and `nItems` at +0x48.

`takeItemsFromBlockheadForUpgradeToNextLevel` (0xd3eb54, 526w, BOOL) calls
`[self upgradeCraftableItem]` through `objc_msgSend_stret` into that 0x7c-byte
buffer (0xd3eba4, memset length 0x7c at 0xd3ebb0). Pass 1 walks the items and acts
only on **type 11** (0xd3ec08) when the current blockhead is not server-controlled
(0xd3ec50): it reads `[CrystalManager instance]` (0xd3ed2c) `amount`/`amountString`
(0xd3ed70) and **MD5-fingerprints** it against
`[NSString stringWithFormat:@"7acfe93afc08%dc65ae2c54ecaf07f" (0xfae308), amount]`
(0xd3ed98/0xd3eda8/0xd3edc8); a mismatch forces the amount to 0 (0xd3ee4c), and
`reqCounts[i] > amount` returns NO (0xd3ee7c). For each affordable item it calls
`[instance modify:reqCounts[i] modifyString:MD5(stringWithFormat:@"7acfe93afc08c%d65ae2c54ecaf07f"
(0xfae318), amount - reqCounts[i] + 73)]` (0xd3ef6c/0xd3efe4 — the **+73** is the
literal 0x49) and re-checks the new amountString (0xd3f104 sets the cheat flag).
Pass 2 (0xd3f130) skips type 11, subtracts the required items (0xd3f1f0) and
returns NO when `reqCounts[i] - [result count] > 0` (0xd3f238). When the cheat flag
is set the tail raises
`[[[UIApplication sharedApplication] delegate] viewController] displayInterstitialForTag:@"Hax"
(CFString 0xfae328)]` (0xd3f308).

## Current-blockhead accessors and flags

`currentBlockheadCash` (0xd3c624, 44w) is a nil-guarded `[self.currentBlockhead
totalCash]` (ivar@56 through slot 0x0105cac4; the nil path returns 0).
`currentBlockheadCountOfInventoryItemsOfType:` (0xd3c6d4, 81w) compares the item
type with 0x5b: 0x5b goes to `countOfInventoryItemsWithSpecificDataBOfType:dataB:includeActions:`
with **dataB = 0 and includeActions = 0** (0xd3c734/0xd3c788), every other type to
`countOfInventoryItemsOfType:includeActions:` with **includeActions = 0**
(0xd3c7e8). `currentBlockheadUsageMultiplierForFirstItemOfType:` (0xd3c818, 51w)
forwards the same way and answers **1.0f** (0xd3c864) when there is no blockhead.
`setPaused:` (0xd3c8e4, 53w) stores the byte into `paused`@116 (0xd3c91c) and calls
`[self.sound stop]` (MJSoundManager ivar@112, 0xd3c980) when the stored byte reads
back non-zero. `isSellInteraction` (0xd3f8f4, 15w) and `isMissionInteraction`
(0xd3f930, 15w) are bare `ldrsb` reads of the flag bytes at **@136** and **@137**
(0xd3f91c / 0xd3f958), with identical bodies apart from the ivar cell.

## worldChanged:

`worldChanged:` (0xd3a8f8, 575w) takes the changed-position vector by reference
(begin/end at *(v+0)/*(v+4), 8-byte `intpair` elements, no stret). It returns
immediately when `isNet`@52 is set (0xd3a938/0xd3a93c). Otherwise the single
delegate message is **`[self.light@100 worldChanged:changed]`** with plain
`objc_msgSend` at 0xd3a998 — the receiver is the portal's light object, not
`super` (this body imports no `objc_msgSendSuper`; the E9a-era note about a super
call is corrected here). Per element it wraps `dx = self.pos.x - cp.x` into
`[-worldWidthMacro<<5 / 2, +worldWidthMacro<<5 / 2)` using `[self.world worldWidthMacro]`
and `__aeabi_idiv` (0xd3ab18/0xd3ab88/0xd3ac00/0xd3ac70), requires `abs(dx) < 2`
(local `abs(int)` helper at 0xd3b1f4, called 0xd3acb4) and gates the y coordinate
to `cp.y == pos.y-1 || cp.y >= pos.y` (0xd3ace0/0xd3ad10). It then probes five
tiles through `tileAtWorldPositionLoaded`: the tile below (`pos.x, pos.y-1`) must be
non-nil, not solid and not half-depth, with `tile[3] != 0x60`
(0xd3ad60/0xd3ad88/0xd3adf8/0xd3ae10); the tile at the portal's own position must be
non-nil with **`tile[1] == 2`** (0xd3ae84); and the left, right and above tiles must
each be non-half-depth, `tile[3] != 0x60` and not solid (0xd3af30 .. 0xd3b094, with
no nil test). When all five pass the portal calls **`[self remove:0]`** (0xd3b148,
selector cell 0xd3b1ec) and returns.

## Anchors

| body | IMP | words | cells (sel/imp/ivar/class) | calls | branches |
|---|---|---:|---|---:|---:|
| tp_loadprice | 0x00d37a78 | 197 | 5 / 1 / 1 / 1 | 8 | 9 |
| tp_worldchanged | 0x00d3a8f8 | 575 | 3 / 1 / 4 / 0 | 26 | 34 |
| tp_cbcash | 0x00d3c624 | 44 | 1 / 1 / 1 / 0 | 1 | 2 |
| tp_cbcount | 0x00d3c6d4 | 81 | 2 / 1 / 1 / 0 | 2 | 4 |
| tp_cbusage | 0x00d3c818 | 51 | 1 / 1 / 1 / 0 | 1 | 2 |
| tp_setpaused | 0x00d3c8e4 | 53 | 1 / 1 / 2 / 0 | 1 | 1 |
| tp_upgrade | 0x00d3cf20 | 454 | 8 / 2 / 5 / 2 | 23 | 13 |
| tp_sell | 0x00d3d638 | 430 | 16 / 5 / 7 / 3 | 19 | 18 |
| tp_buy | 0x00d3dcf0 | 699 | 19 / 5 / 7 / 3 | 29 | 35 |
| tp_upgradecraft | 0x00d3e7dc | 222 | 1 / 1 / 2 / 0 | 6 | 13 |
| tp_takeitems | 0x00d3eb54 | 526 | 15 / 4 / 1 / 3 | 31 | 25 |
| tp_randomize | 0x00d3f460 | 211 | 5 / 2 / 4 / 2 | 7 | 8 |
| tp_issell | 0x00d3f8f4 | 15 | 0 / 0 / 1 / 0 | 0 | 0 |
| tp_ismission | 0x00d3f930 | 15 | 0 / 0 / 1 / 0 | 0 | 0 |

Total: **14 bodies, 3573 verified words, 154 call sites, 164 branches**, 116
selector-side cells (77 selectors + 25 imports + 14 classrefs) and 38 ivar cells.
The cell-count columns above are per kind; the JSON merges selectors, imports and
classrefs into one `selectors` map and adds a `route` field naming how each entry
was resolved (pool C string, PLT/GOT relocation, ABS32 relocation symbol, or
dynsym entry).

## Boundaries

- **Static bodies only.** Values that live in the trade table (0x00e18ee0) or in
  the blockhead/crystal objects at run time are not decoded here; the JSON claim
  string says the runtime values and the trade-table contents are outside these
  bodies.
- **Two literal-pool words misdecode as branches.** In `tp_sell` (0xd3dc60) and
  `tp_buy` (0xd3e5d8) the double 0.997 pool word disassembles as `blhi` with an
  out-of-image destination. They are recorded in `disjoint_branch_rows` instead of
  being counted as control flow, so the exclusion is visible in the artifact.
- **Unnamed constants.** Item types 0xa6/0xa7/0x104/0x444, 0x5b, 11, 298 (0x12a)
  and the achievement/tag strings are reported by number/verbatim; no enum in the
  binary names them.
- **`count` on the swap path.** `buyItem:`'s `count` argument is unused on the coin
  swap branch; only the priced path loops it.
- **Argument typing at two call sites.** `updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:`
  receives the raw 32-bit pattern of the float `usageMultiplier` in `sellItem:`
  (r3 loaded from the frame slot at 0xd3da38) and an explicit -1.0f in `buyItem:`;
  the listing cannot settle the callee's declared type. The eight stack arguments
  of `createFreeBlockAtPosition:...` are mapped positionally, with only ofType /
  dataA / dataB corroborated semantically (playSound holds the literal 4 at both
  sites, not a BOOL).
- **Tile byte semantics.** `tile[1] == 2` and `tile[3] != 0x60` are recorded as
  measured field tests; their game-level meaning belongs to the Tile domain and is
  not derived here.
- **Third-party integrity code.** The CrystalManager MD5 fingerprints
  (`7acfe93afc08%dc65ae2c54ecaf07f` / `7acfe93afc08c%d65ae2c54ecaf07f`-shaped, the
  `+73` offset and the `Hax` interstitial) are reported as recoverable strings and
  arithmetic; what they protect is a product decision, not a decoding question.
