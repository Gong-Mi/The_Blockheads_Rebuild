# Snow surface + ice melt (E118)

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies), the Column/Stairs melt pair and the two DynamicWorld snow hooks. 25 bodies, 1440 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| nq_00 | NPC -[actionTitle] | 0x0064a78c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_01 | NPC -[actsAsInteractionObject] | 0x0064fd44 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_02 | NPC -[age] | 0x00651314 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_03 | NPC -[beginBlockheadInspection:] | 0x0064ed9c | 26 | 0 | 0 | 2 | 0 | 0 | 0 |
| nq_04 | NPC -[blockheadCanRide:usingItem:] | 0x00649fc8 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_05 | NPC -[blockheadIsComingToInspect:] | 0x0064ee04 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_06 | NPC -[breed] | 0x006513a8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_07 | NPC -[breedString] | 0x0064ad30 | 20 | 1 | 1 | 0 | 0 | 1 | 0 |
| nq_08 | NPC -[cameraPosForBlockhead:] | 0x0064fc64 | 35 | 1 | 0 | 0 | 0 | 2 | 2 |
| nq_09 | NPC -[canBeCapturedByBlockhead:withItemType:] | 0x0064a744 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_10 | NPC -[canBeMilkedByBlockhead:] | 0x0064a554 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_11 | NPC -[canBeRemovedByBlockhead:] | 0x0064a7e4 | 22 | 1 | 1 | 0 | 0 | 1 | 0 |
| nq_12 | NPC -[canBeShavedByBlockhead:] | 0x0064a64c | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_13 | NPC -[canMate] | 0x0064ee48 | 54 | 0 | 0 | 3 | 0 | 0 | 2 |
| nq_14 | NPC -[cantBeCapturedTipStringForBlockhead:withItemType:] | 0x0064a768 | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_15 | NPC -[cantBeFedTipStringForBlockhead:] | 0x0064a49c | 46 | 2 | 2 | 0 | 1 | 2 | 0 |
| nq_16 | NPC -[cantBeMilkedTipStringForBlockhead:] | 0x0064a574 | 46 | 2 | 2 | 0 | 1 | 2 | 0 |
| nq_17 | NPC -[cantBeShavedTipStringForBlockhead:] | 0x0064a66c | 46 | 2 | 2 | 0 | 1 | 2 | 0 |
| nq_18 | NPC -[captureRequiredItemType] | 0x0064a2d0 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_19 | NPC -[capturedItemType] | 0x0064a2b4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_20 | NPC -[center] | 0x00649f04 | 34 | 1 | 0 | 0 | 0 | 2 | 2 |
| nq_21 | NPC -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline] | 0x00650a80 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_22 | NPC -[createItemDropsForDeath] | 0x00644704 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_23 | NPC -[creationDataStructSize] | 0x00649358 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_24 | NPC -[diesOfLowFullness] | 0x00643b04 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_25 | NPC -[diesOfOldAge] | 0x00643ab4 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_26 | NPC -[foodItemType] | 0x0064a298 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_27 | NPC -[fullnessFraction] | 0x00649428 | 65 | 1 | 1 | 1 | 0 | 2 | 2 |
| nq_28 | NPC -[getNamesArray] | 0x0064acf8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_29 | NPC -[getNamesArrayCount] | 0x0064ad14 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_30 | NPC -[healthFraction] | 0x00649390 | 38 | 1 | 0 | 1 | 0 | 2 | 0 |
| nq_31 | NPC -[inspectionStopped] | 0x0064a208 | 24 | 0 | 0 | 2 | 0 | 0 | 0 |
| nq_32 | NPC -[isDoubleHeight] | 0x0064a7c8 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_33 | NPC -[isVisible] | 0x00649f8c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_34 | NPC -[jumpsOnSwipe] | 0x0064fcf0 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_35 | NPC -[maxAge] | 0x00643a84 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_36 | NPC -[maxHealth] | 0x00649374 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_37 | NPC -[milkByBlockhead:] | 0x0064a62c | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_38 | NPC -[minFullness] | 0x00643ad0 | 13 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_39 | NPC -[minRidableAge] | 0x0064a83c | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_40 | NPC -[name] | 0x0064e5c8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_41 | NPC -[namePos] | 0x00650980 | 43 | 1 | 0 | 0 | 0 | 4 | 2 |
| nq_42 | NPC -[npcType] | 0x00643a68 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_43 | NPC -[npcUpdateNetDataForClient:] | 0x006455d4 | 42 | 1 | 0 | 0 | 0 | 3 | 2 |
| nq_44 | NPC -[objectType] | 0x00649550 | 20 | 1 | 1 | 0 | 0 | 2 | 0 |
| nq_45 | NPC -[reactToBeingFed] | 0x0065096c | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_46 | NPC -[reactToBeingHit] | 0x00649880 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_47 | NPC -[remoteUpdate:] | 0x00647c84 | 29 | 1 | 1 | 0 | 1 | 1 | 0 |
| nq_48 | NPC -[removeIsRed] | 0x0064a9bc | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_49 | NPC -[removeTitle] | 0x0064a98c | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| nq_50 | NPC -[renderPos] | 0x00649ebc | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_51 | NPC -[requiresFuel] | 0x0064fd28 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_52 | NPC -[requiresPhysicalBlock] | 0x006501b8 | 24 | 0 | 0 | 1 | 0 | 0 | 2 |
| nq_53 | NPC -[ridableWhenTamed] | 0x00650a64 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_54 | NPC -[rideDirection] | 0x0064fd0c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_55 | NPC -[riderBodyYRotationForBlockhead:] | 0x0064fc04 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_56 | NPC -[riderBodyZRotationForBlockhead:] | 0x0064fc34 | 12 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_57 | NPC -[riderDPadShouldAllowUpDown] | 0x00650a2c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_58 | NPC -[riderDPadShouldGiveDiscreteValues] | 0x0065019c | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_59 | NPC -[riderPosForBlockhead:] | 0x006500c0 | 48 | 0 | 0 | 1 | 0 | 5 | 0 |
| nq_60 | NPC -[secondChoiceIsBlue] | 0x0064a9d8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_61 | NPC -[secondOptionTitle] | 0x0064a86c | 72 | 3 | 2 | 1 | 0 | 3 | 4 |
| nq_62 | NPC -[setAge:] | 0x0065135c | 19 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_63 | NPC -[setBabyCreationStartValues] | 0x006445e8 | 71 | 0 | 0 | 4 | 0 | 2 | 0 |
| nq_64 | NPC -[setTargetVelocity:] | 0x00650180 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_65 | NPC -[shaveByBlockhead:] | 0x0064a724 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_66 | NPC -[shouldSaveEveryChangeInPosition] | 0x00650abc | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| nq_67 | NPC -[speciesName] | 0x0064a268 | 12 | 0 | 1 | 0 | 0 | 0 | 0 |
| nq_68 | NPC -[swipeUpGesture] | 0x0064fbf0 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_69 | NPC -[tamed] | 0x0064e81c | 47 | 0 | 0 | 3 | 0 | 0 | 2 |
| nq_70 | NPC -[tapIsWithinBodyRadius:] | 0x0064952c | 9 | 0 | 0 | 0 | 0 | 0 | 0 |
| nq_71 | NPC -[updateNetDataForClient:] | 0x006459c0 | 59 | 2 | 1 | 0 | 1 | 3 | 2 |
| nq_72 | NPC -[willDieIfHitByForce:] | 0x00649e20 | 39 | 1 | 1 | 1 | 0 | 1 | 0 |

# NPC tail sweep (E128)

The remaining 73 NPC bodies (the class tail left open by E117), from the pinned
original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).
73 bodies / **1,440 instruction words**; batch selection was verified per-row
against the coverage ledger: 106 NPC rows total, 33 already refs-covered,
exactly these 73 open (no overlap, no omission).

## Findings (E128)

- **Every body read in full**: all 73 are <=72 words (largest 72w) - no
  census-grade material in this batch (census count 0). The three heaviest:
  `secondOptionTitle` (72w), `setBabyCreationStartValues` (71w),
  `fullnessFraction` (65w).
- **The base riding contract (the Donkey/DonkeyLike/Yak line's parent)**: 
  `blockheadCanRide:usingItem:` == NO, `ridableWhenTamed` == YES,
  `riderDPadShouldAllowUpDown` / `riderDPadShouldGiveDiscreteValues` == NO,
  `rideDirection` = 0, rider body Y/Z rotations = 0.0f (all species-overridden),
  `shouldSaveEveryChangeInPosition` = **rider (self+0x84) != nil**,
  `riderPosForBlockhead:` = **Vector(floatPos.x, floatPos.y + 1.6f, -7.0f)**
  (Vector2(0, 1.6f) add to floatPos, then Vector ctor with z = -7.0f).
- **The "RIDE" menu gate**: `secondOptionTitle` returns the **"RIDE"** CFString
  (@0xf806b8) iff `ridableWhenTamed && !(diesOfOldAge && age < minRidableAge)`
  (selectors ridableWhenTamed / diesOfOldAge / minRidableAge, float compare via
  vcmpe + bpl); `secondChoiceIsBlue` == YES. `removeTitle` = **"SET FREE"**
  (@0xf806c8), `removeIsRed` == YES. `speciesName` = **"CRITTER"** (@0xf80678);
  `breedString` just forwards to `speciesName`.
- **The can't-do tips** (three same-shaped 46w bodies, instruction-identical
  except their cells): `cantBeFedTipStringForBlockhead:` =
  `stringWithFormat:@"THAT %@ ISN'T HUNGRY
TRY AGAIN LATER", speciesName`,
  `cantBeMilked...` = `@"THAT %@ HAS NO MILK
TRY AGAIN LATER"`,
  `cantBeShaved...` = `@"THAT %@ IS ALREADY SHAVED
TRY AGAIN LATER"`
  (format CFStrings @0xf80688 / @0xf80698 / @0xf806a8);
  `cantBeCapturedTipStringForBlockhead:withItemType:` returns nil.
- **Life constants**: `maxHealth` = **16** (u16), `maxAge` = **9000.0f**,
  `minRidableAge` = **900.0f**, `minFullness` = **-1800.0f**; fullness scale
  **5400.0** - `fullnessFraction` = clamp01(fullness / 5400.0) (f64 divide)
  with a `![self diesOfLowFullness] -> 1.0f` early-out;
  `healthFraction` = **clamp01(1 - damage/maxHealth)** (u16 damage @0x36);
  `willDieIfHitByForce:` = **damage + force >= maxHealth**;
  `diesOfLowFullness` / `diesOfOldAge` == YES (base).
- **The mating gate**: `canMate` = mateCooldownTimer (0x4c) <= 0 && !dead (0x38)
  && age (0x58) > 900.0f. `setBabyCreationStartValues` (71w): age = 0.0f;
  fullness = **900 + lrand48()/2^31 * 900**; layCooldownTimer the same
  900 + u*900; mateCooldownTimer = **60.0f**; helper **0x6445d8** (= thin
  lrand48 wrapper - push / bl lrand48 / pop) called twice, the same helper E117
  traced through np_03/09/11/24/28.
- **The inspection handshake**: `beginBlockheadInspection:` sets
  inspectingBlockhead (0x74) = blockhead **and clears** comingToInspectBlockhead
  (0x70); `blockheadIsComingToInspect:` sets comingToInspectBlockhead = blockhead;
  `inspectionStopped` clears both.
- **Taming state**: `tamed` = isNet (0x34) ? (netTameType byte (0xc0) != 0) :
  (tamedClientID pointer (0x6c) != nil); the save-shard id
  (`clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline`) = the
  tamedClientID pointer; `canBeRemovedByBlockhead:` forwards to
  `belongsToPlayerWithBlockhead:` (owner-only removal).
- **The net surface**: `remoteUpdate:` = pure objc_msgSendSuper2 forward
  (trampoline, class OBJC_CLASS_$_NPC); `npcUpdateNetDataForClient:` copies
  `[self dynamicObjectNetData]` (24-byte record) into the return struct;
  `updateNetDataForClient:` packs the same 24 bytes via
  `[NSData dataWithBytes:length:0x18]`; `creationDataStructSize` = **0x48 (72)**
  (matches E117's 0x48 creation record).
- **Positions**: `renderPos` = floatPos copy (@0x18); `center` and
  `cameraPosForBlockhead:` both return `[self renderPos]` (stret; nil-self ->
  zeroed; same contract, 35w vs 34w - cameraPos spills an extra r3);
  `namePos` = renderPos + Vector2(0, 1.0f).
- **The consolidated NPC ivar map** (symbol-resolved cells from this batch):
  name @0x5c, age @0x58, breed @0x60 (u16), dead @0x38, damage @0x36 (u16),
  fullness @0x44, visible @0x39, tamedClientID @0x6c, netTameType @0xc0,
  mateCooldownTimer @0x4c, layCooldownTimer @0x54, inspectingBlockhead @0x74,
  comingToInspectBlockhead @0x70, rider @0x84 (+ DynamicObject isNet @0x34,
  floatPos @0x18).
- **Constant/empty overrides**: `actsAsInteractionObject` = nil,
  `requiresFuel` = NO, `requiresPhysicalBlock` = NO (isNet probed, both arms
  store 0), `isDoubleHeight` = NO, `jumpsOnSwipe` = NO,
  captureRequiredItemType / capturedItemType / foodItemType = 0, npcType = 0,
  getNamesArray = nil / getNamesArrayCount = 0, canBeCaptured / canBeMilked /
  canBeShaved / milkByBlockhead: / shaveByBlockhead: /
  tapIsWithinBodyRadius: == NO; `createItemDropsForDeath` /
  `reactToBeingFed` / `reactToBeingHit` / `swipeUpGesture` /
  `setTargetVelocity:` = empty overrides (frame only); `actionTitle` = the
  name ivar itself.
- **dmb ish pair**: `age` (getter barrier after load) / `setAge:` (setter
  double barrier) - the usual atomic-float idiom.

## Boundaries

- All 73 bodies read in full; nothing census-grade (census count 0). 19 of the
  73 listings are trimmed at the next IMP (small accessors); headers keep the
  extracted ARM.exidx end.
- The stret-family ABI readings (`center`, `cameraPosForBlockhead:`, `namePos`,
  `renderPos`, `riderPosForBlockhead:`, `npcUpdateNetDataForClient:`) are
  decoded from the register contracts: r0 = hidden struct pointer, r1 = self,
  r2 = selector, r3 = first arg. The `cameraPosForBlockhead:` blockhead arg and
  the `npcUpdateNetDataForClient:` client arg are spilled but never read -
  recorded as decoded, not attributed to source intent.
- `requiresPhysicalBlock` keeps a dead `isNet` probe whose two arms both store
  0 (recorded literally).
- `NSString stringWithFormat:` / `NSData dataWithBytes:length:` /
  `objc_msgSendSuper2` contracts are asserted at the selector level only
  (Foundation / runtime internals out of scope).
- Float/double pools, movw/movt constants and the CFString payloads were
  machine-extracted from the pinned ELF (file offset == vaddr) and the
  imp/word prefixes in semantics_npc2.json were verified against roster.json
  for all 73 entries.
