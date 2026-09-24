# Upper-mid-tier initWithWorld loaders incl. the chain nodes (batch b3l)

Scope: fifteen `initWithWorld:…` implementations in the 214–408 word tier
of `libApplication.so` (sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`),
4,518 words, 71 own-key reads. Evidence level: **static (level-A)**,
literal-pool-gated, table-driven like b3k.

## The fifteen (imp / words / runtime super / own keys)

```text
ElevatorShaft    0x00cad2cc 214w DynamicObject      itemType, lastKnownMotorPos.x/.y, ownerID, paintColor
GlowBlock       0x00ca8920 214w DynamicObject      lightDict, tileType
ElevatorMotor   0x0070046c 218w DynamicObject      availableElectricity, itemType, maxY, minY, ownerID
TradingPost     0x005e5718 223w InteractionObject  coinCount, priceTier, sellerClientID, sellerClientName
FireObject      0x00674af4 259w DynamicObject      burnTimer, lightDict, spreadTimer_0..3
DynamicObject   0x00839f7c 273w ROOT               floatPos, pos_x, pos_y, uniqueID
NormalPlant     0x00a66614 281w Plant              availableFood, lightDict
TradePortal     0x00d382fc 281w InteractionObject  level, lightDict, localPriceOffsets
Torch           0x004b5d38 318w DynamicObject      connectionType, dataA, dataB, itemType, lightDict, ownerID
InteractionObject 0x005f4634 352w DynamicObject    currentBlockheadIndex, flipped, isInUse, ownerID, ownerName, paintColor
OwnershipSign   0x00a34b18 352w Sign               h, landOwnerID, landOwnerName, w
Painting        0x00aa81e8 358w DynamicObject      hasVerifiedImageData, itemType, outputImageData, ownerID, ownerName
TrainCar        0x00a3892c 363w DynamicObject      currentBlockheadIndex_%d, engineCarID, engineIsRight, leftCarID, ownerID, rightCarID
DropBear        0x0079d538 404w NPC                courageMeter, dropPos.x/.y, dropSpeed, dropping, goalTreeDirection, onGround, provokeMeter, saveTime
CaveTroll       0x00d538cc 408w NPC                dead, defendSquare.x/.y, state
```

## The chain nodes are closed

- **DynamicObject (273w) is the ROOT loader**: it forwards nothing — it
  reads the base keys `{pos_x, pos_y, floatPos, uniqueID}` (unsignedLongValue
  / floatValue / objectAtIndex:), then runs
  `[self initDerivedStuff:loadPhysicalBlockIfNeeded:]`. Its in-file
  superclass is the ObjC root (nil beyond NSObject). Every loader chain in
  the game ends here.
- **InteractionObject (352w) is the mid-chain node** (Mirror/Bed/Sign/
  TradingPost/TradePortal hang below it): reads six keys, resolves
  `ownerName` via `getOwnerNameForObjectOwnerID:` gated by `isServer`.

## Structural finds

- A **THIRD selector variant** `initWithWorld:dynamicWorld:saveDict:cache:parentObject:`
  (5-arg) appears in the pools of GlowBlock, FireObject, NormalPlant,
  TradePortal, Torch — all five ALSO carry an `ArtificialLight` classref:
  they construct child **ArtificialLight** objects (alloc + the 5-arg
  variant) from their `lightDict` key. The classref gate now carries these
  child-construction refs (plus TrainCar's `NSString` for its formatted
  keys, and TradePortal's `NSMutableDictionary` for localPriceOffsets).
- **TrainCar reads FORMATTED keys**: `currentBlockheadIndex_%d` via
  `stringWithFormat:` — per-rider slots driven by `maxNumberOfRiders`.
- DropBear is the **third saveTime + [world worldTime] site** (b3a gate
  pattern), plus `removeFromMacroBlock` / `release` / `maxAge` / `[NPC age]`.
- CaveTroll parses a byte blob: `bytes` / `length` selectors alongside
  `dead`/`state`/`defendSquare.x/.y`, with a NEW hook name
  **`initSubDerivedStuffStuff`**.
- OwnershipSign reads `{h, w}` land-claim radii and hooks `updateText` +
  `autorelease`; super = Sign (b3k).
- DropBear/CaveTroll hang off **NPC** (b3g root).

## Census

```text
front total:      60 methods / 13,820 words
covered b3f..b3l: 55 methods / 9,039 words
remaining:         5 methods / 4,781 words
  KelpPlant  606w (long), VinePlant 681w (long),
  Chest      760w, FreeBlock 1,347w, Workbench 1,390w
```

## Negative controls

6/6 mutations at the correct site (per-class prologue gates across the
tier, including both chain nodes).

## Artifacts

- `tools/recover_uppermid15_initwithworld.py` (`--check`/`--self-test`).
- `reconstruction/reverse-v3/native/uppermid15_initwithworld.json`.
- `tools/test_uppermid15_initwithworld_evidence.py` — dual-mode guard.
- This document.
