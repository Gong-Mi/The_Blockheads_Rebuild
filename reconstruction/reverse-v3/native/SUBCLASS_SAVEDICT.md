# DynamicObject subclass -[getSaveDict] override inventory (batch 1)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_inventory.py` →
`native/subclass_savedict_inventory.json` (regenerate + `--check`).

The pinned method map carries 66 exact `getSaveDict` rows. DynamicObject,
FreeBlock and NPC have dedicated records; this batch closes 17 of the
remaining 63 subclass overrides as pure routes, pinning for every class
the full pool chain on the hash-gated ELF:

- PIC base anchor re-derived per method from its own base literal cell;
- GOT cell → import symbol `objc_msgSendSuper2` / `objc_msgSend`
  (dynamic relocations, file word 0);
- selref slot → `getSaveDict` cstring / variant selector cstring;
- classref slot → the class struct, verified by the name walk
  (`word(class+0x10)` data → `word(ro+0x10)` name cstring — the
  Apportable ARM32 layout; the GNUstep-style +0x24 guess was rejected
  by the walk itself);
- literal-pool positions checked against the next-method boundary.

## Family A — `[super getSaveDict]` template forwarders (15)

Identical 27-word body (byte-exact against the ClownFish template), 4-cell
pool. ClownFish, Shark, Scorpion, Dodo, CoffeeTree, LimeTree, CherryTree,
MangoTree, MapleTree, OrangeTree, CoconutTree, Mirror, PassengerCar,
FreightCar, HandCar. These save nothing of their own; NPC-family objects
persist through the shared NPC/DynamicObject records only.

## Family B — tail-dispatch to a sibling variant (2)

```text
Blockhead 0x00b9e9d4 → [self getSaveDictIncludingWorkbenchOrInterationObject:NO]
  argument pinned by raw words movw r3,0 (0x00b9e9e8) + sxtb r2,r3 (0x00b9ea0c)
Chest     0x00cb95b0 → [self getSaveDictIncludingInventory:(chestType == 4)]
  argument gate pinned by cmp r1,#4 (0x00cb95f8), movw r1,0/movne r1,1/
  and r1,r1,#1 (0x00cb95fc..0x00cb9604), sxtb r2,r2 (0x00cb9618);
  value ivar = OBJC_IVAR_$_Chest.chestType @108 via the dynsym offset word.
```

The first draft of this batch mislabelled the Chest gate as
`blockType == 4` from an unverified note; the ivar-symbol gate rejected it
and the instruction stream gave `chestType @108`. Recorded here because the
correction is the point: same-name plausibility is not evidence.

## Not covered (46 rows, exact set)

Action, AppleTree, ArtificialLight, Bed, BlockheadCraftableItemObject,
Boat, CactusTree, CaveTroll, Column, CraftableItemObject, Door, DropBear,
Egg, ElevatorMotor, ElevatorShaft, FireObject, GatherBlock, GemTree,
GlowBlock, InteractionObject, KelpPlant, Ladder, NormalPlant,
OwnershipSign, Painting, PaintingCraftableItemObject, PineTree, Plant,
Rail, Sign, SnowSurfaceBlock, Stairs, SteamTrain, Torch, TradePortal,
TradingPost, TrainCar, TrainStation, Tree, TulipPlant, Tutorial,
VinePlant, Window, Wire, Workbench, Yak.

These reassemble the parent dictionary and add their own keys. Pairing each
key set is the next batch, per-class with the same gate set as the
NPC/FreeBlock key records.

Static level-A evidence: routes, dispatches, selectors, ivar offsets and
argument producers are pinned; no save-roundtrip, entity construction or
device behavior is claimed.
