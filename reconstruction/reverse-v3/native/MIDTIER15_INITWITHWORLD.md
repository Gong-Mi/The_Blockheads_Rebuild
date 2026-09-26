# Mid-tier initWithWorld loaders, forward-then-read (batch b3k)

Scope: fifteen `initWithWorld:…` implementations in the 139–200 word tier
of `libApplication.so` (sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`),
2,596 words total. Evidence level: **static (level-A)**, literal-pool-gated.

This batch generalizes b3j: instead of bespoke per-class word gates, all
semantic facts (keys, ivar slots, selectors, runtime superclass) come from
the literal-pool scan, exact-gated per class; word gates pin only the
shared prologue (words 0–1) and the epilogue pair (located by scan — the
literal pool may sit AFTER the epilogue in this tier, so fixed tail
positions are wrong).

## The fifteen (imp / words / variant / runtime super / own keys)

```text
Window      0x00c98944 139w exact  DynamicObject      itemType, ownerID
Bed         0x00d407ec 144w exact  InteractionObject beddingColor, itemType
Tree        0x004c39a0 146w long   DynamicObject      saveTime
PineTree    0x00b64f48 157w long   Tree              availableFood, saveTime
Rail        0x0077ab90 164w exact  DynamicObject      configuration, itemType, ownedByStation
Sign        0x005fa604 166w exact  InteractionObject connectionType, offsetType, text
Boat        0x0096b818 168w exact  DynamicObject      currentBlockheadIndex, ownerID
Ladder      0x00aadcd4 168w exact  DynamicObject      itemType, ownerID, paintColor
Egg         0x00d4e30c 178w exact  DynamicObject      breed, genesDict, hatchTimer
SteamTrain  0x00d18834 180w exact  TrainCar           fuelFraction, goingRight, hasFuel, stopped
Column      0x00834a30 193w exact  DynamicObject      configuration, itemType, ownerID, paintColor
Stairs      0x006cc734 193w exact  DynamicObject      configuration, itemType, ownerID, paintColor
Door        0x007694fc 198w exact  DynamicObject      blocked, ironPlaceClientID, itemType, ownerID
TulipPlant  0x009a1368 199w long   Plant              availableFood, colorGenes, mateColorGenes, mixGenes
Wire        0x0095002c 200w exact  DynamicObject      configuration, itemType, ownerID, solidConfiguration
```

62 distinct CFString keys are read across the batch. Conversion selectors
observed: intValue, floatValue, boolValue, doubleValue, unsignedIntValue,
retain (object values). Post-init hooks: `initSubDerivedItems` (11
classes), `loadDerivedStuff` (Boat), plus Tree's own
`growInTimeSinceSaved:` call after reading `saveTime`.

## Structural notes

- **Tree is the second swallow-forward site**: a 6-arg long-variant method
  that forwards only the 4-arg EXACT selector to DynamicObject (like Plant
  in b3j). PineTree and TulipPlant DO forward the long variant (their
  pools contain it) — so the swallow behavior is per-class, not
  per-variant.
- PineTree reads `saveTime` AND calls `[world worldTime]` — the b3a Plant
  gate pattern (`worldTime - saveTime` reset gate) at the PineTree level.
- TulipPlant's runtime super is **Plant** — the loader chain
  TulipPlant → Plant → DynamicObject is now three deep with key reads at
  two levels.
- SteamTrain hangs off TrainCar (like the b3h rail vehicles HandCar /
  PassengerCar).
- Bed and Sign hang off InteractionObject (like Mirror in b3h).

## Census (whole selector front, both variants — corrected)

```text
front total:     60 methods / 13,820 words (43 exact + 17 long)
covered after
b3f..b3k:        40 methods / 4,521 words
remaining:       20 methods / 9,299 words
  214-410w tier: ElevatorShaft 214, GlowBlock 214, ElevatorMotor 218,
                 TradingPost 223, FireObject 259, DynamicObject 273,
                 NormalPlant 281 (long), TradePortal 281, Torch 318,
                 InteractionObject 352, OwnershipSign 352, Painting 358,
                 TrainCar 363, DropBear 404, CaveTroll 408
  big tier:       KelpPlant 606 (long), VinePlant 681 (long),
                 Chest 760, FreeBlock 1,347, Workbench 1,390
```

## Negative controls

5/5 mutations detected at the correct site: per-class prologue gates
(Window/Bed/Egg push, PineTree add-fp) and the epilogue-scan control
(Tree RET_SUB at its real index 131 — after which the literal pool
continues, proving the scan-based gate, not a fixed-tail gate, is what
fires).

## Artifacts

- `tools/recover_midtier15_initwithworld.py` — recovery tool
  (`--check` / `--self-test`).
- `reconstruction/reverse-v3/native/midtier15_initwithworld.json`.
- `tools/test_midtier15_initwithworld_evidence.py` — dual-mode guard.
- This document.
