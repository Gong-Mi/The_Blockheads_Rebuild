# KelpPlant / VinePlant big loaders (batch b3m-1)

Scope: the two plant-family BIG loaders of the `initWithWorld:` front —
KelpPlant `0x00815be8` (606w) and VinePlant `0x004f68a0` (681w), both the
long 6-arg variant, 1,287 words total — closeout series part 1 of 3.
`libApplication.so` sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.
Evidence level: **static (level-A)**, literal-pool-gated.

## Mirror-twin finding

KelpPlant (grows UP through water) and VinePlant (grows DOWN from ceilings)
are structural mirror twins:

```text
                  KelpPlant                    VinePlant
keys              availableFood                availableFood
                  growthTimer                  growthTimer
                  numberOfOccupiedTilesAbove   numberOfOccupiedTilesBelow
                  saveTime                     saveTime
super             Plant                        Plant
selectors (12)    identical set (both)
ivars             own 3 + Plant{age,frozen,     own 3 + Plant{age,growthRate,
                    growthRate,maxAge}           maxAge}
                  + DynamicObject{dynamicWorld,pos,world} (both)
```

Both run the plant-age phase after loading: `[world worldTime]` (the 4th
and 5th sites of the b3a `worldTime − saveTime` gate pattern), then
`dieOfOldAge`, `isGrowingInCompost`,
`dynamicWorldChangedAtPos:objectType:`, `worldContentsChangedAtPos:`,
`objectType`, `initSubDerivedItems`.

Bodies are **not** byte-identical (sequence similarity 0.559 — register
allocation differs and VinePlant carries ~75 extra words for the
below-tile occupancy scan), so unlike b3f/b3i there is no shared-body hash;
the evidence is pool-gated per class with prologue/epilogue word gates
(same as b3k/b3l). KelpPlant additionally loads `Plant.frozen` (ice-biome
state) — the only ivar-set difference.

## Census

```text
front total:        60 methods / 13,820 words
covered b3f..b3m1:  57 methods / 10,326 words
remaining:           3 methods / 3,494 words
  Chest      760w (exact)
  FreeBlock  1,347w (exact)
  Workbench  1,390w (exact)
```

## Negative controls

4/4 mutations at the correct site (prologue word 0 and word 1 per class).

## Artifacts

- `tools/recover_kelpvine_big_initwithworld.py` (`--check`/`--self-test`).
- `reconstruction/reverse-v3/native/kelpvine_big_initwithworld.json`.
- `tools/test_kelpvine_big_initwithworld_evidence.py` — dual-mode guard.
- This document.
