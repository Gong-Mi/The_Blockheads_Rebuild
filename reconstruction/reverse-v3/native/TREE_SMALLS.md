# Tree smalls sweep — E85 (plants line opener)

The plants line opens with the ten fruit trees' small bodies: the shared
skeleton of type pins, the stage-code machines, the membership sets and the
float-food atomics.
**73 bodies, 1463 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_treesmalls.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/tree_smalls.json`.

## The tree stage-code table (the sweep's headline)

Every tree occupies a **3-code live band** and a **2-code dead pair** in the
world-format tile byte (+3). The makeTileDead machines write the dead pair
for the live stages; the kindself sets test membership:

| tree | objectType | fruitItem | live stages | dead markers | treeType |
|---|---:|---:|---|---|---:|
| AppleTree | 1 | 0x15 (21) | 3/4/5 | 0x1b/0x1c | 1 |
| CactusTree | 0x18 (24) | 0x18 | 0x2b | 0x2b/0x2c | 5 |
| CherryTree | 0x4d (77) | 0x4d | 0x15/16/17 | 0x27/0x28 | - |
| CoconutTree | 0x2e (46) | 0x2e | 0xf/10/11 | 0x23/0x24 | - |
| CoffeeTree | 0x4e (78) | 0x4e | 0x18/19/1a | 0x29/0x2a | - |
| PineTree | 0x1b (27) | 0x1b | 0x1d/0x22 | (pair) | 4 |
| MangoTree | 0x16 (22) | 0x16 | 0xc/d/e | 0x20/0x21 | 2 |
| MapleTree | 0x17 (23) | 0x17 | 0xa/b | 0x1e/0x1f | - |
| OrangeTree | 0x3c (60) | 0x3c | 0x12/13/14 | 0x25/0x26 | - |
| LimeTree | 0xa0 (160) | 0xa0 | 0x59/5a/5b | 0x5c/0x5d | 0xa (10) |

(objectType == fruitItemType for most trees: the fruit item mirrors the tree
type; LimeTree differs: objectType 0xa0 with treeType 0xa.)

## Load-bearing findings

- **makeTileDead:** the stage->dead machine reads the tile byte [r0+3] and
  writes via `strb [r1, 3]` (apple: stage 3 -> 0x1b, 4/5 -> 0x1c).
- **tileIsKindOfSelf:** the stage-set membership over [r0+3]/[r1+3]
  (live+dead codes + the marker arm).
- **The soils:** CactusTree accepts {0x3a/0x30/0x31/0x32}; CoconutTree
  accepts {6, 0x1b, 8, 0x3a, 0x30, 0x31}.
- **The float food:** AppleTree's availableFood is a plain float ivar
  (vldr/vstr + dirty chain ffffc8b4/c89c + ffe2466c notify); CactusTree's
  is **dmb ish-fenced** (fffff368 cell) - SMP-mirrored.
- **shouldAddFallenFruits:** PineTree = 0.
- **getSaveDict:** the tree save-dict forwarders (fffbca8 + ffe28998/
  ffe2c414 family).

## Boundaries (honest)

- uncl 12/12 resolve as PIC base anchors (clean).
- Some per-tree fruitseason branch counts vary (2-4 compares) - the season
  value model stays per-body in the listings; the ffffea98/fffff368 float
  cells are the pinned ivar slots.
