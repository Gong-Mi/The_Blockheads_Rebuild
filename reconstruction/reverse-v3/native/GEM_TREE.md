# GemTree — E95 (plants line closer)

The branching gem tree: the contents ladders, the gem item codes, the 3600
season clock, the recursive tile set and the world-index lookups.
**17 bodies, 4471 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_gemtree.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/gem_tree.json`.

## Load-bearing findings

- **The contents ladders**: `bushContentsType` = a 12-const table
  **{0x6e,0x71,0x74,0x77,0x7a,0x6d,0x70,0x73,0x76,0x79,0x6f,0x72}**;
  `trunkContentsType` = {0x6d,0x70,0x73,0x76,0x79,0x6f,0x72,0x75,0x78,
  0x7b}; `trunkBushContentsType` = {0x6f,0x72,0x75,0x78,0x7b} - the
  0x6d..0x7b family with 3-apart ladders (the gem-content code space).
- **The gem item codes**: `gemItemType` = **{0x57,0x56,0x4c,0x4b,0x58}** -
  the 5 gem families the tree yields.
- **The dead markers**: makeTileDead writes **0x1d/0x22** (matching the
  kindself cmps).
- **The 3600 clock**: update: and fruitShouldFallInSeason: carry
  **0xe10 (3600)** + `__modsi3` - the season/growth clock domain.
- **The recursive tile set**: `recursivelyAddOwnedTile:toPositions:` builds
  the gem tree's owned-tile set recursively (makeIntpair x4 +
  `worldIndexAtWorldPosition` + the tile-search `find(...)`) - the
  branching structure.
- **The lookups**: worldChanged: runs worldIndexAtWorldPosition x4 +
  the search (`find`) across 1436w/53 calls; the ctor runs clampi x4
  (the gene clamps) with cmps 0xff/0x40.

## Boundaries (honest)

- uncl 70/70 resolve as PIC base anchors (clean).
- The helper 0x5290e8 (x8 in the ctor, x8 in worldChanged) stays opaque;
  the contents-code semantics read from the ladders.
- **This closes the plants line: plants/Tree/Plant/NormalPlant bases + the
  ten fruit trees + seven crops + Vine/Kelp/Tulip + GemTree = the full
  vegetation surface.**
