# Tree growth + update giants — E87 (plants line)

The ten `updateGrowth:` and ten `update:accurateDT:isSimulation:` bodies —
the growth contract and the season tick.
**20 bodies, 22630 verified words** (the largest batch to date), from the
pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_treegrowth.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/tree_growth.json`.

## Load-bearing findings

- **The shared growth contract**: every `updateGrowth:` runs
  **`reloadDrawBlockGeometryForTile` x4** (the geometry-reload render tie —
  sibling of the quad reloads E73/E84) + the neighbour walk (makeIntpair
  x5-7, tileAtWorldPositionLoaded x3-6, **tileIsSolid**) + the vegetation
  predicates **tileIsDeadTree** (cactus/coconut) and **tileIsBush**
  (coconut); the at_growth window pins the **ffffc908 gate**, the clamp
  **[-99, 99]** (`mvn 0x62` / `0x63`), the divisor **8**, the **rounding
  divide-by-2** (`add r5, r5, r5, lsr 31` / `sub r4, r4, r5, asr 1`) and the
  **+0x7f (127) bias**, over the ffffc8a0/c89c/c904/c924 cells (the at_growth base cell 0x9be67c).
- **The season tick**: every `update:` calls **`seasonForWorldX(int, double,
  World*)`** (the shared season query with a double arg); the tick carries
  the objc notifies (9-16 per tree) + tile probes; **pt_update** adds
  **`__wrap_fmodf`** (the coordinate wrap) + the unloaded
  `tileAtWorldPosition` probe + makeIntpair.
- **The per-tree helpers**: each class reuses its ctor-family helper
  (at: 0x9bd3a0 x4, ct: 0xb533ac x3, pt: 0xb64f38 x3, etc.) inside the
  growth.
- The at_growth pool carries the **0x3fffffff half-max sentinel** (the one
  unclassified word).

## Boundaries (honest)

- uncl 200/201: the single 0x3fffffff pool word is the sentinel (data); the
  rest resolve as PIC base anchors.
- The giants are characterized by census (call tables per body) + the
  at_growth window read; the helper bodies stay opaque; the per-arm detail
  continues in the listings.
