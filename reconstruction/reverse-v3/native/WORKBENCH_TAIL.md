# Workbench tail closure — E83

The Workbench's remaining accessor/flag band (the 0xb0xxxx tail), the render
flag tables, the delegate chains and the accessor cell map.
**26 bodies, 2324 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wbtail.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_tail.json`.

## Load-bearing findings

- **The render flag tables**: `rendersDynamicObjectQuad` = the type cascade
  (3 / 1 / 0xd / 8 / 0x1f ...); `rendersDynamicObjectCubes` = **{0x18 (24),
  0x1a (26), 0x1d (29)}**; `lightGlowQuadCount` gates on 1/0xd/3 + the
  fffff144 flag + 8/0x1f arms; `occupiesNormalContents` = 1.
- **The accessor cell map** (the fffff1xx band): type -> **fffff120**,
  level -> **fffff130**, selectedIndex -> **fffff17c**, craftingItemObject ->
  **fffff180**, count -> **fffff18c**, countLeft -> **fffff188**,
  craftProgressUI -> **fffff1ac**, xScroll -> **fffff178**; the craftable
  counts are **dmb ish-fenced** (numberOfCraftableItems -> fffff128,
  ...UpToCurrentLevel -> fffff124).
- **The delegate chains**: `canBeUsedInExpertModeWhenNotOwned` = the
  ffe26690 equality against 1; `requiresFuel` runs ffe26694/90 + the helper
  0xae3538 (the E75 getLightRGB family); `upgradeName`'s local helper
  0xb0b8fc is a **5-arm jump table** over the type (special 1/0xd arms +
  `cmp r0, 4; bhi` + table @0xb0b958); `fuelTypesCount`/`fuelTypes` forward
  to the E76 helpers 0xb01800/0xb018f8.
- **The manager release**: `blockheadUnloaded:` gates on the **fffff190
  owner compare** (only the current fuel manager clears) + fffff160 +
  ffe2642c.
- **destroyItemType -> the same helper 0xafd54c** as E79's
  freeblockCreationItemType (destroy/create share the item-type
  derivation); `fuelUIPos` = macro pos + **Vector2(0, 2.0f)**.

## Boundaries (honest)

- uncl 70/70 resolve as PIC base anchors (clean).
- The ffe266xx chains stay opaque; the render-quad type set beyond the read
  arms continues in the listing (31 branches); jump-table arm identities
  read from the listing.
