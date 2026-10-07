# World class — E100: the tile-mutation core

The World class opens: the fill/remove/paint/place engines, the 900/450 day
cycle, the polar sun arc and the sky gradient.
**36 bodies, 15099 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_worldmut.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/world_mutation.json`.

## Load-bearing findings

- **The giant fill**: `fillTile:` (9-arg) = **4785w with objc x68** +
  tileAtWorldPositionLoaded x19 + makeIntpair x11 + tileIsSolid x8 +
  tileIsAirOrSnow x6 — the complete tile-write pipeline; its rule codes
  include the **0x422 (1058)/0x43f/0x423 (1059)** family and **0x7d00
  (32000)/0x820 (2080)**.
- **The day cycle**: the ignoreSandFraction worker = clamp_float x3 + idiv +
  **linearInterpolate** with **0x384 (900)** and **0x1c2 (450)** — the
  900-tick day split into two 450-tick halves.
- **The celestial arc**: getDayNightFractionForX = **absoluteSeasonFraction
  + __wrap_fmodf + cos + polarToRectangular + getWorldUpVectorForX** — the
  sun/moon as polar coordinates.
- **The sky ramp**: dayColorForPosition = **linearInterpolate x10**.
- **The water flow**: waterMovedFrom: = operator float* x15 family with the
  **0x1f4 (500)** capacity and the 0x4dd3 divisor.
- **The decommission sweep**: uses **std::unordered_set x2** (+insert/erase
  unique) — the physical-block set drives batch teardown.
- **The removal engine**: the 9-arg removeTileAtWorldX = objc x17 +
  makeIntpair x16 + tileIsWater x4 with **0xc350 (50000)**.
- **The paint face codes**: consts 0x18/0x19 in paintTile - + makeIntpair
  addressing everywhere.

## Boundaries (honest)

- uncl 180/182: two bodies share the cell 0xffed2e68 (below the window).
- The 0x559f54/0x55468c/0x579a48/0x579ab4 helpers stay opaque.
- This opens the **World line** (322 bodies estimated >100k words; more
  sub-batches follow: render, net, UI).
