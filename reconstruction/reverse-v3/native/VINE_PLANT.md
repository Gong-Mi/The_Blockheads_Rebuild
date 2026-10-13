# VinePlant — E92 (plants line)

The water-growing vine: the temperature-gated ctor, the water substrates,
the arbitrary-quad emitter and the quad-reload tie.
**24 bodies, 4102 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_vineplant.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/vine_plant.json`.

## Load-bearing findings

- **The temperature gate**: the ctor calls **`currentTemperatureForTileAt...`
  x2** - the vine's placement is temperature-aware (the minAllowedTemperature
  family from E91 made concrete).
- **The water substrates**: `update:` runs **`tileIsWater` x3** - the vine
  grows over WATER (vs the land crops' soil sets).
- **The quad-reload tie**: `reloadDrawBlockDynamicObjectQuad` appears in
  `update:`, `remoteUpdate:`, `initSubDerivedItems` and
  `tileHarvested:` (x4 sites overall; harvest x2) - the same veg-line
  reload as NormalPlant (E90).
- **The arbitrary-quad emitter**: `addForegroundDrawQuadData:fromIndex:
  forMacroPos:` runs **`fillArbitraryQuadBuffer`** (the arbitrary-quad fill
  variant beside fillQuadBuffer!) + **`macroPosForWorldPos(intpair,
  World*)`** + the helpers 0x4fa398 x4 with consts 0x20/0xbf00 (-0.5f
  bits)/0x1be.
- **The foreground count**: `staticGeometryForegroundDrawQuadCountForMacroPos:`
  (the foreground variant of the E84 static count).
- **dieOfOldAge**: the plant-specific death routine (objc x4 + the shared
  helper 0x4f688c).
- The harvest carries the 0x3fffffff half-max sentinel in its pool.

## Boundaries (honest)

- uncl 47/48: the 0x3fffffff pool word is the sentinel.
- The helpers 0x4f688c/0x4fa398/0x4fa2e8/0x4fa35c stay opaque; the const
  roles (0x384 = the harvest 900 family) read from the call sites.
