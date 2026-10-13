# NormalPlant — E90 (plants line)

The first plant subclass: the growth/vigor machinery, the render-quad tie,
the light family and the flowering gate.
**36 bodies, 5090 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_normalplant.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/normal_plant.json`.

## Load-bearing findings

- **The plant vigor symbol**: `initSubDerivedItems` calls
  **`growthVigorForPlantTypeAtPos(...)`** - the plant counterpart of the
  tree's `growthVigorForTreeTypeAtPos` (the vigor family has a plant leg).
- **The render tie**: **`reloadDrawBlockDynamicObjectQuad`** appears in
  `update:` (the giant tick), `initSubDerivedItems` and `setFlowering:` -
  the veg-line sibling of the light-glow (E68) / geometry (E87) reloads;
  the flowering transition invalidates the plant's render quads.
- **The giant tick**: `update:` = 1736w / 79 calls (objc ×32 + makeIntpair
  ×5 + the probes) with the time-base consts **0x708 (1800) / 0x400 / 0xff
  / 0x100**.
- **The light family**: `emitsLight`/`lightFactor`/`lightColor` +
  `lightGlowQuadCount`/`addLightGlowQuadData:fromIndex:` (the glow pair) +
  `addArtificialLightContribution...` - the plant as a light contributor.
- **The harvest**: `tileHarvested:...` runs clampi with the **0x384 (900)**
  constant (the same as the cactus ctor - the planting/harvest fraction).
- **The flowering gate**: `setFlowering:` runs the `tileIsAirWaterOrSnow`
  substrate check + the quad reload.
- The quad emitter runs `fillQuadBuffer`; the ctor carries the season query
  (seasonForWorldX) + the 0xa66604 helper.

## Boundaries (honest)

- uncl 56/61: five cells resolve as adjacent instruction words (the listing
  boundary bleed - recorded, not resolved); the helpers 0xa66604/0xa69eec
  stay opaque.
