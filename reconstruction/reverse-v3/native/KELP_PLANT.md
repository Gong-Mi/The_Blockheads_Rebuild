# KelpPlant — E93 (plants line)

The swaying water kelp: the dual placement gates, the sine wave animation,
the arbitrary-quad updater and the quad-reload tie.
**23 bodies, 5280 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_kelpplant.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/kelp_plant.json`.

## Load-bearing findings

- **The dual gates**: the ctor runs **`currentTemperatureForTileAt...` x2**
  AND **`tileIsWater` x2** (both the temperature and the water substrate
  gate at placement); `update:` tracks the water column with
  **`tileIsWater` x5** (the most water probes in the line).
- **The sine sway**: `draw:` and `addDrawQuadData:` both run
  **`sinf` x2** - the kelp BENDS with the sine wave (the wave animation!).
- **The arbitrary-quad updater**: `draw:` calls
  **`updateArbitraryQuadV...`** (the updater beside E92's
  fillArbitraryQuadBuffer) + **`macroTileAtMacroPostion(int, int)`** (the
  macro-tile resolver).
- **The quad-reload tie x6**: update/dieOfOldAge/initSubDerived/
  remoteUpdate/harvest(x2)/rmmacro(x2) - the densest reload coverage of the
  line.
- **The tick bases**: update consts **0x708 (1800)/0x384/0xe1 (225)/0x51
  (81)**; harvest consts 0x384/0x90 (144); the 0x3fffffff half-max sentinel
  in the harvest pool.
- **The net contract**: remoteUpdate's consts 0x28/0x51 - the same shape
  as the vine's (the shared plant-subclass net contract).

## Boundaries (honest)

- uncl 57/58: the 0x3fffffff pool word is the sentinel.
- The helpers 0x814f44/0x818d60/0x818cec stay opaque; the sinf phase/amp
  read from the draw listing.
