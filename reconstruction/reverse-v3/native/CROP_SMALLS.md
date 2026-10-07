# Crop smalls sweep — E91 (plants line)

The seven simple crops: the type/seed/soil/render constant tables and the
chilli/sunflower light arms.
**73 bodies, 1343 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_cropsmalls.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/crop_smalls.json`.

## The crop constant table (the sweep's headline)

| crop | objectType | maxAgeBase | seedItem | soil | render |
|---|---:|---:|---:|---|---|
| Carrot | 0x1b (27) | 0x1c20 (7200) | 0x47 (71) | {1b,1c,30,31,32} | f5/f6 |
| Chilli | 0x21 (33) | 0x1c20 | 0x70 (112) | {1b,30,31} | f7/f8 + light |
| Corn | 0xc (12) | 0x1c20 | 0x3e (62) | {1b,1c,30,31,32} | f3/f4 |
| Flax | 0xa (10) | **0x3840 (14400)** | 0x36 (54) | {1b,1c,3a,30,31,32} | ef/f0 |
| Sunflower | 0xb (11) | 0x1c20 | 0x3d (61) | {1b,1c,30,31,32} | f1/f2 + light |
| Tomato | 0x3e (62) | 0x1c20 | **0x13c (316)** | {1b,30,31} | 2fa/2fb |
| Wheat | 0x3d (61) | 0x1c20 | **0x136 (310)** | {1b,1c,30,31,32} | 2f8/2f9 |

## Load-bearing findings

- **The seed/item polarity**: each crop's objectType equals ANOTHER crop's
  seed item (corn's obj 0xc is wheat's seed family; tomato obj 0x3e =
  corn's seed; wheat obj 0x3d = sunflower's seed) - the item/plant code
  space is shared.
- **The max-age pair**: the standard 0x1c20 (7200) with **flax at 0x3840
  (14400)** - the double.
- **The render pairs**: two sprite indices per crop (live/dead).
- **The spawn cost**: foodToRemoveWhenSpawningNPC = **0x708 (1800)**.
- **The light pair**: chilli and sunflower emit light (consts 0xff/0x4b +
  the Vector build) - the flowering light.

## Boundaries (honest)

- The soil deltas follow the crop (tomato/chilli drop the dead-tree
  markers; flax adds 0x3a).
- The npcSpawnType derivations and the lightFactor math read from the
  listings; the temperature/mintemp constants are per-crop immediates.
