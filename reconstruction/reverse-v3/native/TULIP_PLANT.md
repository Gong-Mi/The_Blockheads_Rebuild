# TulipPlant — E94 (plants line)

The color-genetics flower: the gene mask mixer, the 0..100 color variation,
the clamped color vector and the uniform coloring.
**26 bodies, 5691 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_tulipplant.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/tulip_plant.json`.

## Load-bearing findings

- **The color genetics**: `colorGenesVariation` mixes on a **0..100 scale**
  (consts 0xc/0x64) via the helper 0x9a5c50 x8 + 0x9a09e8 x5 + modsi3 x2;
  `mixGenesVariation` carries the **0xffff (16-bit) gene mask** (the parent
  genes combine into the child mask).
- **The gene storage**: colorGenes/setColorGenes: are plain ivar slots.
- **The clamped color vector**: `.cxx_construct` runs **`clamp_float` x4**
  (the color vector's components clamp to [0,1]).
- **The uniform coloring**: `draw:` runs **`glUniform4f` x3** with the
  0x3f80 (1.0f) const - the tulip uploads its color as a GL uniform (the
  color-genes-driven petals).
- **The breed gate**: `canBreed` const **0x1c2 (450)** (the same as the
  update's time base).
- **The tick**: update: runs seasonForWorldX x2 + the quad reload x2 with
  consts 0x708/0x384/0x1c2/0x100.
- The initSubDerivedItems carries the dense Vector math (48 calls,
  clamp_float x2).

## Boundaries (honest)

- uncl 52/53: the 0x3fffffff sentinel in the harvest pool.
- The helpers 0x9a5c50/0x9a09e8/0x9a0710 stay opaque; the gene bit layout
  beyond the 0xffff mask reads from the variation code.
