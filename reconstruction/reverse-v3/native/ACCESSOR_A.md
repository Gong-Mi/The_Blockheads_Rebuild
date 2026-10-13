# DynamicWorld typed accessor family A — E36

The first typed-accessor batch: fire placement, the object-of-type resolver, the
torch/egg/painting at-position lookups, the egg adder and the
torch/egg/painting removers. **10 bodies, 711 verified words**, from the pinned
original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_acc1.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/accessor_a.json`.

| body | imp | words | content |
|---|---|---:|---|
| addEggAtPos:saveDict: | 0x008ea7a8 | 160 | egg adder |
| placeFireAtPosition: | 0x008e80e4 | 143 | fire placement |
| objectOfType:atPos: | 0x008e86b4 | 118 | object-of-type resolver |
| paintingWithID: | 0x008eaadc | 71 | painting-ID lookup |
| removeTorchAtPos: | 0x008e8fe8 | 45 | torch removal |
| removeEggAtPos: | 0x008eaa28 | 45 | egg removal |
| removePaintingAtPos: | 0x008eb00c | 45 | painting removal |
| torchAtPos: | 0x008e888c | 28 | torch accessor |
| eggAtPos: | 0x008ea738 | 28 | egg accessor |
| paintingAtPos: | 0x008eabf8 | 28 | painting accessor |

## Load-bearing findings

- **Type codes pinned**: torch = **0x11 (17)**, egg = **0x1e (30)**,
  painting = **0x34 (52)**, fire = **0x10 (16)** — each `XAtPos:` body is
  type-immediate + the ffe235f0 lookup call; each `removeXAtPos:` is the
  ffe23600 gate + a per-type remove cell (ffe23564 torch / ffe23618 egg /
  ffe23558 painting).
- **placeFireAtPosition:** probes `tileAtWorldPositionLoaded(int, int, World*)`
  + the tile byte +0x16, branches on **`tileIsPlant(Tile*)`** (plant -> ffe235e4
  + byte [r2+0xb] cleared = the burn) and otherwise creates type 16 via
  ffe235b0.
- **objectOfType:atPos:** the two-registry resolver (ffffe554 12-byte segment
  `__count_unique` -> `operator[]` -> the ffe234ac loaded gate -> return; miss
  continues the second walk) — the same shape as E31's
  loadStandardDynamicObjectOfType:atPos:.
- **paintingWithID:** probes the **+0x270 slices of both ffffe54c and
  ffffe550** (`__count_unique` + `operator[]` on each) — the two-registry
  painting lookup; the same +0x270 offset appears in E33's mute walk (shared
  member arithmetic, offset-pinned).
- **addEggAtPos:saveDict:** class ffe2af80 + alloc/init + the ffffe4e4/ffffe504
  world chain + the ffe23614 add call.

## Boundaries (honest)

- C symbols (`tileAtWorldPositionLoaded`, `tileIsPlant`) and dispatch cells are
  pinned by call site/cell; type codes read from immediates; the +0x270 slice
  identity is offset-pinned, not name-derived; all 21 uncl cells resolve as PIC
  base anchors (clean).
