# Workbench twin giants closure — E80 (electricity line)

The Workbench's two great bodies — the per-tick simulation and the render —
whose recovery **closes the Workbench class: 96/96 bodies**.
**2 bodies, 11150 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wbgiants.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_giants.json`.

| body | imp | words | content |
|---|---|---:|---|
| wg_draw | 0x00af11f0 | 8600 | the render (2nd-largest in project) |
| wg_update | 0x00aeea18 | 2550 | the per-tick simulation |

## Load-bearing findings

- **The update census** (2550w, 78 calls): **30 objc_msgSend** + `makeIntpair`
  x4 + `tileAtWorldPosition` x2 + the helper 0xae3c5c x2 + **tileIsWater** +
  **`tileIsBurnable(Tile*, DynamicWorld*, intpair)`** — the furnace's
  neighbour-burnable check (the **fire-feeding contract** of the furnace) +
  `clamp_float` + **`__wrap_fmodf`** (the coordinate wrap).
- **The draw census** (8600w, 259 calls - the second-largest body of the
  project after the SteamTrain's): **`fillQuadBuffer(...)` x10** (the
  E41/E44/E73 quad-emit family), the **quad-buffer API pair**
  `updateQuadBufferTexCoords(float*, int, f,f,f,f)` x2 +
  `updateQuadBufferVertsAndMatrix(float*, int, _GLKMatrix4*, f,f,f,f)` x2,
  and **`itemTypeIsPainting(ItemType)`** — the painting-aware draw; 30x
  Vector float* + 22x Vector2 + 15x Vector3 ctors (5 four-float) + the
  helper 0xae3c5c x11; idiv x8 + modsi3 x2 (the grid math).
- **The sprite/sizing pools**: **-0.99 (x8), -0.98, 0.9 (x2), 0.2, -1.4,
  -0.2** (the part offsets) and the crafted-item sizing triple **0.8078 /
  0.8549 / 0.8863** (0x3f4ececd/0x3f5adadc/0x3f62e2eb).

## Boundaries (honest)

- uncl 57/60: two cells (0xffdb8c2c) resolve below the window (shared
  code); one (0xffffd6a0) likewise; both giants are characterized by
  structural census (call tables + float pools) with the load-bearing
  symbols pinned.
- This closes the Workbench class: 96/96 bodies across E75-E80.
