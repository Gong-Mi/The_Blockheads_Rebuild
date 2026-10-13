# DynamicWorld draw & reload cluster — E25

The draw and reload cluster: the packed in-front object draw, the names/labels
pass, and the three macro-tile keeper reload contracts (quads, static cylinders,
static geometry) with their free/count/malloc/fill phases, plus the blockhead
box draw. **6 bodies, 5368 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_draw.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/draw_reload.json`.

| body | imp | words | content |
|---|---|---:|---|
| drawInFrontOfBlocksObjects:… | 0x008d2db8 | 1642 | packed in-front family draw |
| drawNames:… | 0x008dc6b4 | 1393 | names/labels pass |
| reloadDynamicObjectQuadsForMacroTile: | 0x008ff8bc | 961 | quads free/count/malloc/fill |
| reloadDynamicObjectStaticCylindersForMacroTile: | 0x008fec40 | 487 | cylinders reload |
| reloadDynamicObjectStaticGemometryForMacroTile: | 0x008fe4a4 | 487 | geometry reload |
| drawBlockheadBoxes:… | 0x008dc07c | 398 | blockhead box draw |

## Load-bearing findings

- **In-front draw**: the ffffe54c map's member slices (+0x2d0 / +0x240 / +0x234 /
  +0x168 / +0xc0) are drawn one family at a time with the packed send frame
  (camera rect + matrices + hideUIType at r0+0x0..0x8c) and the per-family
  dispatch slot built from the literal-pool pairs (0xffe23538 + 0x78c870 /
  0x78c3d0 / 0x78bf30 / 0x78ba80); loops advance with `std::__1::tree_next`.
- **Names**: `__wrap_glEnable(0xbe2)` (GL_BLEND) then an **8-arm SWITCH**
  (table **0x00E4AA1C**) over the ffffe54c segments with the pinchScale float in
  the packed frame (dispatch slot ffe23544); the drawLocalNames gate ([lr+0xff])
  opens the blockhead passes (ffffe4f8 / ffffe4f4 / ffffe4f0).
- **Reload contracts (one family)**: `__wrap_free` + clear of the keeper's two
  buffer pointer pairs (quads: +0x1a4/+0x1a8, +0x1b8/+0x1bc; cylinders:
  +0x1dc/+0x1e0, +0x1e4/+0x1e8; geometry: +0x190/+0x194, +0x198/+0x19c); the
  [r3+0xc] count gate; per-object counts through the ffe23760/64 (quads),
  ffe2374c/48 (cylinders), ffe2373c/38 (geometry) calls; a 2-arm SWITCH
  (table **0x00E18134**) over the ffffe54c segments; then
  `__wrap_malloc(count * 2 * 4 * 0x60)` for quads vs `* 0x240` for
  cylinders/geometry at the first slot, NULL -> `__wrap_exit(0)`; fill pass
  (ffe2376c for quads). The 0x60/0x240 strides are the record-size difference.
- **Box draw**: count chain (ffffe55c / ffffe4f8 / ffe23204) takes the first
  blockhead and runs the box draw (ffe231cc fields) plus the packed camera frame
  (dispatch slot ffe23540).

## Boundaries (honest)

- The per-slice offsets, dispatch slots, malloc strides and switch tables are
  read from the immediates; the drawn families' classes and the ffe237xx call
  bodies are outside this batch.
- 0xbe2 is read as the glEnable cap (GL_BLEND); the state byte at [sp,0x6ff] is
  observed, not decoded.
- The literal-pool word 0x8d3df0 (0x78cad4) has no consumer line in the listing
  (recorded as observed); its siblings 0xffe23538 / 0x78c870 are the dispatch
  pair.
- The reload trio is recorded as ONE contract family with per-slot differences.
