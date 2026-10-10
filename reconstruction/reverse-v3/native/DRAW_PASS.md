# DynamicWorld draw cluster — E41

The draw cluster: the two-collection pre-draw update, the opaque draw pass
(double enumeration + the 33-argument ffe23538 dispatch) and the free-block
draw pass (the +0xa8 slice walk + the map<int,int> build).
**3 bodies, 2344 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_drawbig.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/draw_pass.json`.

| body | imp | words | content |
|---|---|---:|---|
| preDrawUpdate:…cameraMaxYWorld: | 0x008d11a8 | 401 | two-collection pre-draw update |
| drawOpaqueObjects:…:hideUIType: | 0x008d17ec | 1395 | opaque draw pass |
| drawFreeBlocks:…:hideUIType: | 0x008d4760 | 548 | free-block draw pass |

## Load-bearing findings

- **preDrawUpdate:** — two enumerations: **ffffe4f4 netBlockheads** then
  **ffffe4f0 local-client family**, each per-element **ffe23534** call with the
  camera float and the 4-byte array element — the paired update matching E35's
  collection-getters.
- **drawOpaqueObjects:** — frame 0x860 + 16-alignment; the **same two
  enumerations** (ffffe4f4 @0x8d1a94 then ffffe4f0 @0x8d1f54) with the huge
  33-argument marshalling wall (the camera/projection bundle stacked at sp)
  into the **shared ffe23538 draw-dispatch** (cells 0x8d2164/0x8d2d94 — the
  same dispatch E25's drawInFrontOfBlocksObjects uses); the tail takes the
  **0x00E4AA1C jump table** (8-arm family) before the epilogue.
- **drawFreeBlocks:** — the **ffffe54c member's +0xa8 free-block slice**
  tree-walked, per node the ffe23298 position + the **`std::__1::map<int, int>`
  built via __tree** with `operator[]` keyed by the objectType and the
  **`lsl r0, r0, 0xb` (<<11) macro maths** (type index -> world coordinate)
  + ffe23450; the marshalled 33-argument **ffe23538** call then the
  `~map<int,int>()` destructor.
- **Draw-dispatch unification**: drawFreeBlocks, drawOpaqueObjects (and E25's
  drawInFrontOfBlocksObjects) all funnel per-object draw work through the
  **ffe23538** dispatch — the render line's single execution slot.

## Boundaries (honest)

- The 33-argument marshalling walls are described structurally (register/stack
  stores read from the listings); the +0xa8 slice identity is offset-pinned;
  the <<11 maths read from the immediate shift; 11 of 12 uncl cells resolve as
  PIC base anchors, the last is the 0xE4AA1C table base; the dispatch targets
  are outside the batch.
