# ParticleEmitter class — E73 (electricity line)

The ParticleEmitter: the game's particle system — and the host of the
**electricity arc** effect (`addElectricityParticleWithPath:size:` /
`doAddElectricityParticleWithPath:size:`). The full class: the 2048-slot
pool, the singleton, the dmb-fenced atomics, the record adders, the arc path
builder and the GL render/update pass.
**15 bodies, 6662 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_particles.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/particles.json`.

## Load-bearing findings

- **The pool**: `init` allocates the effect arrays with **`__wrap_calloc
  (16384, 4)`** (the 64 KB float array) + a second calloc; the cap is
  **0x800 (2048)** (`cmp r0, 0x800; bge`) — the particle pool size; the
  ivar cells **ffffff08/0c/10/14** thread the members; `instance` is the
  **singleton** (global cell 0x67a4, lazy alloc).
- **The electric arc**:
  - `addElectricityParticleWithPath:size:` copies a
    **`std::__1::vector<ElectrictyParticlePathIndex>`** (the mangled symbol
    pins the game's own spelling **"Electricty"**) and bridges to doAdd
    (with `_Unwind_Resume` exception paths).
  - `doAddElectricityParticleWithPath:size:` builds the path: the **size / 50
    normalization** (`movw 0x32` = 50 segments, the f64 divide) + a `> 0`
    guard; the path elements are **40-byte** records (`i*5*8` index math,
    field at +0x1c); the path is written with
    **`vector<ElectrictyParticlePathIndex>::assign(first, last)`** — the arc
    interpolated between the endpoints.
- **The render/update pass** (4099w, 186 calls): the **GL pipeline**
  (`glUseProgram` x3, `glUniformMatrix4fv` x3, `glVertexAttribPointer` x7,
  **`glDrawArrays` x2 + `glDrawElements` x1**, `glBindTexture`, attrib
  enables, **`pushDepthMaskState`/`popDepthMaskState` x3**); the arc render
  reads the path via **`vector<...>::at(unsigned long)` x2** and runs
  **`closestPointOnLineToPoint(Vector, Vector, Vector)`** (the arc-vs-point
  hit test — the electrocution check) + `linearInterpolatev` +
  `Vector2::normal()`; particles collide with the world via
  `tileAtWorldPosition` + `tileIsAir`; constants **0.99f / 0.01f / 0.7f**
  (life decay / dv / drag family).
- **The atomics**: `setWorldWidthMacro:`/`worldWidthMacro` and
  `setStopAllParticles:` are **`dmb ish`-fenced** (the same SMP idiom as the
  Torch's setDataA/B); `setWorld:` is a plain store.
- **The adders**: the record layout is pinned by the stores (pos +0/+4,
  velocity +8/+0xc, color +0x10, gravity/life +0x14/+0x18, scale, and the
  center extension +0x44..+0x50); the goal/addBonus adders run the
  **ffffff50 stop gate** + the **world-width 4-tuple bounds gate**
  (ffffff58/5c/60/64: x >= -W, x <= W, y-bounds) + the **0x7fffffff
  sentinel** free-slot lookup (the INT_MAX marker).

## Boundaries (honest)

- uncl 27/7: the six 0x7fffffff occurrences are the pinned sentinel constant
  (data, not code); one cell (pe_render's ffffc9bc) resolves below the
  scanned window (shared code).
- The ffe291xx/ffe292xx call-chain identities stay opaque; the arc's
  per-segment visual shape reads from the render constants/calls without
  listing every one of the 4099 rows; the helpers 0xd8c67c (x3 in pe_render)
  stay opaque.
