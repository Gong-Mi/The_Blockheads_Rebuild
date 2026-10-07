# World class — E101: the simulation core

The World simulation core: the tick giant, the render-prep giant, the
simulation pump, the event filter and the GPU-owning teardown.
**12 bodies, 22239 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_worldsim.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/world_simulation.json`.

## Load-bearing findings

- **The tick giant**: `update:accurateDT:pinchScale:dragInProgress:` =
  **7369w with sel x140** + operator float* x28 + fast enumeration x6 +
  __aeabi_idiv x6 + the timing pool **0x258 (600)/0xe10 (3600)/0x5a (90)/
  0xf (15)/0x3c (60)** — the minute/hour timing table.
- **The render-prep giant**:
  `preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:` = **7877w** with
  **linearInterpolate x10 + clamp_float x7** — the camera smoothing core
  (10 lerps per frame) + 3 out-of-window external helpers.
- **The GPU-owning teardown**: dealloc = **__wrap_free x24 +
  __wrap_glDeleteTextures** (the World owns its texture set).
- **The event filter**: addSimulationEventOfType: gates on
  **itemTypeIsSolid + itemTypeIsSowable**.
- **The day cell**: 0x15180 = **86400** (one day in seconds) shared by the
  start/finish family.
- **The pump**: continueSimulate = sel x59 + fast enumeration x4.
- **The progress**: simulationProgress (nullary accessor), pauseUpdates /
  preUpdate / deleteTimers / setServer:.

## Boundaries (honest)

- uncl 64/69: five cells (four sharing 0xffed2e68 below the window; one
  0x00015180 = the 86400 data cell).
- ws_09's 3 out-of-window calls stay opaque (external helpers).

**World line status after E100-E101**: 48/322 bodies recovered
(mutation core + simulation core); the render giant (30580w) and the net/UI
families remain.
