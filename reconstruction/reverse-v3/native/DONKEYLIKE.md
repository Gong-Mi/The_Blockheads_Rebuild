# DonkeyLike — E97 (animals line, the animal base class)

The animal base: the mega tick, the render, the gate-piercing knockback and
the full animal lifecycle.
**46 bodies, 18480 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_donkeylike.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/donkeylike.json`.

## Load-bearing findings

- **The mega tick**: `update:accurateDT:isSimulation:` = **7982w** - Vector
  float* x114 + objc x98 + **`__aeabi_idiv` x40** + **`tileIsAirWaterOrSnow`
  x18** (the pathing substrate probes) + tileAtWorldPositionLoaded x24 +
  consts 0x384/0xff/**0x1518 (5400)**/0x28/0xa/0x10.
- **The render**: `draw:...` = **6656w** - objc x73 + glUniformMatrix4fv x14
  + the helper 0xac2748 x14 with the 0xde1 (GL_TEXTURE_2D) const.
- **The gate-piercing knockback**: `hitWithForce:blockhead:` runs
  **`tileContainsGate` x4** + tileIsAirWaterOrSnow x4 - the hit resolves
  through gates.
- **The trig cxx_construct**: `.cxx_construct` = clamp_float x4 + **`cosf`
  x3 + `sinf` x3** - the orientation basis is built with trig.
- **The lifecycle**: the paired record family (donkeyLike creation/update
  records with 0x48/0x20 sizes + the base records + remoteCreationDataUpdate
  + doDonkeyLikeRemoteUpdate 533w); the ride stack (blockheadCanRide with
  the 0x384 const, addRider/removeRider, rider rotations, rideDirection,
  cameraPosForBlockhead); the hit/death pair (die:/reactToBeingHit/
  reactToBeingFed with 0x384/0x3333/0x4000); the capture pair
  (canBeCapturedByBlockhead:/cantBeCapturedTipStringForBlockhead:); the
  flags (jumps/flies/.../galloping/actsAsInteractionObject/requiresFuel).

## Boundaries (honest)

- uncl 175/176: the 0x3fffffff sentinel in the update pool.
- The two monsters are census-characterized (the call/const tables above);
  the helpers 0xac2748/0xab9de8/0xab1cdc stay opaque.
