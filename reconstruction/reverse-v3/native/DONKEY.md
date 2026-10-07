# Donkey class — E96 (animals line opener)

The Donkey: the animation engine, the render giants, the breed family and
the ride gate.
**25 bodies, 15785 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_donkey.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/donkey.json`.

## Load-bearing findings

- **The animation engine**: `setupMatrices:dt:` = **`sinf` x14** (the
  gait/bob cycle!) + memcpy x12 + the helpers 0x6c3f24 x22 / 0x6c3d3c x16,
  with the phase/amplitude float pool 0xd70a/0xcccd/0x8f5c/0x851f/0x40/
  0x999a/0x6666/0x3333; 40 ivars.
- **The render**: `drawSubClassStuff:...` = objc x25 + **glUniformMatrix4fv
  x14** + **glBindTexture x5** (with the 0xde1 = GL_TEXTURE_2D const) + the
  helpers 0x6c9fe0 x14 / 0x6ca890 x7.
- **The breed family**: `nameForDonkeyBreed(DonkeyBreed)` appears in
  createItemDropsForDeath and generateBreedForChild; breedString exposes
  the breed name; the death drops pick consts 0x149/0x78/0x7f/0x47.
- **The ride gate**: `blockheadCanRide:usingItem:` carries the **0x384
  (900)** constant (the same value as the plant harvest family) with 7
  branch conditions.
- **The stat family**: npcType/maxAge/minFullness/foodPlantType/
  foodItemType/capturedItemType/captureRequiredItemType/getNamesArray
  (cfstring pair + count)/creationDataStructSize/maxHealth/flies/
  canJumpMultipleTilesWhileFlying/galloping/maxVelocity.

## Boundaries (honest)

- uncl 48/49: the 0x3fffffff sentinel in the death-drops pool.
- The two giants are census-characterized (sinf/glUniform/memcpy counts +
  float pools); the helpers 0x6c3f24/0x6c3d3c/0x6c9fe0/0x6ca890 stay
  opaque; the DonkeyBreed enum values read from the breed helpers.
