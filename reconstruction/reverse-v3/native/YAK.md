# Yak class — E98 (animals line)

The milkable, shaveable animal: the milk/fur item codes, the powf-animation,
the death drops and the full lifecycle.
**33 bodies, 8563 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_yak.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/yak.json`.

## Load-bearing findings

- **The produce codes**: `milkByBlockhead:` carries **0x13f (319) = the milk
  item**; `shaveByBlockhead:` carries **0x143 (323) = the fur item**;
  `createItemDropsForDeath` picks **0x141 (321 = the beef)**, 0x78, 0x7f,
  0x136 with `lrand48` randomization - the yak's three produce channels.
- **The powf animation**: `setupMatrices:dt:` = sinf x5 + **`powf` x1** (the
  only powf of the animal line) + memcpy x5 + the helper quartets (x10/x6/
  x4/x2) with the 1.0f/0.3f-family pool.
- **The render**: `drawSubClassStuff:` = objc x16 + glUniformMatrix4fv x8 +
  glBindTexture x4 (GL_TEXTURE_2D).
- **The lifecycle pair**: the yak-specific net family
  (yakUpdateNetDataForClient:/doYakRemoteUpdate:/remoteCreationDataUpdate)
  + the shared ctor/update/dealloc with the 0x384 family const.
- **The interaction gates**: canBeMilkedByBlockhead:/canBeShavedByBlockhead:
  (the 46w gates, same shape).

## Boundaries (honest)

- uncl 40/41: the 0x3fffffff sentinel in the drops pool.
- The helpers 0x9621d8/0x9623c0/0x962910/0x962ca8/0x965290/0x966378 stay
  opaque; the item codes above are pinned immediates.
