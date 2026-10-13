# DynamicWorld breeding/NPC/service cluster — E27

The breeding, NPC and service cluster: the NPC breeding-distance check, the
breeding-plant partner scan, the plant/occupant lookups, the NPC spawn cap, the
pause propagation and the blockhead inventory/teleport services.
**7 bodies, 2961 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_breed.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/breed_npc.json`.

| body | imp | words | content |
|---|---|---:|---|
| npcCloseEnoughToBreedWithNPC: | 0x008f3288 | 574 | breeding-distance check |
| getPlantAtPos: | 0x008ef6f8 | 465 | plant lookup by type+pos |
| findBreedingPlantNearPlant: | 0x008e37c0 | 440 | partner scan |
| tooManyNPCsToSpawnMoreNearPos: | 0x008f2bb4 | 437 | NPC spawn cap |
| setPaused: | 0x008f9580 | 380 | pause propagation |
| saveBlockheadInventory: | 0x008b8634 | 339 | inventory archive/service |
| teleportBlockhead:toWorkbench: | 0x008f5658 | 326 | randomized teleport |

## Load-bearing findings

- **Breeding distance** (`npcCloseEnoughToBreedWithNPC:`): the counterpart is
  found through the ffffe54c segment with the ffe236b4 gate; the comparison uses
  the **cylindrical wrap-distance family** (worldWidthMacro <<5 + `__aeabi_idiv`
  + the 2/5 constants + `rsb` negation) — the same idiom as E23's sow scans and
  E24's repair pass.
- **Partner scan** (`findBreedingPlantNearPlant:`): the ffe23594 eligibility gate
  + family filter + the same wrap-distance math over the ffffe54c plants.
- **Plant lookup** (`getPlantAtPos:`): `type >= 0xa` returns nil; the 10-arm
  table **0x00E4AA3C** routes the ffffe54c then ffffe550 segments with the
  ffe23670/ffe23674 positional compares.
- **Spawn cap** (`tooManyNPCsToSpawnMoreNearPos:`): `npcType >= 8` false; 8-arm
  table **0x00E4AA1C**; in-range NPCs counted through the wrap-distance math and
  compared to the cap.
- **Pause propagation** (`setPaused:`): three sweeps — blockheads ffffe4f8, the
  4-arm table **0x00E4AA0C** over ffffe54c, and the 9-arm table **0x00E4AA90**
  over ffffe54c — each per-node call carrying the paused byte through the
  ffe236f8 selector.
- **Inventory service** (`saveBlockheadInventory:`): NSKeyedArchiver with the key
  **0x21 ('!')** and the uniqueID-keyed payload; the ffffe518 gate splits the
  client-send chain (ffe2334c/44/68/3c + gzip hook) from the database store
  (`stringWithFormat:` key 0xfff33e44 against worldDatabase ffffe50c).
- **Teleport** (`teleportBlockhead:toWorkbench:`): the ffe236c0 BOOL gate; the
  MJSoundManager chain with sound string 0xfff34184 and a -5/5 Vector; then a
  **256-iteration randomized landing search** (helper 0x8ad2a4, double
  round-trips, Vector4(0.5f, ·, ·, 1.0f) from the 0x3f000000/0x3f800000
  immediates, class ffe2afa0) with the -5 offset variants.

## Boundaries (honest)

- The ffe236b4/ffe23594/ffe236c0/ffe23670/74/ffe236f8 selector bodies are pinned
  by cell (bodies elsewhere); the wrap-distance constants (2/5) are read from the
  immediates; the 256-loop acceptance condition is recorded as observed from the
  Vector/random chain; the '!' archive key and sound string are read by
  address/value. All 35 uncl cells resolve as PIC base anchors + 4 jump-table
  pairs (0xE4AA1C, 0xE4AA3C, 0xE4AA0C+0xE4AA90 in setPaused).
