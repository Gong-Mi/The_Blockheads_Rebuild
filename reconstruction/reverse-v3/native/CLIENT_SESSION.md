# DynamicWorld client-request/session cluster — E28

The client-request and session cluster: the master constructor with its
512-entry noise table, the harmable-object tap resolver, the client blockhead
lookup, the light-channel queue filler, the client pickup request and the chest
inventory sender. **6 bodies, 3047 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_session.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/client_session.json`.

| body | imp | words | content |
|---|---|---:|---|
| initWithWorld:… (11 args) | 0x008ac884 | 648 | master constructor |
| checkForHarmableDynamicObjectUnderTap:… | 0x008f1acc | 586 | harmable tap resolver |
| clientBlockheadWithID:fromClient:requestsDyamicObjectRemovalWithID: | 0x00905308 | 521 | client blockhead lookup |
| sendLightblocksToClients | 0x008b1dd4 | 478 | light-channel queue filler |
| clientPickupRequest:count:clientID:blockheadRequesterUniqueID: | 0x008f6954 | 427 | pickup request |
| sendChestInventoryForChest:toClientOwningBlockheadWithID: | 0x00901b58 | 387 | chest inventory sender |

## Load-bearing findings

- **Constructor**: eleven args; the alloc/init with count 0xe; the **17-slot ivar
  cascade** (ffffe4e8→fffe4e4) writing the initial object down the
  collection/map/database chain; `NSSearchPathForDirectoriesInDomains` +
  NSFileManager build the save directory; then **`for i in 0..0x200 (512)` fills
  the uint16 table at ffffe530 with `0x8ad2a4` random values** — the 512-entry
  noise/jitter table created at construction.
- **Harmable tap**: family `cmp 8` gate + the 8-arm table **0x00E4AA1C** over
  ffffe54c; ffe23664-gated collection (`addObject:`); the count branch returns the
  single candidate via ffe23694 or runs the ffe23698/9c picker for multiple.
- **Client blockhead**: the ffffe51c gate; `for i in 0x41` over ffffe54c then
  ffffe550 segments matching `[obj uniqueID]` (eor/orr); the post ffe234ac gate
  and ffe23284 chain. (The base cell 0x905b10 name in dynsym —
  `mdb_midl_append_list` — is an ld64 artifact of the pool partner.)
- **Light channels**: 32 channels (`cmp 0x20`); the per-light 12-byte struct at
  the ffffe56c slice; per entry `macroTileAtMacroPostion` then the ffffe570/
  ffffe574 queue dedup+pushes (found-flag polarity: init 1, cleared on hit).
- **Pickup request**: VLA of 8-byte pairs on the stack; per item the ffe236d4 +
  **ffe2349c flag-1 removal mark**; then the 11-arm **table 0x00E18104** over
  ffffe54c with `__count_unique` + `operator[]` resolving each object and the
  **ffe23600 pickup call**.
- **Chest inventory**: netBlockheads ffffe4f4 uniqueID match → `[bh clientID]`;
  the chest state gate on **5 then 1** (ffe23390) + ffe2344c/ffe23438 gates →
  the inventory send chain.

## Boundaries (honest)

- Selector bodies (ffe23664/94/98/9c/00, ffe23390/44c/438, ffe236d4) are pinned
  by cell; the ctor's random helper 0x8ad2a4 is outside the batch; the VLA pair
  layout and the found-flag polarity are read from the stack/store patterns.
- uncl 26/26: 23 pc-base anchors + 2 jump-table pairs (0xE4AA1C, 0xE18104) +
  1 pool-partner cell (0x905b10).
