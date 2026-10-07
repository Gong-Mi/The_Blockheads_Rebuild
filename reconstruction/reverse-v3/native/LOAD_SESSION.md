# DynamicWorld load/session smalls — E31

The load/session smalls: the kicked-client action stopper, the client found-list
receiver, the debug-log appender, the explore-light channel recorder, the chest
local-inventory loader, the ridable-object lookup cascade and the
standard-object loader. **7 bodies, 1671 verified words**, from the pinned
original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_loadsm.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/load_session.json`.

| body | imp | words | content |
|---|---|---:|---|
| stopAllBlockheadActionsForClientDueToKick: | 0x008f8108 | 294 | kicked-client cleanup |
| newFoundListRecievedFromClient:list: | 0x008fad90 | 246 | found-list receiver |
| appendDebugLog: | 0x00902b2c | 245 | debug-log appender |
| exploreLightChangedAtMacroPos:clientLightBlockIndex: | 0x008e17ac | 239 | light-channel recorder |
| loadLocalInventoryDataForChest: | 0x008b8fc4 | 222 | chest inventory loader |
| ridableObjectWithID: | 0x008f8fcc | 216 | ridable lookup cascade |
| loadStandardDynamicObjectOfType:atPos: | 0x008e6250 | 209 | standard-object loader |

## Load-bearing findings

- **Ivar-name confirmations** (from the batch symbol table): ffffe4f4 =
  `netBlockheads`, ffffe514 = `serverClients`, **ffffe54c is the
  `dynamicObjects` family (the 65-segment per-type maps)** — the container every
  batch from E21 on addresses; ffffe508 region = the `dynamicObjectDatabase`
  tracker; also `lightChangedSendUnreliablyMacroPositionsSingleClient`.
- **Ridable cascade**: `ridableObjectWithID:` probes the ffffe54c member's
  **+0x150 / +0x2f4 / +0x9c / +0x264 / +0x1d4 slices** in order with
  `__count_unique` + `operator[]` — the per-family object maps; the first hit
  returns. This proves the family-slice layout of the ffffe54c member.
- **Standard loader**: `objectTypeHasStaticPosition(int)` gate -> the ffffe554
  12-byte segment path with `__count_unique` + the ffe234ac gate (loaded ->
  return); otherwise `classForDynamicObjectType(int)` + alloc/init + the
  ffe235ac packed create + registration into the ffffe550 map.
- **Debug log**: 0x41-gated walk of the ffffe54c 12-byte segments with the
  segment count gate + `NSStringFromClass` + the 0xfff34234 format.
- **Explore light**: channel == -1 special arm (ffe23404 with 0) vs the
  ffffe56c 12-byte light-channel struct writes (the changed-flag record feeding
  E28's sendLightblocksToClients).
- **Kick cleanup**: enumeration of the ffffe4f4 netBlockheads with the
  ffe23444 clientID match -> the ffe236ec stop-all-actions selector.
- **Chest loader**: `[chest xPos]/[chest yPos]` -> /32 -> the ffffe508 +
  worldIndex locator with the ffe2332c uniqueID and the 0xfff33ef4 string in
  the compare walk.

## Boundaries (honest)

- The C symbols (`objectTypeHasStaticPosition`, `classForDynamicObjectType`,
  `NSStringFromClass`) and the dispatch-cell bodies are outside the batch; the
  family-slice offsets are observed member arithmetic (identity pinned by
  offset, not name); the found-list receive tail beyond the gate is read from
  the listing's continuation; all 15 uncl cells resolve as PIC base anchors
  (clean).
