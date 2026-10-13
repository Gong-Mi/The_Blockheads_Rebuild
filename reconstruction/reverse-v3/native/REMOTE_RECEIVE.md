# DynamicWorld remote-receive/painting/chest smalls — E32

The remote-receive/painting/chest smalls: the remote creation-data and update
appliers, the snow-change recorder, the NPC-existence probe, the free-block
move, the painting request/receive pair and the chest-inventory receiver.
**8 bodies, 1197 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_remote.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/remote_receive.json`.

| body | imp | words | content |
|---|---|---:|---|
| freeblockPositionChanged:oldPos: | 0x00906998 | 205 | free-block registry move |
| snowChangedAtMacroPos: | 0x008e1bf0 | 202 | snow-change recorder |
| npcExistsAtPos:ignoreNPC: | 0x008f28a4 | 196 | NPC-existence probe |
| chestInventoryDataRecievedFromServer: | 0x00902164 | 164 | chest-inventory receiver |
| remoteUpdate:forObjectsOfType:fromClient: | 0x008c3fa0 | 155 | remote update applier |
| paintingDataRecievedFromServer: | 0x009019a8 | 108 | painting-data receiver |
| requestPaintingDataForPainting: | 0x00901560 | 88 | painting-data requester |
| remoteCreationDataUpdate:forObjectsOfType:fromClient: | 0x008c3e64 | 79 | creation-data applier |

## Load-bearing findings

- **Free-block move**: the second consumer+writer of E24's ffffe588 registry —
  unregister at the old pos (`__count_unique` + `operator[]` + the set's
  `__erase_unique`; when the set empties, the map's `__erase_unique(u64)` drops
  the position) then re-register at the new pos via a second
  `worldIndexAtWorldPos` walk.
- **Snow recorder**: the ffffe580 member pair-dedup (the E22-family eor/tst
  found-flag) + a second structure pass — the snow queue E22's save sweep scans.
- **NPC probe**: the `arg >= 8 -> false` gate + the **jump table 0x00E4AA1C**
  (8-arm NPC family table) selecting a slice of the ffffe54c member (12-byte
  striding), then the tree walk comparing the node pos + the object's
  xPos/yPos + the ignoreNPC gate.
- **Remote appliers**: `remoteCreationDataUpdate` lazily buckets per-objectType
  in the ffffe544 4-byte pointer array (class ffe2aeb0 slots);
  `remoteUpdate` takes the `objectType == 0x3c` gate and the ffffe51c array
  walk (matching E24's interaction type code 60).
- **Painting pair**: the requester builds the message (ffe2aef0 class +
  ffe23340 last-client-blockhead ID + the 0x30/1/8 frame) with the ffe2332c
  uniqueID; the receiver slices the 8-byte tail (`sub r0, r0, 8; mov r1, 8`)
  and applies via ffe23790/ffe23348.
- **Chest receiver**: the `cmp r0, 8; bls` length gate + the same 8-byte tail
  convention + the ffe2af7c class check — the client side of E28's
  sendChestInventoryForChest:.

## Boundaries (honest)

- All dispatch cells, classes and the ffffe544/ffffe51c array element classes
  are pinned by cell; the continuations past each head window are read from the
  listings; the jump-table arms are the table's 8 entries; all but one uncl
  cell (the 0xE4AA1C table base) resolve as PIC anchors (23 cells accounted:
  22 pc-base + 1 table).
