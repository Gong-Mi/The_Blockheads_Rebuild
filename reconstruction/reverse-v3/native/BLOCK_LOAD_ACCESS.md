# DynamicWorld block-load/accessor smalls — E35

The block-load/accessor smalls: the repair removal, the client-blockhead
receive, the portal checks, the loaded-count, the gather pair, the client/server
booleans, the net/all-blockhead merges, the portal-positions and blockheads
getters and the connection-loss stub.
**13 bodies, 605 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_blocktele.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/block_load_access.json`.

| body | imp | words | content |
|---|---|---:|---|
| removeObjectDueToRepair: | 0x00905b2c | 169 | repair removal |
| clientBlockheadsRecievedForPlayerID:data: | 0x008fb168 | 72 | client-blockhead receive |
| portalIsBeingRemovedAtPos: | 0x00902f3c | 54 | portal removal check |
| allBlockheadsIncludingNet | 0x008f6698 | 53 | full blockhead merge |
| loadedCountOfObjectsOfType: | 0x00903594 | 50 | loaded count |
| loadGatherBlockAtPos: | 0x008f5530 | 46 | gather-block load |
| isClient | 0x008f64c0 | 42 | client boolean |
| netBlockheads | 0x008f676c | 35 | net blockhead getter |
| gatherBlockAtPos: | 0x008f55e8 | 28 | gather-block lookup |
| isServer | 0x008f6514 | 21 | server boolean |
| portalPositions | 0x008fdeac | 15 | portal-positions getter |
| blockheads | 0x00902f00 | 15 | blockheads getter |
| connectionToServerLost | 0x008f956c | 5 | no-op stub |

## Load-bearing findings

- **Slot confirmations**: `isServer` = `ffffe51c != nil` and `isClient` =
  `ffffe518 != nil` — the pair that pins the server/client registries used by
  E31–E34. `blockheads` returns ffffe4f8 directly; `portalPositions` returns
  the ffffe4e8 world-struct member.
- **Collection merges**: `netBlockheads` merges ffffe4f0+ffffe4f4 via ffe236a8;
  `allBlockheadsIncludingNet` merges ffffe4f0+ffffe4f4+ffffe4f8 — the
  collection-getter family.
- **Repair removal**: the ffffe51c gate + `[obj objectType]` +
  **`objectTypeIsInteractionObject(int)`** (C) dispatch: interaction types via
  ffe23690 with argument 0; others via the ffe237e0/ffe23600 pickup family + the
  ffe23298 position + worldIndex removal.
- **Client-blockhead receive**: parses via the **shared 0x008b1db0 helper**
  (the same routine E21's loadAnyBlockheads calls) then applies through
  ffffe50c with the 0xfff33df4 string.
- **Gather pair**: both `gatherBlockAtPos:` and `loadGatherBlockAtPos:` use the
  type **0x1a (26)** (ffe235f0 lookup vs ffe235b0 creation).
- **loadedCountOfObjectsOfType:** reads the ffffe550 12-byte segment count
  (`mul` with 0xc).
- **connectionToServerLost** is an empty 5-word stub.

## Boundaries (honest)

- C symbols (`objectTypeIsInteractionObject`) and dispatch cells pinned; the
  shared-helper target 0x8b1db0 identified by E21 cross-reference; getter
  bodies are direct member returns (offsets observed); all 16 uncl cells
  resolve as PIC base anchors (clean); note two E35 candidates
  (loadGlowBlockIfNeededAtPos:tile:, teleportBlockhead:toWorkbench:) and
  tooManyNPCsToSpawnMoreNearPos: were already covered (E20 dyn_leaf / E27
  breed_npc) and were rejected by the coverage crosscheck.
