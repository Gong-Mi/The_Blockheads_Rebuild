# DynamicWorld query/accessor smalls — E34

The query/accessor smalls: the NPC and harmable-object lookups, the blockhead
ID lookup, the local/disconnected merge, the local net ID, the path-user
collector, the rail-name notification and the lights-ready check.
**8 bodies, 1133 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_query.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/query_access.json`.

| body | imp | words | content |
|---|---|---:|---|
| pathUsers | 0x008fdf6c | 334 | path-user collector |
| harmableDynamicObjectWithID: | 0x008f2630 | 157 | harmable-object lookup |
| blockheadWithIDIncludingNet: | 0x008f932c | 144 | net blockhead lookup |
| npcWithID: | 0x008f23f4 | 143 | NPC lookup |
| railOrStationNameChanged | 0x008fe280 | 137 | rail-name notification |
| localAndDisconnectedClientBlockheads | 0x008f67f8 | 87 | blockhead merge getter |
| localNetID | 0x008f6568 | 76 | local net ID |
| hasLightsToAdd | 0x009034b8 | 55 | lights-ready check |

## Load-bearing findings

- **npcWithID:** — the `arg >= 8` gate + the **0x00E4AA1C table** (8-arm) family
  slice of ffffe54c (12-byte striding) `__count_unique` → hit returns via
  `operator[](u64 const&)`; miss falls to the ffffe550 segment — the same
  two-registry lookup shape as E31's loadStandardDynamicObjectOfType:atPos:.
- **Registry lookups**: `blockheadWithIDIncludingNet:` and
  `harmableDynamicObjectWithID:` compare `[obj uniqueID]` via the **eor/orr
  64-bit equality** over their collections (the canonical ID probe).
- **Collection getters**: `localAndDisconnectedClientBlockheads` returns
  ffffe4f8 directly for clients and merges ffffe4f0 for servers;
  `localNetID` branches ffffe518 (client) vs ffffe51c (server) into ffe2327c.
- **pathUsers** builds a set (ffe2aeb0 + ffe2331c) and walks the **ffffe54c
  +0x1d4 path-user slice** (the slice E31's ridable cascade probes): per node
  the ffe23730 check + the **ffe23294 addObject:** collection + the found byte
  + `__tree_next` + the ffe23734 close.
- **railOrStationNameChanged** — the `arg >= 4` gate + the **0x00E4AA0C
  table** (4 arms) family slice walk with the ffe235e0 per-node call.
- **hasLightsToAdd** — the 0x41 gate + `objectTypeMayHaveArtificalLight(int)` +
  the ffffe550 12-byte segment count scan.

## Boundaries (honest)

- Table arms pinned by the gates (8/4); dispatch cells pinned; the +0x1d4 slice
  and ffffe4f0/ffffe4f8 merge semantics inferred from branches (pinned by
  offset); all but 3 uncl cells resolve as PIC anchors (21 cells: 18 pc-base +
  3 table bases 0xE4AA1C + 0xE4AA0C ×2); the listing continuation covers each
  body's tail.
