# DynamicWorld reload-tail & lifecycle smalls — E29

The reload-contract tail and lifecycle smalls: three reload instantiations
(item/glow/egg), the C++ member destructor inventory, the artificial-light
contribution, the save-worthiness check, the unload notification and the
free-block position reader. **8 bodies, 2280 verified words**, from the pinned
original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_reload_tail.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/reload_tail.json`.

| body | imp | words | content |
|---|---|---:|---|
| reloadLightGlowQuadsForMacroTile: | 0x00900ca0 | 312 | reload instantiation |
| reloadDynamicObjectItemQuadsForMacroTile: | 0x009007c0 | 312 | reload instantiation |
| reloadDodoEggQuadsForMacroTile: | 0x008ff3dc | 312 | reload instantiation |
| .cxx_destruct | 0x00906ccc | 339 | member destructor inventory |
| addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos: | 0x00903014 | 259 | light contribution |
| hasDynamicObjectsToSaveInMacroPos: | 0x008c98a0 | 259 | save-worthiness check |
| blockheadWillBeUnloaded: | 0x00901180 | 248 | unload notification |
| freeBlocksAtPos: | 0x008f16bc | 239 | free-block position reader |

## Load-bearing findings

- **Reload trio**: THREE byte-identical instantiations (byte-diff = 4 words each:
  base cell + 2 pool words + selector cell) of the E25 reload contract at the
  **+0x1c4/+0x1c8** keeper slot with `__wrap_malloc(count*2*4*0x60)` and
  `__wrap_exit(0)` on NULL; per-family selectors ffe23774 (item) and siblings.
- **Member destructor inventory** (`.cxx_destruct`): the exact container member
  chain — `~list<u64>` (ffffe5c8); `~vector<intpair>` over ffffe570, the
  **ffffe578 member with its 0x30c/12 = 65-element loop**, ffffe5dc, ffffe5c4,
  ffffe5c0, the **ffffe56c member with its 0x180/12 = 32-element loop (the 32
  light-channel structs — matching E28's cmp 0x20)**, ffffe57c, ffffe580,
  ffffe574, ffffe5b8, the **ffffe58c 0x30c/12 = 65-element loop**;
  `~vector<DynamicObject*>` over the ffffe5a0 member's 0x514/12 loop;
  `~unordered_set<u32>` (ffffe5a0+0x514) and `~unordered_set<u64>` (ffffe584).
  This body pins the container run lengths (65-segment arrays, 32 light slots).
- **Light contribution**: `objectTypeMayHaveArtificalLight(int)` (C) + ffffe54c
  then ffffe550 segments with the ffe237c0 per-node call.
- **Save-worthiness**: client gate (false when client set) + the 0x41 loop over
  the ffffe578 12-byte segments + the ffffe570 queue check.
- **Unload notification**: 0x41 loop over ffffe54c/ffffe550 with ffe23784 per
  node.
- **Free-block reader**: `worldIndexAtWorldPos` -> ffffe588 `__count_unique` ->
  `operator[]` -> set iteration with ffe234ac gate + `addObject:` — the READER of
  E24's master-factory registration.

## Boundaries (honest)

- Selector/bindings pinned by cell; `objectTypeMayHaveArtificalLight` and the
  ffe237xx call bodies are outside the batch; the destructor tail members beyond
  the cited chain are recorded from the continuing deallocation sequence; all
  15 uncl cells resolve as PIC base anchors (clean).
