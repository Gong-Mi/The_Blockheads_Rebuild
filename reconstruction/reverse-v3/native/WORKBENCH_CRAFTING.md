# Workbench crafting engine cluster — E78 (electricity line)

The Workbench's crafting engine: the completion handler with the item-data
preservation, the craft start, the ownership transfer and the soft/hard
aborts.
**5 bodies, 5964 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wbcraft.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_crafting.json`.

| body | imp | words | content |
|---|---|---:|---|
| wc_craftcompleted | 0x00aeb47c | 1891 | completion + **preserveItemDataA** |
| wc_craftitem | 0x00afb164 | 1478 | craft start (39 objc) |
| wc_bhownership | 0x00ae7248 | 994 | ownership transfer |
| wc_abortcraft | 0x00ae9b78 | 979 | soft abort |
| wc_abortrestore | 0x00aeaac4 | 622 | hard abort |

## Load-bearing findings

- **The crafted-item data preservation**: `craftCompleted` calls
  **`preserveItemDataAInCraftedItem(ItemType, ItemType)` x2** (@0x00aebb94
  and @0x00aec42c) — the crafted output inherits the input item's **dataA**
  (the per-item data contract, matching the family's dataA/dataB storage in
  E75/E76); the bodies build the output records via the 7x
  stret/7x memset/4x memcpy family.
- **The state block**: the crafting state lives in ffffcffd0 (the crafting
  record, read x10-11 in the aborts) + fffff194/180/188/168/184/164/1a0
  (fraction) + ffffc8a0/c89c (position) + ffffc8b4/c8d8 (dirty) cells.
- **The craft keys**: **fff3c074/c064** (the craft-dict pair) appear in all
  four drivers; the ownership transfer uses its own save keys
  **fff3bf74/bf64/bf54** (the E77 save family).
- **The UI weight**: craftItem: carries **39 objc_msgSend** (the heaviest
  objc census of the class - the blockhead/UI interaction); the aborts run
  24/17 objc + the enumeration mutation.
- **The abort pair**: `abortCraft` (24 objc + 5x stret + 5x memset) restores
  partial items per progress; `abortImmediatelyAndRestoreBlockheadItems`
  (17 objc) is the same without the completion path.

## Boundaries (honest)

- uncl 39/39 resolve as PIC base anchors (clean).
- The five bodies are characterized by structural census (call tables + key
  pools + the load-bearing symbols); the ffe26xxx/fff3c0xx and stret record
  layouts stay opaque; the item-transfer arms read from the call sites.
