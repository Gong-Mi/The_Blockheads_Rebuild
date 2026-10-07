# DynamicWorld workbench/interaction cluster — E39

The workbench/interaction cluster: the workbench accessor/flag/UI-assigner, the
portal getter, the interaction lookup/type query and removers, the free-block
existence probe and the ID generator. **10 bodies, 887 verified words**, from
the pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_workbench.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_interaction.json`.

| body | imp | words | content |
|---|---|---:|---|
| assignCraftProgressUIToLoadedWorkbenches: | 0x008f0198 | 238 | craft-UI assigner |
| workbenchAtPos: | 0x008efe3c | 149 | workbench resolver |
| interactionObjectWithID: | 0x008f1048 | 143 | interaction lookup |
| freeBlocksExistAtPos: | 0x008f1564 | 86 | registry existence probe |
| removeWorkbenchAtPos:removeBlockhead: | 0x008f1354 | 66 | workbench removal |
| removeInteractionObjectAtPos:removeBlockhead: | 0x008f145c | 66 | interaction removal |
| interactionObjectTypeForObjectAtPos: | 0x008f1284 | 52 | 16-bit type query |
| portal | 0x008f0090 | 51 | portal getter |
| getNextDynamicObjectID | 0x008f1a78 | 21 | ID generator |
| workbenchHasBeenCrafted | 0x008f015c | 15 | flag getter |

## Load-bearing findings

- **workbenchAtPos:** — type **0x2d (45)** via ffe235f0 + the **y−1 probe**
  (`makeIntpair` after `sub ip, ip, 1`) + the ffe23678 check — the same y−1
  pattern as E38's doorAtPos:.
- **workbenchHasBeenCrafted** reads the **ffffe558 byte** directly — the flag
  E30's workbenchPlacedAtPosition: sets (getter pair confirmed).
- **assignCraftProgressUIToLoadedWorkbenches:** walks the **ffffe54c member's
  +0x21c workbench slice** (ffe2367c per node + `__tree_next`) then the
  ffffe550 side — the craft-UI assigner.
- **interactionObjectWithID:** — `arg >= 9` gate + the **0x00E4AA90 table**
  (**9 arms**) into the ffffe54c 12-byte segments (`__count_unique` /
  `operator[]`); miss continues the ffffe550 path.
- **interactionObjectTypeForObjectAtPos:** — ffe23570 fetch + the **ffe23688
  type read returned as uint16** (`strh`/`ldrh`) — the 16-bit type query.
- **Removal pair**: workbench leg (ffe233e0 check -> ffe23690 remove) vs
  interaction leg (ffe23570 fetch -> ffe23690 remove) — the shared ffe23690
  remover.
- **freeBlocksExistAtPos:** — `worldIndexAtWorldPos` + the **ffffe588
  registry** `__count_unique` — the third ffffe588 consumer (with E24's writer
  and E32/E35's movers).
- **getNextDynamicObjectID** — the **ffffe560 64-bit counter** incremented with
  carry (`adds/adc`) and returned.

## Boundaries (honest)

- All cells pinned by cell address; type codes and the uint16 return read from
  immediates/register widths; the +0x21c slice identity is offset-pinned;
  24 of 25 uncl cells resolve as PIC base anchors, the last is the 0xE4AA90
  table base; the ffffe550 continuations are covered by the listings.
