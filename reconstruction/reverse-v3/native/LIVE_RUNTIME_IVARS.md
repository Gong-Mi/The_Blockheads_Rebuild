# Live runtime ivar offsets (corrected)

**(Corrected 2026-10-02.)** The first revision of this file carried 527 "live" values that
were a cross-build misread: they were the cell contents of neighboring symbols (the same
uniform +0x50 shift documented in `IVAR_OFFSET_READING.md`), not the runtime layout. Its
pinned examples were wrong — it claimed `Blockhead.headCube = 712` (actual 212),
`Blockhead.state = 728` (actual 56), `World.saveID = 3460` (actual 436),
`DynamicWorld.world = 9496` (actual 4).

## Corrected data

`live_runtime_ivar_offsets.json` (schema 2) now carries the pinned-ELF cell values for the
same 527 ivars of the four core classes:

- a same-build audit shows these file values equal the runtime offsets, and **no cell of
  these four classes is in the 79-cell rewritten set** (`IVAR_OFFSET_READING.md`);
- all 527 values are **identical between the pinned 1.7.6 ELF and the audited live 1.7.5
  build**;
- **90 of the 527** are additionally verified hop-by-hop through a live object graph
  (`live_verified_fields.json`).

Verified examples (live object graph, 2026-10-02):

### Blockhead (bones & rendering)
- `Blockhead.headCube` = 212, `bodyCube` = 228, `armCube` = 236, `legCube` = 244

### DynamicObject (base)
- `DynamicObject.world` = 4, `DynamicObject.dynamicWorld` = 8

### DynamicWorld (container & bridge)
- `DynamicWorld.world` = 4, `DynamicWorld.blockheads` = 44,
  `DynamicWorld.worldDatabase` = 32, `DynamicWorld.worldSaveDirectory` = 40

### World (persistence & UI)
- `World.saveID` = 436, `World.worldName` = 440, `World.dynamicWorld` = 416,
  `World.uiManager` = 240

## Scope of the corrected table

A total of **527 ivar offsets** across four core classes:

| Class | Count |
|---|---:|
| `Blockhead` | 221 |
| `DynamicObject` | 13 |
| `World` | 227 |
| `DynamicWorld` | 66 |

## Artifacts and verification

- `live_runtime_ivar_offsets.json` — all 527 values; `verified_live` lists the 90
  object-graph-verified names.
- `live_verified_fields.json` — the full 153-field object-graph verification (six objects).
- `IVAR_OFFSET_READING.md` — correction, method, chain, boundaries.
- Contract test: `tools/test_live_runtime_ivars.py` (no device needed).
