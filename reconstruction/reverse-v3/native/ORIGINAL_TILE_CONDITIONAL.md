# Conditional TileType resolution (foreground_arg == 0 switch)

Evidence grade: **A** — read directly from the pinned original ARM ELF; every row
is regenerated deterministically and gated by contract tests.

- Original ELF: `libApplication.so` (armeabi-v7a), SHA-256
  `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
- Function: `itemTypeFromTileIsForegorund` @ `0x00a18044` (3496 bytes),
  `foreground_arg == 0` jump table @ `0x00a1868c`, TileTypes 1..77
- Default path: `0x00a18dac` (`movw r0, #0`), epilogue `0x00a18db8`

## What was missing

`tools/extract_original_tile_item_map.py` accepts only the exact
`movw r0, #imm; str r0, [fp, #-4]; b <epilogue>` case shape. 68 of the 77
entries match (44 yield an ItemType, 24 store literal 0). The remaining **nine**
entries inspect another Tile field and were marked `conditional` instead of
guessed: TileTypes 1, 2, 3, 5, 6, 12, 13, 27, 28.

## What the nine entries do

They compare **`OriginalTile.contentsType()`** — the byte at offset 3 of the
64-byte original Tile (`app/src/main/cpp/original_save_format.h`) — against
ItemTypes, and return the ItemType the tile yields. Shape:

```text
ldr  r0, [fp, #-0x14]     ; the Tile* argument
ldrb r0, [r0, #3]         ; contentsType()
cmp  r0, #<item type>
bne  next                 ; or `beq <value block>`
movw r0, #<item type>
str  r0, [fp, #-4]
b    <epilogue>
```

Four case bodies cover the nine TileTypes:

| case target | TileTypes | chain | fallback |
|---|---|---|---|
| `0x00a187c0` | 2, 3, 5 | 96→178, 3/21/24/9/6/15→4, **helper `0x00a11390`**, **helper `0x00a138fc`**, 12/18/89/43/110/113/116/113/122→4, 103→1087, 104→1088, 101→0 (*tail unresolved*) | none |
| `0x00a18a98` | 6, 27, 28 | 1→3, 2→28 | 1048 |
| `0x00a18b04` | 1 | 61→31, 62→36, 63→32, 65→51, 77→73, 106→261, 107→279 | 1024 |
| `0x00a18c10` | 12, 13 | 64→48 | 1028 |

Two boundaries are recorded, never guessed:

- **Helper-gated** (`bl 0x00a11390`, `bl 0x00a138fc`): the branch is taken when
  the helper returns non-zero. Chain order therefore matters — the comparisons
  listed after a gate are only reached when that helper returned 0, so a
  `contentsType()` value matching after a gate must not be applied.
- **Tail unresolved**: `movw r0, #0` followed by further setup
  (`ldr r1, [fp, #-0x1c]`) at `0x00a189d0` — an assignment this map cannot
  follow. It is reachable only behind the helper gate.

## Tooling and gates

| artifact | role |
|---|---|
| `tools/extract_original_tile_conditional.py` | walks each conditional case chain over the pinned ELF; emits the TSV + JSON evidence record; fails loudly on an unrecognised shape |
| `reconstruction/reverse-v3/native/original_tile_conditional.tsv` | flattened rows (`tile_type, resolution, depends_on, contents_type, item_type, helper, case_target, step_index, status`) |
| `reconstruction/reverse-v3/native/original_tile_conditional.json` | per-case chain record: helper markers, fallback, termination |
| `tools/gen_tile_conditional_table.py` | generates the APK decode product from the JSON (`--check` gated) |
| `app/src/main/cpp/original_tile_conditional_table.inc` | `kConditionalTileSteps` / `kConditionalTileFallbacks` (committed, `--check` gated, same convention as `dynamic_object_type_table.inc`) |
| `tools/test_tile_conditional_evidence.py` | CI contract: JSON ↔ TSV ↔ `.inc` lockstep, chain order, helper placement, pinned ELF identity (no ELF needed) |
| `tools/validate_reverse_evidence.py` | requires the artifacts and that the resolved TileType set equals the nine `conditional` rows of `original_tile_item_map.tsv` |

Negative controls run locally: mutating the `.inc` fails the contract test;
editing the TSV fails JSON↔TSV lockstep.

## Replacement-side use

`app/src/main/cpp/original_world_import.cpp` maps a decoded tile through
`mapOriginalTile()`: direct assignment first, then the ordered conditional
chain. The walk stops at the first helper-gated or unresolved step, so a later
comparison is never applied. `WorldImportReport` records the outcome:

- `tiles_conditional_mapped` — tiles resolved through `contentsType()`
- `unmapped_by_reason` — `conditional_helper_gated`, `conditional_tail_unresolved`,
  `no_compat_id`, `no_mapping`

Host tests (`world_import`) pin the behaviour: TileType 6 with contents 0 takes
the 1048 fallback (→ dirt), TileType 12 with contents 0 resolves to 1028 which
has no rebuild counterpart and stays counted, and TileType 2 with contents 12
reports helper-gated instead of applying the post-gate comparison.

## Boundaries (not claimed)

- The two helpers (`0x00a11390`, `0x00a138fc`) are **not** modelled: any tile
  whose chain reaches them is reported, not resolved.
- `ConditionalUnresolved` is currently unreachable from the committed chains
  because the only known tail sits behind the helper gate; the enum variant is
  kept so a future chain can report it.
- The resolved value is a **client-domain ItemType**. Conversion into the
  replacement compatibility id still goes through
  `ItemManager::fromOriginalType`, and ItemTypes without a counterpart stay
  counted (`no_compat_id`).
- Back wall (`Tile[1]`) remains unmapped; no per-value A-grade mapping exists.
- No device run and no original-runtime differential is claimed by this batch.
