# WorldHelper recursivelyUpdateSunLightWithList: — the single-step light-up engine

Original ELF `libApplication.so` (armeabi-v7a), SHA-256 `733d8210…b94c7`.
One class body, word-verified against the pinned bytes by
`tools/recover_worldhelper_recursiveupdate.py --check`:

| method | IMP | bounded end | words |
|---|---|---|---|
| `+[recursivelyUpdateSunLightWithList:openIndices:world:]` | `0x00a19c0c` | `0x00a1b7d4` | 1778 |

The engine the per-tile updater (`+[updateSunLightForTile:atPos:world:]`,
mapped in `WORLDHELPER_SUNLIGHT.md`) drains in its `while ([array count] > 0)`
loop — the updater twin of the removal engine (`WORLDHELPER_RECURSIVE_REMOVE.md`).
**No internal loop** (all 164 branches forward); one call processes one work
item.

## The step

```text
obj = [list objectAtIndex:0];  idx = [obj intValue];
[list removeObjectAtIndex:0];  [openIndices removeIndex:idx];
dw = [world dynamicWorld];     isClient = [dw isClient];
getWorldPosForWorldIndex(idx, &x, &y, world);
tile = tileAtWorldPosition(x, y, [world macroTiles], world);   // MacroTile path
if (tile == 0) return;
if ((signed char)tile[9] <= 0) return;                          // byte-9 gate
```

## LIT path — the tile opens to the sky

Triggered when `(tileIsAirOrSnow(tile) && tile[1] == 2)` **or**
`tile[0xc] ∈ {0x45, 0x5f}` (contents byte = 69 or 95):

```text
tile[7] = 0xff;                      // full sun
if (tile[0xc] ∈ {0x45, 0x5f}) tile[7] = 0xef;
recalculateDrawBlockLightingForTile(x, y, [world macroTiles], world);
four neighbour enqueues (y+1, y-1, x+1, x-1):
    skip if !tn;  skip if tn[7] == 0xff (already full);
    skip if tn[0xc] ∈ {0x45, 0x5f};
    nidx = worldIndexAtWorldPosition(...);
    skip if nidx < 0 or [openIndices containsIndex:nidx];
    else [list addObject:[NSNumber numberWithInt:nidx]] +
         [openIndices addIndex:nidx];
return;
```

## SHADOW path — the tile is occluded; light descends from six neighbours

Otherwise the tile keeps its shadowed state and recomputes:

```text
cur = tile[7]; max = 0;
for (dx, dy) in [(0,+1), (0,-1), (+1,0), (-1,0), (+1,+1), (-1,+1)]:
    tn = tileAtWorldPositionLoaded(x+dx, y+dy, world);
    if (!tn)                                contribution = 0;
    elif (tileIsAirOrSnow(tn) && tn[1] ∈ {2,3}):
        contribution = (dy == +1 && dx == 0) ? 0xff : 0xe0;   // window; only
                                                              // straight-up is full
    else:
        base = (tn[7] > 0xef) ? 2 : 8;
        if (tn[0] == 3 || tileIsSemiTransparentSolidBlock(tn)) base = 0x10;
        elif (!tileIsAirOrSnow(tn))                            base = 0x41;
        contribution = max(tn[7] - base, 0);
    max = max(max, contribution);
if (max <= tile[7]) return;
tile[7] = max;
[world saveSunlightChangedAtPos:makeIntpair(x, y)];
```

- **Stencil**: N, S, E, W plus the two upper diagonals NE (+1,+1) and NW
  (−1,+1) — no lower diagonals; six blocks, each with its own contribution
  slot and comparison.
- **Attenuation**: a nearly-full neighbour (> 0xef) loses only 2; a dimmer one
  8; semi-transparent solids (or type 3) 16; opaque solid 65. The saturated
  0xef the lit path writes for contents 69/95 therefore attenuates at the 8
  tier.
- **Window rule**: air-or-snow with back wall 2 or 3 passes 255 when directly
  above (y+1) but 224 from every other direction.

## Server-only content activation (after a raise)

When `!isClient`, the tile's `tile[0xb]` byte drives a rewrite-and-spawn
chain, each case rewriting the byte down by one and spawning the matching
dynamic object through `[dw addTorchAtPos:pair ofType:kind dataA:0 dataB:0
saveDict:nil placedByClient:0]`:

| tile[0xb] | becomes | spawn |
|---|---|---|
| 0x34 | 0x33 | torch kind `0x4b` |
| 0x36 | 0x35 | torch kind `0x4c` |
| 0x38 | 0x37 | torch kind `0x56` |
| 0x3a | 0x39 | torch kind `0x57` |
| 0x3c | 0x3b | torch kind `0x58` |

Then, when `tile[3] ∈ {0x5e, 0x90, 0x91}`:

```text
loadTroll    = (tile[3] != 0x91);   // 0x91 → treasure only
loadTreasure = (tile[3] != 0x90);   // 0x90 → troll only; 0x5e → both
tile[3] = 0;
if (tile[0] == 2)
    [dw createTreasureChestOrTrollAtTile:tile atPos:pair
     loadTroll:loadTroll loadTreasure:loadTreasure];
```

`loadGlowBlockIfNeededAtPos:tile:` (tile 0x00a1b7bc) is the sibling call on the
`tileRequiresGlowBlock(tile)` branch at `0xa1abc0` (glow-capable tiles load
their glow block when the light reaches them).

## Common tail (both client and server)

```text
recalculateDrawBlockLightingForTile(x, y, [world macroTiles], world);
six re-enqueue checks, same neighbour order (N, S, E, W, NE, NW):
    when (max > contribution_k) and nidx valid and not in [openIndices]:
        enqueue the neighbour (addObject + addIndex);
return;
```

## Anchored facts

- 21 selector cells (pop protocol, containers, `saveSunlightChangedAtPos:`,
  `addTorchAtPos:…`, `createTreasureChestOrTrollAtTile:…`,
  `loadGlowBlockIfNeededAtPos:tile:`, `macroTiles`, `isClient`,
  `dynamicWorld` ×2 cells), `NSNumber` classref via `.rel.dyn`, two
  `objc_msgSend` GOT cells.
- All 116 call sites with pinned direct-call targets:
  `getWorldPosForWorldIndex` `0x00a15518`, `tileAtWorldPosition` (MacroTile)
  `0x00a16e68`, `tileAtWorldPositionLoaded` `0x00a12f24` (×10),
  `tileIsAirOrSnow` `0x00a12760` (×13), `tileIsSemiTransparentSolidBlock`
  `0x00a128b0` (×6), `tileRequiresGlowBlock` `0x00a14824`,
  `worldIndexAtWorldPosition` `0x00a156a8` (×10),
  `recalculateDrawBlockLightingForTile` `0x00a18f68` (×2), `makeIntpair`
  `0x004b49fc` (×8), and 15 direct `bl` to the cached `objc_msgSend` thunk
  `0x001c281c`.
- All 164 branches pinned exactly (set equality); key stores anchored
  (`strb` of 0xff/0xef/0xef-shadow, the byte-9 gate load, the 2/8/0x10/0x41
  attenuation seeds, the 0x33/0x35/0x39/0x3b rewrites, the `tile[3] = 0`
  store).

## Boundaries

- No own ARM.exidx entry; closed by the next method IMP (`0x00a1b7d4`).
- The dynamic-object factories behind the content activation (torch
  construction, chest/troll spawning, glow-block loading), `Tile`/`MacroTile`
  internals and the renderer behind `recalculateDrawBlockLightingForTile` are
  **outside this body**.
- `tile[0xb]`/`tile[0xc]`/`tile[3]` value names are not claimed; the cases are
  recorded as the code compares them.
- No runtime claim; no device run.

## Artifacts

| artifact | role |
|---|---|
| `tools/recover_worldhelper_recursiveupdate.py` | hash-gated extractor; `--check` re-verifies every anchor |
| `disasm_worldhelper_recursiveupdatesunlight.txt` | the bounded listing |
| `worldhelper_recursiveupdate.json` | machine record: selectors/classrefs/calls/branches |
| `tools/test_worldhelper_recursiveupdate_evidence.py` | CI contract on the committed JSON (no ELF needed) |
