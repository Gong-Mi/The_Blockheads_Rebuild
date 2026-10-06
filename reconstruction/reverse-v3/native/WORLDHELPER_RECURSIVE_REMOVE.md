# WorldHelper recursivelyRemoveAllSunLightWithList: — the single-step removal engine

Original ELF `libApplication.so` (armeabi-v7a), SHA-256 `733d8210…b94c7`.
One class body, word-verified against the pinned bytes by
`tools/recover_worldhelper_recursiveremove.py --check`:

| method | IMP | bounded end | words |
|---|---|---|---|
| `+[recursivelyRemoveAllSunLightWithList:openIndices:lightWasRemovedList:removeIndices:world:minx:maxX:]` | `0x00a1bd10` | `0x00a1c680` | 604 |

This is the **single-step work-item engine** the per-tile remover
(`+[updateSunLightRemovedForTile:atPos:world:]`, mapped in
`WORLDHELPER_SUNLIGHT.md`) drains in its `while ([list count] > 0)` loop:
one call pops exactly one item, clears one tile's sunlight byte, and
re-enqueues its lit neighbours. There is **no loop inside the body** — all
51 branches are forward; the caller drives the repetition.

## The step

```text
obj = [list objectAtIndex:0];  idx = [obj intValue];
[list removeObjectAtIndex:0];  [openIndices removeIndex:idx];
x = 0; y = 0;
getWorldPosForWorldIndex(idx, &x, &y, world);
tile = tileAtWorldPositionLoaded(x, y, world);
if (tile == 0) return;                                    // aborts this item
if (tileIsAirOrSnow(tile) && (tile[1] == 2 || tile[1] == 3)) return;
lvl = tile[7];
if (lvl == 0) return;                                     // nothing to remove
tile[7] = 0;                                              // clear first ...
mt = [world macroTiles];
recalculateDrawBlockLightingForTile(x, y, mt, world);     // ... then recalc
[lightWasRemovedList addObject:[NSNumber numberWithInt:idx]];
[removeIndices addIndex:idx];
```

- The pop protocol is anchored: `objectAtIndex:0` → `intValue` →
  `removeObjectAtIndex:0` → `[openIndices removeIndex:]` (four sends at
  `0xa1bdec/bdfc/be18/be30`).
- The clear happens **before** the two lighting calls (`strb r3, [ip, 7]`
  at `0xa1bee0`, with `movw r3, 0` immediately before).
- The current-tile aborts (`tile == nil`, air-or-snow with back wall 2 or 3,
  `lvl == 0`) jump straight to the epilogue: neighbours are **not** examined.
- `tile[1]` is the back-wall byte, `tile[7]` the sunlight byte — the same
  fields the per-tile pair and the save records use.

## The four neighbour passes (order: y+1, y-1, x+1, x-1)

For each neighbour `(dx, dy)`:

```text
(x-neighbours only) skip when x+1 >= maxX (dx=+1) or x-1 < minx (dx=-1)
tn = tileAtWorldPositionLoaded(x+dx, y+dy, world);  if (!tn) skip
if (tn[7] == 0 || tn[7] > lvl) skip      // level monotonicity vs the popped tile
if (tileIsAirOrSnow(tn) && tn[1] in {2, 3}) skip
nidx = worldIndexAtWorldPosition(x+dx, y+dy, world);  if (nidx < 0) skip
if ([openIndices containsIndex:nidx]) skip
[list addObject:[NSNumber numberWithInt:nidx]];
[openIndices addIndex:nidx];
```

- **Level monotonicity**: only neighbours lit at or below the removed level
  (`0 < tn[7] <= lvl`) are swept — the removal wave descends, it never
  climbs onto brighter tiles.
- **Horizontal window**: the two x neighbours are clamped by the
  `minx`/`maxX` arguments (the `x-32 .. x+32` band the caller computed); the
  y neighbours are unbounded.
- Neighbour aborts fall through to the next pass (chained `b` trampolines at
  `0xa1c158/15c/160`, `0xa1c2e8/2ec/2f0`, `0xa1c48c/490/494/498`,
  `0xa1c634/638/63c/640/644`), unlike the current-tile aborts.
- All four passes collect through the same four sends
  (`containsIndex:` → `numberWithInt:` → `addObject:` → `addIndex:`); the
  receivers are the caller's `list` and `openIndices` (arg1/arg2 slots).

## Anchored facts

- Container/call anchors: `openIndices` slot `0x00e84c88` is `removeIndex:`,
  `0x00e84c90` `containsIndex:`, `0x00e84c9c` `addIndex:`, `0x00e84c98`
  `addObject:`, `0x00e84c94` `numberWithInt:`, `0x00e84c7c`
  `objectAtIndex:`, `0x00e84c80` `intValue`, `0x00e84c84`
  `removeObjectAtIndex:`, `0x00e84c70` `macroTiles`; `NSNumber` classref via
  `.rel.dyn` at `0x00e8ae74`.
- Direct calls and targets: `getWorldPosForWorldIndex` `0x00a15518`,
  `tileAtWorldPositionLoaded` `0x00a12f24` (×5), `tileIsAirOrSnow`
  `0x00a12760` (×5), `worldIndexAtWorldPosition` `0x00a156a8` (×4),
  `recalculateDrawBlockLightingForTile` `0x00a18f68`.
- 40 call sites and all 51 branches are pinned exactly (set equality).

## Boundaries

- No own ARM.exidx entry; closed by the next method IMP (`0x00a1c680`).
- The updater twin (`recursivelyUpdateSunLightWithList:openIndices:world:`,
  `0x00a19c0c`), `recalculateDrawBlockLightingForTile` and the Tile/MacroTile
  internals are **outside this body** — this batch anchors the removal
  engine's own step and queue discipline only.
- `tile[7]` semantics (sunlight/light byte) are used at the level the
  recovered per-tile pair and the save-record profiling established; no new
  field meaning is claimed here.
- No runtime claim; no device run.

## Artifacts

| artifact | role |
|---|---|
| `tools/recover_worldhelper_recursiveremove.py` | hash-gated extractor; `--check` re-verifies every anchor |
| `disasm_worldhelper_recursiveremovesunlight.txt` | the bounded listing |
| `worldhelper_recursiveremove.json` | machine record: selectors/classref/calls/branches |
| `tools/test_worldhelper_recursiveremove_evidence.py` | CI contract on the committed JSON (no ELF needed) |
