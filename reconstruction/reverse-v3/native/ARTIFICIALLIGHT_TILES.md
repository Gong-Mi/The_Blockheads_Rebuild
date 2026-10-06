# ArtificialLight register/unregister pair — addToTiles / removeFromTiles

Static map of the artificial-light half of the lighting system: how a torch /
lamp's per-channel colour and heat enter the tiles when the light is added,
and how they are exactly retracted when it goes away. Recovered from the
pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`), every
instruction word re-verified, tool refusing to emit on any drift (see
`tools/recover_artificiallight_tiles.py`; JSON: `artificiallight_tiles.json`).

## Bodies

| method | IMP | end (ARM.exidx) | words |
|---|---|---|---|
| `-[ArtificialLight addToTiles]` | `0x00a92238` | `0x00a93160` | 970 |
| `-[ArtificialLight removeFromTiles]` | `0x00a93198` | `0x00a93728` | 356 |

Total: 1326 verified words.

## -[ArtificialLight addToTiles]

**Step 1 — propagation seed.** An `std::list<unsigned int>` work list is
constructed and `push_back(worldIndexAtWorldPosition(self.pos.x, self.pos.y,
self.world))`; the body then drains it through
`-[self recursivelyUpdateLightWithList:&list]` behind a compiler-generated
list-state loop (condition byte-tested in the scaffold at `0xa92324..0xa9236c`,
call at `0xa92388`). The propagation engine itself (3075 words) is outside
this body — bounded boundary.

**Step 2 — contribution square.** For `i` in `[0, diameter)` and `j` in
`[0, diameter)`:

- `idx = i*diameter + j`; skip unless `addedGrid[idx] == 0`;
  `v = contributionGrid[idx*5]` (int16); skip when `v <= 0`.
- `x = contributionGridOrigin.x + j`, `y = contributionGridOrigin.y + i`;
  `mt = [self.world macroTiles]`; `tile = tileAtWorldPosition(x, y, mt,
  self.world)`; skip when `!tile`.
- `v0 = (float)v / ((float)radius * 5 * 2)` (i.e. `/(radius*10)`); the
  scaled per-channel values are written INTO the grid cell itself:
  `contributionGrid[idx*5+1] = (int16)(maxRed*v0)`,
  `+2 = (int16)(maxGreen*v0)`, `+3 = (int16)(maxBlue*v0)`,
  `+4 = (int16)(maxHeat*v0)`.
- Accumulate onto the tile's 16-bit colour/heat accumulators:
  `tile[0xe] += grid[+1]; tile[0x10] += grid[+2]; tile[0x12] += grid[+3];
  tile[0x14] += grid[+4]`; mark `addedGrid[idx] = 1`.
- **Content activation:** when `tileRequiresGlowBlock(tile)` →
  `[dw loadGlowBlockIfNeededAtPos:(x, y) tile:tile]` with
  `dw = [self.world dynamicWorld]`; else the `tile[0xb]` chain rewrites the
  byte down one and spawns a torch via `[dw addTorchAtPos:(x, y) ofType:kind
  dataA:0 dataB:0 saveDict:nil placedByClient:0]`:
  `0x34->0x33` kind `0x4b`, `0x36->0x35` kind `0x4c`,
  `0x38->0x37` kind `0x56`, `0x3a->0x39` kind `0x57`,
  `0x3c->0x3b` kind `0x58`; when `tile[3]`
  in `{0x5e, 0x90, 0x91}`: `loadTroll = (tile[3] != 0x91)`,
  `loadTreasure = (tile[3] != 0x90)`, `tile[3] = 0`, then when `tile[0] == 2`:
  `[dw createTreasureChestOrTrollAtTile:tile atPos:(x, y) loadTroll:
  loadTreasure:]`.
- **Per-cell tail:** wrap `px = origin.x + j` by `worldWidthMacro`
  (`px < 0` → `px += w*32`; `px >= w*32` → `px -= w*32`), `py = origin.y + i`;
  `recalculateDrawBlockLightingForTile(px, py, [self.world macroTiles],
  self.world)`; then `[dw lightChangedAtMacroPos:(px>>5, py>>5)
  sendReliably:1]`.

## -[ArtificialLight removeFromTiles]

The exact inverse walk. For `i` in `[0, diameter)` and `j` in
`[0, diameter)`:

- `idx = i*diameter + j`; skip unless `addedGrid[idx] == 1`;
  `v = contributionGrid[idx*5]` (int16); skip when `v <= 0`;
  `addedGrid[idx] = 0`.
- `x = origin.x + j`, `y = origin.y + i`; `mt = [self.world macroTiles]`;
  `tile = tileAtWorldPosition(x, y, mt, self.world)`; skip when `!tile`.
- `tile[0xe] -= grid[+1]; tile[0x10] -= grid[+2]; tile[0x12] -= grid[+3];
  tile[0x14] -= grid[+4]`.
- **Underflow guard:** when any of `tile[0xe]`, `tile[0x10]`, `tile[0x12]`
  (unsigned 16-bit, loaded with `ldrh`) exceeds `0xdfff`
  (`movw r0, 0xdfff` at `0xa93480`), ALL four accumulators are zeroed.
- `px = origin.x + j` wrapped by `worldWidthMacro` (`px >= w*32` →
  `px -= w*32`, then `px < 0` → `px += w*32`);
  `recalculateDrawBlockLightingForTile(x, y, mt, self.world)`; then
  `[self.dynamicWorld lightChangedAtMacroPos:(px>>5, py>>5) sendReliably:1]`.

No list, no propagation engine — the removal is purely the contribution
subtraction plus reporting. Note the receiver difference: the add path
reaches the dynamic world as `[self.world dynamicWorld]`, the remove path
loads `DynamicObject.dynamicWorld` directly.

## Class layout anchors (resolved ivar descriptors)

| ivar | offset | cell(s) |
|---|---|---|
| `DynamicObject.pos` | 16 | `0xa93084` |
| `DynamicObject.world` | 4 | `0xa9308c`, `0xa936f8` |
| `DynamicObject.dynamicWorld` | 8 | `0xa93718` |
| `ArtificialLight.contributionGrid` | 56 | `0xa93098`, `0xa936f0` |
| `ArtificialLight.addedGrid` | 60 | `0xa93094`, `0xa936ec` |
| `ArtificialLight.maxRed` | 64 | `0xa930b8` |
| `ArtificialLight.maxGreen` | 68 | `0xa930bc` |
| `ArtificialLight.maxBlue` | 72 | `0xa930c0` |
| `ArtificialLight.maxHeat` | 76 | `0xa930c4` |
| `ArtificialLight.radius` | 80 | `0xa930b4` |
| `ArtificialLight.contributionGridOrigin` | 84 | `0xa930a0`, `0xa93704` |
| `ArtificialLight.diameter` | 92 | `0xa93090`, `0xa936e8` |

Selector cells: `macroTiles` (`0xa930a8`, `0xa93700`), `worldWidthMacro`
(`0xa93138`, `0xa93710`), `lightChangedAtMacroPos:sendReliably:`
(`0xa9314c`, `0xa93720`), `loadGlowBlockIfNeededAtPos:tile:` (`0xa93124`),
`addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:` (`0xa930e4`),
`createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:` (`0xa930d4`),
`recursivelyUpdateLightWithList:` (`0xa93154`), `dynamicWorld` (`0xa930cc`).

## Direct call anchors

`worldIndexAtWorldPosition(int,int,World*)` `0xa156a8`;
`tileAtWorldPosition(int,int,MacroTile*,World*)` `0xa16e68`;
`recalculateDrawBlockLightingForTile(int,int,MacroTile*,World*)` `0xa18f68`;
`tileRequiresGlowBlock(Tile*)` `0xa14824`;
`makeIntpair(int,int)` `0x4b49fc`;
`std::__1::list<unsigned int>::push_back` `0xa91e48`;
`std::__1::list<unsigned int>::~list` `0xa93160` (add) / `0xa9306c` (dtor call).

## Boundaries

- `recursivelyUpdateLightWithList:`'s own body (the propagation engine) is
  NOT mapped here — only its invocation site and work-list seed.
- `Tile` accumulators at `0xe/0x10/0x12/0x14` are read/written as 16-bit
  ints; their consumer (draw-block lighting) is the WorldHelper line.
- The `0xdfff` guard is recorded mechanically: any of the three
  `ldrh`-loaded accumulators above `0xdfff` (after subtraction) zeroes all
  four; the exact intended range semantics stay as observed.
- Branch/call sets, instruction anchors, negative controls (JSON semantics
  mutation, listing word drift) are enforced by
  `tools/test_artificiallight_tiles_evidence.py`.
