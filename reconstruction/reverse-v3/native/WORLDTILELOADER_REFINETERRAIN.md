# WorldTileLoader -[refineTerrain] static map

Original ELF SHA-256 `733d8210…b94c7`; types `v8@0:4`. IMP `0x00854c54`,
ARM.exidx end `0x00855ad0`, 927 words verified against the pinned bytes
(`tools/recover_worldtileloader_refineterrain.py --check`). PIC base
`0x0105faf4`, materialised twice (r2, r8) and per-site via pc pairs — a
single shared GOT base for this compilation unit. This is the main terrain
refinement orchestrator and the consumer of every slice mapped so far:
`refineTerrainCount`, `faultOffsetForX:y:`, `isCaveForX:y:faultOffset:`,
and the `getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:` /
`worldWidthMacro` pair it queries.

## Call census (all 39 sites, byte-decoded)

Flavours: `stub` = bl to the cached `objc_msgSend@plt`; `got` = blx register
holding `objc_msgSend` from GOT slot 0x0105b7a0; `plt-idiv`/`plt-modsi3` =
bl through PLT 0x001c3728/0x001c3020 (field-decoded to JUMP_SLOTs
0x106001c/0x105fdc4); `rand` = bl to local unsymbolised function
`0x008540cc` (inside the `initWithWorld:randomSeed:…` IMP range);
`tileat`/`makepair` = direct bl to `_Z25tileAtWorldPositionLoadediiP5World`
(0x00a12f24) / `_Z11makeIntpairii` (0x004b49fc).

Per-iteration send pairs (four copies each pattern):
`[self faultOffsetForX:i y:randX]` (selector cell 0x00855a7c → slot
0x00e82404) immediately followed by `[self isCaveForX:i y:randX
faultOffset:faultOffset]` (cell 0x00855a78 → slot 0x00e82408), with `sxtb`
on the char result gating the carve — the sxtb/char-return coherence is what
pinned the single-base resolution (an off-by-4 base makes the second send
`faultOffsetForX:y:` whose 512-scaled int result would gate dead).

## Anchored cells (base 0x0105faf4)

| cell | slot | fact |
|---|---|---|
| 0x00855a3c | 0x0105ddbc | ivar `refineTerrainCount` (offset 232) |
| 0x00855a68 | 0x0105ddc0 | ivar `hasRefinedTerrain` (offset 104) |
| 0x00855a50 | 0x0105dd4c | ivar `world` (offset 4) |
| 0x00855a6c | 0x0105dd60 | ivar `rockHeights` (offset 96) |
| 0x00855a74 | 0x0105dd5c | ivar `dirtHeights` (offset 92) |
| 0x00855a40 | 0x0105b7a0 | import `objc_msgSend` |
| 0x00855a4c | 0x00e8a8a0 | classref `OBJC_CLASS_$_NSAutoreleasePool` (reloc-verified) |
| 0x00855a44/48/64 | 0x00e823a4/bc/414 | selectors `init` / `alloc` / `release` |
| 0x00855a58 | 0x00e823a8 | selector `worldWidthMacro` |
| 0x00855a60 | 0x00e82434 | selector `decommisionAllBlocksBlockToSavePhyscialBlock:` |
| 0x00855a7c | 0x00e82404 | selector `faultOffsetForX:y:` |
| 0x00855a78 | 0x00e82408 | selector `isCaveForX:y:faultOffset:` |
| 0x00855a80+84 | (pc pair) 0x00e82430 | selector `recursivelyFlowOutWaterFromTile:atPos:` |

## Reviewed semantics (static CFG)

```text
pool = [[NSAutoreleasePool alloc] init];                    // fp-0x28
w4   = [self->world worldWidthMacro] / 4;                   // (w<<5)/0x80, fp-0x24
for (i = self->refineTerrainCount;                         // ivar 232
     i < self->refineTerrainCount + w4;                     // bge 0x00854d90
     i++) {
    [pool release]; pool = [[NSAutoreleasePool alloc] init];// per-iteration recycle
    colRock = self->rockHeights[i];  colDirt = self->dirtHeights[i];
    byte    = (colRock < colDirt);                          // fp-0x2d
    modX1   = (colRock + w*32 - 1) % (w*32);                // fp-0x34
    modX2   = (colDirt + w*32 - 1) % (w*32);                // fp-0x38
    if (rand() % 8 == 0) {                                  // 1/8 sampling
        randX = rand() % (colRock - 1);                     // fp-0x48
        faultOffset = [self faultOffsetForX:i y:randX];     // fp-0x4c
        if ([self isCaveForX:i y:randX faultOffset:faultOffset])
            punch(i, randX);
    }
    three column-fill loops: same faultOffset/isCave pair per
    scanline yy descending the column range, punch(i, yy)
}
punch(x, y):                                                // 4 identical bodies
    tile = tileAtWorldPositionLoaded(x, y, self->world);
    if (tile->byte0 != 0x1f) {                              // 0x1f = leave-alone marker
        tile->byte0 = 3;  tile->byte4 = 0xff;  tile->byte7 = 0;
        [self recursivelyFlowOutWaterFromTile:tile
         atPos:makeIntpair(x, y)];
    }
exit:
    self->refineTerrainCount += w4;                         // 0x00855954..0x00855970
    [world decommisionAllBlocksBlockToSavePhyscialBlock:1]; // 0x00855988..0x008559b0
    if (w*32 - 1 == <world-queried value>)                  // 0x008559f8..0x00855a10
        self->hasRefinedTerrain = 1;                        // byte store, ivar 104
```

## Structural notes

- `refineTerrainCount` is a cumulative scan cursor, not an iteration count:
  each pass carves one `worldWidthMacro/4`-wide band and advances the cursor;
  the pass schedule lives in the caller. `hasRefinedTerrain` is the
  completion byte.
- The `sxtb` gate coherence (see above) is the load-bearing fact that locked
  the whole body to base 0x0105faf4; every earlier hand-arithmetic attempt
  that produced 0x0105faf0 made the carve gates dead code, which the shipped
  game cannot be.
- Each iteration releases and recreates its `NSAutoreleasePool` — carving
  churns autoreleased tile/pair objects, so the pool is recycled per
  scanline band rather than per call.
- The tile punch writes byte0=3 (air), byte4=0xff, byte7=0 and then calls
  `recursivelyFlowOutWaterFromTile:atPos:` — punched caves drain water.
- 47 branch sites are byte-verified; the `>= 0x200` (512) comparisons are
  the same world-width cap seen in `faultOffsetForX:y:`.

Claim boundary: static bounded-body map. The data flow between modX1/modX2
and the column-fill loop bounds (fp-0x44/fp-0x6c chains) is census-level,
not semantically closed. No runtime claim.
