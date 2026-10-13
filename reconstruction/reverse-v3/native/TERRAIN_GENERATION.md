# Terrain generation batch (E12) — the named WorldTileLoader T2/T3 slice

Recovers the terrain-generation slice of `WorldTileLoader` that the project
inventory listed by name (material fractions, cave/beach predicates, the dirt
fill/flow pair, gem placement, start-position search) rather than the whole class.
All 13 bodies are statically recovered from the SHA-256-pinned original
`libApplication.so` (1.7.6, armeabi-v7a,
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`) and re-verified
word by word by `tools/recover_terrain_generation.py` (**13 bodies, 5391 instruction
words**, 174 call sites, 317 branches). The artifact is
`native/terrain_generation.json`.

The whole batch is one pipeline: the material fractions decide what a column is
made of, the predicates decide what it is called, `fillDirtTile:…` writes the
block id and the flint bands, the two recursive flow-out bodies redistribute
material, `placeGemsInCaveForPhysicalBlock:…` stamps ore and gems, and
`findBestStartPosition` searches that finished terrain for a spawn column.

## Material fractions

`limestoneFractionForX:y:faultOffset:` (0x00857684, 141w) is the noise-driven one:
the result is `<second dispatch result> * min((faultOffset / 1024.0f) * 2.0f, 1.0f)`.
It primes 1.0f, 2.0f and the f32 pool 1024.0 / 32.0 / 39599.0 and samples
`self->rockTypeNoiseFunction@32` through `getX:Y:octaves:` (0x00857770), scaling the
returned int by `<<5` to form the term `(y + 39599.0f) / ((float)(ret << 5) * 2.0f)`
and a second term `(faultOffset - arg4) / (32.0f * self->yHeightDivider@244 * 2.0f)`
(0x00857788 / 0x008577cc); a second dispatch (0x00857800) returns the scale and the
product is clamped by the `min(…, 1.0f)` at 0x00857848.

`sandstoneFractionForX:y:faultOffset:limestoneFraction:` (0x008578b8, 93w) is the
sentinel-style wrapper: below **0.45** (double pool 0x00857a10) it answers -1.0f
(0x008579ec), otherwise it takes `min(rockHeights@96[y][x], dirtHeights@92[y][x])`
(0x00857948/0x00857968, min at 0x00857998) and answers with the limestone fraction
**unchanged** only when `[self isDesertForPos:pos height:min]` is true (0x008579d0),
else -1.0f.

The sand fractions come in two layers. `sandFractionForPos:highRes:` (0x0085a84c,
179w) is the bounds normaliser: it wraps `pos.x` into `[0, worldWidthMacro * 32)` by
adding or subtracting the period once and returns **0.0f** when x is still outside
(0x0085a8c0 / 0x0085a934), then takes `h = max(rockHeights[x], dirtHeights[x])` and
forwards to the worker with the caller's `highRes`. `sandFractionForPos:height:highRes:`
(0x0085ab18, 366w) is that worker: `width = MAX(512, [world worldWidthMacro])`
(the MAX macro re-issues the send at 0x0085ac9c), `X = (pos.x / 32.0f) / width`,
`Y = ((pos.y - 0.5 * h) / 32.0f) / width * 4.0f`, noise from
`self->sandNoiseFunction@44 getX:X Y:Y octaves:(highRes ? 11 : 4)` (0x0085ad30 /
0x0085ad58), narrowed to float. Then `[world customRules]` byte **+8** selects a
delta through the 5-entry jump table at 0x0085adf0 — 0 -> +1.0, 1 -> +0.6, 2 -> none,
3 -> -0.6, 4 -> 1.0 - value, > 4 -> none — the sum is clamped to [-1, 1]
(0x0085aeb8) and a value <= 0 returns immediately (0x0085aed0). Otherwise, when that
byte is non-zero, the value is scaled by
`weight = clamp((1 - |fmodf((pos.x/32)/width, 0.5) - 0.25| / 0.25) * 3.0 - 0.5, 0, 1)`
(`__wrap_fmodf` at 0x0085afd8, `clamp(float,float,float)` at 0x0085b044).

## Predicates

| body | IMP | words | rule |
|---|---|---:|---|
| `wtl_isdesertforpos_height_` | 0x0085b0d0 | 48 | `[self sandFractionForPos:pos height:h highRes:YES] > 0.3` |
| `wtl_isbeachforpos_height_` | 0x0085b190 | 188 | height band, then a noise threshold |
| `wtl_isdesertorbeachforpos_` | 0x0085b480 | 76 | `isBeach ? YES : (sandFraction > 0.3)` |
| `wtl_isfloatingislandcavefo` | 0x00858320 | 209 | `|noiseA + 0.5 * noiseB| < 0.2`, gated by customRules |

`isDesertForPos:height:` is the shortest body in the batch: it loads the double 0.3
from its own pool copy (0x0085b180), dispatches the sand fraction with `highRes = 1`
(0x0085b148) and answers the `>` comparison (0x0085b16c). `isDesertOrBeachForPos:height:`
checks `isBeachForPos:` first (0x0085b4f0, early YES at 0x0085b580) and otherwise
compares the sand fraction against a **second pool copy of the same 0.3**
(0x0085b598) — both thresholds are 0.3, from two different literal slots.

`isBeachForPos:height:` answers from the height band before sampling anything:
`(float)Y < 1008 - H` is YES (512 - H + 0x1f0 at 0x0085b1cc) and `(float)Y > 1040 - H`
is NO (512 - H + 0x210 at 0x0085b1f8) — a span of exactly ±16 around 1024 - H. In
between it samples `self->sandNoiseFunction@44` with
`nx = ((float)X / 32.0f) / worldWidthMacro` and
`ny = (((double)Y - 0.5 * H) / 32.0) / MAX(worldWidth, 512) * 4.0f` at octaves 11
(0x0085b3f0) and returns `(float)Y < 1024 - 16 * noise - H` (0x0085b434/0x0085b444).

`isFloatingIslandCaveForX:y:` reads the 64-byte `[world customRules]` struct
(objc_msgSend_stret at 0x0085839c, memset 0x40 when the world is nil) and returns 0
unless byte **+12** is non-zero; it then computes `x' = (x/32)/worldWidthMacro` and
`y' = (y/32)/self->yHeightDivider@244` and answers `|noiseA + 0.5 * noiseB| < 0.2`
(double 0.2 at 0x00858630), where `noiseA = [self->caveNoiseFunctionA@52 getX:Y:octaves:2]`
(0x0085853c) and `noiseB = [self->caveNoiseFunctionB@56 getX:Y:octaves:1]`
(0x00858598), both sampled at `(x'*8, y'*8)`.

## Filling and flowing

`fillDirtTile:worldPos:worldDirtHeight:parentType:` (0x0085b5b0, 793w) fills the
passed tile. When `parentType` is one of **{6, 7, 8, 27, 28, 58}** (0x0085b6b0) the
block id is inherited rather than computed — 7 for {7, 8, 58}, 8 for {8, 58},
otherwise 6 (0x0085b990..0x0085ba08). Otherwise it takes
`H = max(rockHeights@96[x], dirtHeights@92[x])` and asks for the sand fraction at
`highRes:1`: id = 7 when the fraction > 0.3 (0x0085b90c), else 8 when
`isBeachForPos:` answers (0x0085b968), else 6. **tile[0] and tile[1] both receive the
id** (0x0085ba2c/0x0085ba44/0x0085ba60) and byte 2 is never written. Dirt tiles then
sample `self->flintDensityNoiseFunction@36 getX:fracA Y:fracB octaves:3`
(0x0085bcac) with `fracA = (x/32)/worldWidthMacro` and
`fracB = 4 * ((y - 0.5*H)/32) / MAX(512, worldWidthMacro)`, and store
**tile[3] = 1** above the high threshold or **2** below the low one
(0x0085be64/0x0085be88). The thresholds are 0.5 / -0.6 by default, 0.75 / -0.8 when
`customRules` byte **15** == 1 (0x0085bd30), 0.125 / -0.15 when it is 3, and both are
halved when `[world expertMode]` (0x0085be1c). Beach tiles re-sample the noise with
`fracA*0.0625, fracB*0.625` (0x0085c0c8) and overwrite tile[0]/tile[1] with block
**58** when the result > 0.4f (0x0085c0f4). Finally a dirt tile with `y >= 511`,
`y == worldDirtHeight - 1` and `lakeHeights@100[x] < worldDirtHeight` becomes **27**
(0x0085c11c/0x0085c170).

`recursivelyFlowOutDirtFromTile:atPos:` (0x0085c518, 594w) redistributes dirt upward:
`pos.y < 1` returns (0x0085c558); for `(x, y-1)` it probes
`tileAtWorldPositionLoaded` and, when the neighbour's byte0 is 2 or 3 with byte2 == 1,
sends `fillDirtTile:… worldDirtHeight:99999999 (0x5f5e0ff) parentType:parent->byte0`
(0x0085c64c) and recurses on it (0x0085c684). It then draws
`f1, f2 = (float)lrand48() / 2147483648.0f` from the four-instruction lrand48 wrapper
at 0x8540cc and wraps x into `[0, worldWidthMacro << 5)`, running the same
probe+fill+recurse triple on `(x-1, y-1)` when `f1 > 0.7` (0.7f at 0x0085c560), on
`(x+1, y-1)` when `f2 > 0.7`, on `(x-2, y-1)` when `f1 > 0.9` (0.9f at 0x0085ce44) and
on `(x+2, y-1)` when `f2 > 0.9` — 30 % per adjacent column, 10 % per two-away column,
always one row up.

`recursivelyFlowOutWaterFromTile:atPos:` (0x0085c214, 193w) is the water sibling: a
depth-first flood fill over `(x, y-1)`, `(x+1, y)` and `(x-1, y)` — **`(x, y+1)` is
never visited**. A neighbour is accepted only when byte0 == 2 (0x0085c2a8) and
byte2 == 1 (0x0085c2b8); accepted tiles are rewritten in place (byte0 = 3 at
0x0085c2c8, byte4 = 0xff at 0x0085c2d4, byte7 = 0 at 0x0085c2e0) and the method
recurses on them (0x0085c31c).

## Ore, gems and the spawn column

`placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType:`
(0x0085ce60, 1556w — the largest body in the batch, 125 branches) stamps one terrain
tile (`physicalBlock->tiles@8 + tileIndex*64`). It normalises
`nx = ((float)worldX + 1453.0f)/32.0f/yHeightDivider` and the same for y with 1247.0
(f32 pool 0x0085d264/0x0085d268/0x0085d26c), then chooses the cave predicate on
`floatingIslandType` (0x0085cf4c): non-zero goes to
`[self isFloatingIslandCaveForX:worldX y:worldY-1]` (0x0085cf98), zero goes through
`faultOffsetForX:y:` (0x0085d010) into `isCaveForX:y:faultOffset:` (0x0085d03c) —
**both predicates are asked about `worldY-1`**. The non-cave branch samples
`self->flintDensityNoiseFunction@36` (0x0085d0dc, fractions `nx*1.423 / ny*1.4536`),
reads `[world expertMode]` to pick the 0.11 / 0.22 factor
(0x0085d1c0, pool 0x0085d5a0/0x0085d5a4) plus the `customRules` struct (0x0085d25c),
and writes byte0 = **16** when `floatingIslandType == 0` (0x0085d2c8) else byte0 = 2
(0x0085d818), byte4 = 0, byte3 in **{0x5e, 0x91, 0x90}** (0x0085d85c/0x0085d880/
0x0085d8c0). The gem body (0x0085d900) sets byte0 = 2 and byte4 = 0
(0x0085d930/0x0085d944) and returns early unless `customRules` byte **0x11** is
non-zero (0x0085d9b0); `floatingIslandType` 1..5 maps to gem ids
**{0x3a, 0x38, 0x36, 0x34, 0x3c}** (0x0085d9c8..0x0085da28) and five band tests sample
`self->gemNoiseFunction@60` through `getX:Y:octaves:`, writing the gem id or the
branch fallback into `tiles[tileIndex].byte0xb` (0x0085dfa8 plus four siblings).

`findBestStartPosition` (0x00864188, 955w) returns an intpair through a hidden pointer
and searches for a spawn column: a random start offset `r = helper_0x8540cc() % (W*32)`
(0x00864220/0x0086423c) then a sweep `x = (r+i) mod (W*32)`. Each candidate must pass
the band gate `[2W,14W] ∪ [18W,30W]` (doubles 0.0625 / 0.4375 / 0.5625 / 0.9375 at
0x008644f8/0x00864384/0x008643fc/0x00864474 against `worldWidthMacro`), have
`ground = max(dirtHeights[x], rockHeights[x]) >= 512` (0x008648c4/0x00864b0c), a zero
`lakeHeights@100[x]`, `dirt > rock`, `|prevGround - ground| < 2` (helper 0x8540fc),
a base temperature in (-10.0f, 40.0f) from
`baseTemperatureForWorldPos(intpair{x, dirt}, 0.25f, 0.25f, 0.0f, world)`
(0x00864998/0x00864e3c) — tightened to (-5.0f, 25.0f) when `customRules` byte +3 == 2
(0x00864a14) — and must **not** be `isDesertOrBeachForPos:` (0x00864b90), with
`customRules` byte +8 == 1 or byte +2 in {3, 4} overriding that test. A streak of
accepted columns commits at `min(256, W/2)` (0x00864d5c) or 32/8 by rule byte +2, and
the committed spawn is `(firstX + 4 + (rand()/2^31) * (streak-8)) mod (W*32)` with
`y = [self unmodifiedGroundLevelForX:thatX]` (0x00864e80). A failed sweep returns
**(-1, -1)** (0x00864eb4).

## Anchors

| body | IMP | words | sel/imp/class | ivars | calls | branches |
|---|---|---:|---|---:|---:|---:|
| wtl_limestonefractionforx_ | 0x00857684 | 141 | 2 / 1 / 0 | 3 | 2 | 2 |
| wtl_sandstonefractionforx_ | 0x008578b8 | 93 | 1 / 0 / 0 | 2 | 2 | 5 |
| wtl_isfloatingislandcavefo | 0x00858320 | 209 | 3 / 2 / 0 | 4 | 6 | 7 |
| wtl_sandfractionforpos_hig | 0x0085a84c | 179 | 2 / 0 / 0 | 3 | 5 | 11 |
| wtl_sandfractionforpos_hei | 0x0085ab18 | 366 | 3 / 2 / 0 | 2 | 13 | 15 |
| wtl_isdesertforpos_height_ | 0x0085b0d0 | 48 | 1 / 0 / 0 | 0 | 1 | 0 |
| wtl_isbeachforpos_height_ | 0x0085b190 | 188 | 2 / 1 / 0 | 2 | 4 | 7 |
| wtl_isdesertorbeachforpos_ | 0x0085b480 | 76 | 2 / 0 / 0 | 0 | 2 | 1 |
| wtl_filldirttile_worldpos_ | 0x0085b5b0 | 793 | 6 / 2 / 0 | 5 | 19 | 51 |
| wtl_recursivelyflowoutwate | 0x0085c214 | 193 | 1 / 0 / 0 | 1 | 9 | 9 |
| wtl_recursivelyflowoutdirt | 0x0085c518 | 594 | 3 / 0 / 0 | 1 | 28 | 34 |
| wtl_placegemsincaveforphys | 0x0085ce60 | 1556 | 10 / 5 / 0 | 8 | 33 | 125 |
| wtl_findbeststartposition | 0x00864188 | 955 | 4 / 2 / 0 | 4 | 50 | 50 |

Total: **13 bodies, 5391 verified words, 174 call sites, 317 branches**, 55
selector-side cells (40 selectors + 15 imports, no classrefs) and 35 ivar cells.
Every body's PIC base (0x0105faf4) is recomputed from its own pool literal and no
pool word in this batch misdecodes as a branch (`disjoint_branch_rows` is empty
everywhere).

## Boundaries

- **Block and gem ids are measured bytes, not names.** The ids written by this batch
  (tile byte0 ∈ {16, 2, 3, 6, 7, 8, 27, 58}, byte3 ∈ {0x5e, 0x91, 0x90}, byte0xb ∈
  {0x3a, 0x38, 0x36, 0x34, 0x3c}, tile[3] ∈ {1, 2}) are reported as bytes; the game's
  name tables for them are not in these bodies and no mapping is asserted.
- **The Tile record is opaque here.** Only the offsets this code touches are known
  (byte0 type, byte2 compared with 1, byte3 flint band, byte4, byte7, byte0xb gem).
  The batch does not claim the layout.
- **The 64-byte `[world customRules]` struct is opaque.** Four bodies read single
  bytes of it (byte 0, +2, +3, +8, +12, byte 15, byte 0x11) as switches; the field
  names and the rest of the layout are outside these bodies.
- **The noise layer is a boundary.** `getX:Y:octaves:` is sampled with explicit
  coordinates and octave counts (2, 1, 3, 4, 11) but the noise implementation, its
  output range and the meaning of the 39599.0 / 1247.0 / 1453.0 offsets are not
  recovered here.
- **One dispatch's callee is unnamed.** The second dispatch in
  `limestoneFractionForX:y:faultOffset:` (0x00857800) receives the two computed
  doubles and returns the fraction scale; its receiver/selector is not resolved from
  the listing, so the arithmetic around it is reported without naming it.
- **A dead spill repeats across the family.** `movw r0, 5` (and in the siblings a
  dead `0x20` / `2` / `0`) is written to a frame slot immediately before several
  `worldWidthMacro` sends and never read back — most likely the compiler evaluating a
  MAX-style macro argument twice. Recorded as observed, not explained.
