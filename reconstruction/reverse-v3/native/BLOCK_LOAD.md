# The physical-block load path (E16) — the block-load orchestrator

Recovers `WorldTileLoader`'s **block-load orchestrator**: the single body that reads a
serialized `PhysicalBlock` from the block database (or its per-block file), unpacks the
64 KB tile image and the header fields, and — when nothing is stored and
`createIfNotCreated` is set — **generates and populates the block from scratch**. It is
the fourth body of the block-storage line (write/sync E14, migrate E15, load E16) and the
largest single body recovered so far. All evidence is statically recovered from the
SHA-256-pinned original `libApplication.so` (1.7.6, armeabi-v7a,
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`) and re-verified word by
word by `tools/recover_block_load.py` (**1 body, 5736 instruction words**, 133 call sites,
397 branches). The artifact is `native/block_load.json`.

| body | IMP | words | sel/imp/class | ivars | calls | branches |
|---|---|---:|---|---:|---:|---:|
| `wtl_loadphysicalblock_atxp` | 0x0085e6b0 | 5736 | 43 / 9 / 5 | 18 | 133 | 397 |

The body's PIC base (0x0105faf4) is recomputed from a pool literal at a verified
`add rX, pc, rX` site; the nine branch rows that leave the body (data-island false
branches, e.g. the pool words at 0x0085f474-0x0085f480) are recorded in
`disjoint_branch_rows` instead of being dropped.

## What the body does

Arguments: `self` [fp,-0x31c], `_cmd` [fp,-0x320] (never re-read), the `PhysicalBlock`
[fp,-0x324], `atXPos` [fp,-0x328], `yPos` [fp,-0x32c], `createIfNotCreated` [fp,-0x32d].
`atXPos` is wrapped into `[0, W)` against `[world worldWidthMacro]` (0x0085e710-0x0085e800)
and `linear = yPos*W + atXPos` indexes a macroTiles-based lookup whose result gates the
early exit (0x0085e8d0-0x0085e8ec -> 0x00863ff4).

**1. Fetch (0x0085e8f4-0x0085ef54).** Key via `[NSString stringWithFormat:]` (cells
0x0085f8e8/0x0085f8f0, call 0x0085e994), then `[blockDatabase dataForKey:]` (ivar cell
0x0085f8e4 @256, call 0x0085e9d0). On nil: the **file fallback** — second
`stringWithFormat` (cell 0x0085f9ac; `blockDirectory@12` cell 0x0085f9a8),
`[NSFileManager defaultManager]` + `fileExistsAtPath:` (0x0085eaf0) +
`[NSData dataWithContentsOfFile:]` (0x0085eb4c). **Unpack**: require data non-nil and
`[data length] >= 0x10001` (literal cell 0x0085f9b8); `memcpy(dst = *(PhysicalBlock+8) =
the tile image, src = [data bytes], 0x10000)` (0x0085ec18); `getBytes:range:{0x10000,1}`
(cell 0x0085f9ec, call 0x0085ec60) reads the payload byte at **0x10000** into the version
field `PhysicalBlock+0xd` (0x0085ec6c). The **database branch zeroes `PhysicalBlock+0x18`
and `+0x1c`** (0x0085ec80/0x0085ec88); the stored-as-file variant (0x0085ec9c-0x0085ef54)
repeats the unpack and instead sets the loaded flag `[fp,-0x33d] = 1` (0x0085ef4c).

**2. Create (0x0085ef58-0x0085f0a8)** — no data and the create flag set:
`[NSDate timeIntervalSinceReferenceDate]` is written as the double at
`PhysicalBlock+0x10` (0x0085efe4); `+0` = atXPos, `+4` = yPos, `+0xc` = 1
(0x0085efa8-0x0085efbc); the 32 tile-pointer slots at `PhysicalBlock+0x20` are
`__wrap_free`'d and zeroed (loop 0x0085f024-0x0085f0a8); `+0x18`/`+0x1c` = 0.

**3. Loaded-repair sky pass (0x0085f2f0-0x0085f604)** — when the block WAS loaded, a
double loop rebuilds the per-tile light/sky fields from
`getRockAndDirtHeightforX:` (call 0x0085f36c): rows above `localRock = rock/16 - y*32 +
0x10` get byte0 = 0x1f and `0xff/0x7f/0x1f/0x7f` halfwords at +0xe..+0x14, the next 32
rows get the fading band `(j-localRock)/C1 + 1.0` scaled, and deeper rows are zeroed.
After it: loaded or create==0 -> the finish at 0x00863ff4.

**4. Generation (0x0085f628-0x00863fbc)** — only (not loaded AND create). The version
byte is **cleared to 0** (0x0085f650). Gates: `customRules[14] != 0` and
`0x240 < yPos*32 < 0x384` (0x0085f6dc-0x0085f718, else the tile-init loops). Noise
scalars: x'/y' normalised by `yHeightDivider@244`, a flint@36 sample -> S1 with
threshold overrides from `customRules[14]` (==3 / ==1) and `S1 > threshold` required; a
gem@60 gate `> 0`; a centre-column `getRockAndDirtHeightforX:(x*32+16)` gate; and
`S2 = flint*5 + 5`. **Two marker ladders** write `[fp,-0x3ac]`: ladder A maps S1 to
2..5; ladder B walks nine `growthVigorForTreeTypeAtPos(TreeType, pair, world) > 0.2`
rungs (TreeType -> marker 9->0xd, 2->7, 7->8, 0xa->0xa, 8->0xc, 3->0xe, 2->0xf, 1->6,
4->9, fallback 0xb). The pair as read is `(yPos*32, yPos*32)` — recorded as observed.
Placement intent (0x00860378): a depth sample plus two `clampi` bounds give
[fp,-0x3b8] = top and [fp,-0x3b0] = bottom of the feature. The **all-tile clear loop**
(0x00860910-0x00860b68) writes every tile of the block with byte2 = 2, byte0xa = 0x7f,
byte4 = 0xff and everything else zeroed, then per column computes `localRock`,
`localDirt`, the lake row and `rock/16-y*32+0x10`. The **sky-material chain** writes
byte0 = 0x13 / 0x11 / 0xc / 1 and byte3 = 0x40 / 0x41 (the 0x41 gated by
`customRules[15]` and a 0.7 band); the **ore bands** write byte3 = 0x3f / 0x4d / 0x6a /
0x6b with the four `customRules[15]`-transformed floats as band offsets (the same
0x6a/0x6b ids the E15 migration writes).

**5. Spawn/marker loop (0x008623ec-0x00862cfc).** Per tile: when `colX ==
self->bestStartPosition` (@76, cell 0x00863424) the tile gets byte0/1/2 = 1 and a
spawn-column call runs (objc_msgSend 0x00862568; its selector slot pair
0x00863428/0x0086342c is not classified — not determined). The **quarter-column grid**
`colX == (W*32)/4 * {1,2,3}` writes byte1 = 0x29 / 0x27 / 0x28 and `colX == 0` writes
0x26 — the same `(W*32)/4` grid the E15 migration guards on. The **deep branch**
(`yPos > 0x1f0`, `customRules[+0x12]`, not expertMode, no cave) writes the ore id
**byte3 = 0x5e** (0x00862c64-0x00862cbc; 0x5e is one of E12's `placeGemsInCave` band
bytes).

**6. Final loop (0x00862d9c-0x00863fd8).** Per tile: byte0 = 2 / byte1 = 2 / byte7 =
0xff base, water rows below the lake line get byte0 = 3 / byte2 = 3 / byte4 = 0xff, the
quarter-column markers repeat under a depth window. **Tree stamping** (0x0086349c):
when the marker's depth and column range match, the trunk gets byte0 = byte1 = id
(0x1b, or 6) and byte7 = 0; the unnamed local function at **0x00864050** is called with
the marker (0x008635e8) and its result — whitelisted to {0x6c,0x80,0x81,0x82,0x83} when
`customRules[+0x0a] == 1` — is written to byte3 of the tile one row up; fruit markers
use the lrand48 wrapper `bl 0x008540cc` (byte0xb = 0x8e/0x8f for markers 1..5, 0x7e for
0x1b, 0x7f on rng > 0.6); the canopy uses `cosf` (0x00863c74) for its phase and a
flint@36 sample for the radius, writing leaf ids byte1 = 0xc / 0xe / 0x11. When
`[self isFloatingIslandCaveForX:y:]` reports a cave the tile instead runs
`[self placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType:]`
with **the marker as floatingIslandType** (0x00863fb0). The **finish** (0x00863ff4)
re-checks `__stack_chk_guard` against the saved value, branches to `__stack_chk_fail`
(0x0086401c) on mismatch, and epilogues at 0x00864010.

## Boundaries

- The concrete storage layer behind `dataForKey:` / `dataWithContentsOfFile:` is outside
  this body, as is the unnamed local function at 0x00864050 (usage only: marker in,
  whitelisted id out).
- The selector of the spawn-column call at 0x00862568 (slot pair 0x00863428/0x0086342c)
  is not classified — not determined.
- **Tile byte values are raw ids** (byte0 1/2/3/0xc/0x11/0x13/0x1f, byte1 markers
  0x26-0x29 and trunk ids, byte3 ore ids 0x3f/0x40/0x41/0x4d/0x5e/0x6a/0x6b, byte0xa
  0x7f, byte0xb 0x7e/0x7f/0x8e/0x8f, byte4/byte7 0xff); no tile-type enum mapping is
  proven.
- The two `stringWithFormat:` vararg sets were not decoded to concrete format texts (the
  format cells are 0x0085f8e8 and 0x0085f9ac).
- The pair words handed to the nine growthVigor rungs read back as `(yPos*32, yPos*32)`;
  recorded as observed, not interpreted.
- The `/16` in the repair loop's `localRock` is read as the asr-4 rounding idiom; its
  unit meaning is not proven here.
