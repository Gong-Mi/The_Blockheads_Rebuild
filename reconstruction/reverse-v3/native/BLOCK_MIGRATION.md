# The physical-block version-upgrade body (E15) — third of the block-storage trilogy

Recovers `WorldTileLoader`'s block upgrader, the body that brings a record's
64-byte-stride tile image up to the latest rules in cumulative passes gated by the
record's version byte (and never writes that byte back). It is the third of the
block-storage trilogy: the writer and the client-sync sender (E14), and now the upgrade
ladder for what those two saved. The body is statically recovered from the SHA-256-pinned
original `libApplication.so` (1.7.6, armeabi-v7a,
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`) and re-verified word by
word by `tools/recover_block_migration.py` (**1 body, 1311 instruction words**, 29 call
sites, 81 branches). The artifact is `native/block_migration.json`.

| body | IMP | words | sel/imp/class | ivars | calls | branches |
|---|---|---:|---|---:|---:|---:|
| `wtl_updatephysicalblocktol` | 0x008650b0 | 1311 | 13 / 2 / 0 | 10 | 29 | 81 |

The body's PIC base (0x0105faf4) is recomputed from a pool literal at a verified
`add rX, pc, rX` site, and the one branch row that leaves the body is recorded in
`outside_branch_rows` instead of being dropped.

## What the body does

`updatePhysicalBlockToLatestVersion:` (0x008650b0) is a **cumulative version ladder**, not
a single fixup: it re-reads the record's version byte (offset 13) at three gates, runs the
matching stages, and returns **without writing that byte** — an exhaustive store scan finds
no writer of offset 13 anywhere in the body, so the caller that bumps the version is
outside it.

| gate | sites | runs when | stages that run |
|---|---|---|---|
| 1 | 0x008650d8-0x008650e4 | byte < 3 | A, then B, then C |
| 2 | 0x0086568c-0x00865698 | byte < 5 | B, then C |
| 3 | 0x00865bc0-0x00865bc8 | byte < 7 | C only; `>= 7` jumps to the epilogue (0x00866474) |

**Stage A (byte < 3)** — one loop over the 32 columns (`i` at [fp,-0x3c], head 0x008650f4).
Per column it forms `index = physicalBlock->x * 32 + i` (0x00865108-0x00865110), asks
`getRockAndDirtHeightforX:rockHeight:dirtHeight:` (call 0x00865154, selector cell
0x00865fe0) and converts the two returned heights to column-local values by subtracting
`physicalBlock->y * 32` (0x00865160-0x00865180). The fixup then passes a guard chain:
local rock in `[0, 0x20)` (0x0086518c/0x00865198), global rock > 0x1f0 (0x008651a4), and
`index` equal to none of 0, `(W*32)/4`, `(W*32)/4*2`, `(W*32)/4*3` (idiv at 0x00865210 and
0x008652dc; `W` re-requested each time, 0x008651f8/0x0086525c/0x008652c4); then tile
byte3 == 0 (0x00865324) and byte0 == 8 (0x0086534c) and a `dirt - rock > 2` gap
(0x00865364-0x00865374); then `faultOffsetForX:y:` (0x008653e4) and
`isCaveForX:y:faultOffset:` (0x00865410, skipped when nonzero). The flint band is
**two-sided**: `0.55 < noise < 0.85`, with 0.55 synthesised as `0.85 - 0.3` at 0x00865568
(skips at 0x00865574/0x00865588). The fixup rewrites the tile in place — **byte2 = 1,
byte1 = 1, byte0 = 2** (0x008655a0 / 0x008655b4 / 0x008655c8) — and then places a dynamic
object: `[[self->world dynamicWorld] createTreasureChestOrTrollAtTile:&tile
atPos:(index, rockHeight) loadTroll:0 loadTreasure:1]` (0x008655f4 → call 0x0086565c,
selector cell 0x00866528; the pair is built by `makeIntpair` at 0x00865624 and the two
stacked words 0/1 are staged at 0x00865648-0x00865654).

**Stage B (byte < 5)** — columns `j`, with the column equal to `self->bestStartPosition`
skipped (0x008656ec, offset 76). Per column it recomputes the fresh heights (0x00865744),
walks `k` from `max(local rock, 0)` while `k < local dirt` and `k < 0x20` (head 0x008657dc),
per `k` taking `max(self->rockHeights[idx], self->dirtHeights[idx])` as the height
(0x0086585c/0x00865880, cells 0x008664e4/0x00866510), requires `isBeachForPos:` true
(0x00865900) and tile byte0 == 8 (0x0086592c), and writes **byte0 = byte1 = 0x3a** when its
one-sided flint sample is `> 0.4` (skip 0x00865b6c; strings at 0x00865b70-0x00865b80).

**Stage C (byte < 7)** — columns `m`, same bestStart skip (0x00865c28). Per `k` while
`k < min(local rock, 0x20)` it requires tile byte0 == 1 and byte3 == 0 (0x00865d4c/0x00865d5c),
`faultOffsetForX:y:` (0x00865d2c), a normalised noise2 `> 0` (0x00865f90/0x00865fac), then a
mirrored tin band around ±0.3 with a `C_ty` correction (0x00866090-0x00866158), and its two
write paths store **byte3 = 0x6a** (0x0086622c) or **byte3 = 0x6b** (0x00866428) under
their own `0.1 < noise < 0.15` windows.

State consulted: `self->world` (cells 0x00865ff0/0x00866238/0x008664d4; only
`worldWidthMacro` and `dynamicWorld`), `bestStartPosition@76`, `flintDensityNoiseFunction@36`
(cells 0x0086625c/0x008664dc), `tinDensityNoiseFunction@40`, `yHeightDivider@244`,
`rockHeights@96`, `dirtHeights@92`. Measured artifacts: the `_cmd` spill (0x008650cc) and
the `movw` value stubs staged around 0x00865100-0x0086532c are never reloaded;
`worldWidthMacro` is re-requested per surviving column and again inside the clamp arms
(0x00865aa0, 0x00865eec).

## The fourteen unclassified pool words (measured mechanism, not a gap)

`tools/build_specs.py` resolves every pool word as a PIC-relative cell
(`slot = base + signed(word)`); fourteen words in this body do not fit that model and are
left unclassified **by the classifier, not by the code** — each one is accounted for:

- **Thirteen are per-site re-materialisations of the PIC base**: `ldr rX, [pc, #k]`
  followed immediately by `add rX, pc, rX`, each recomputing 0x0105faf4 exactly — load
  sites 0x008650c0, 0x00865120, 0x008651c8, 0x00865230, 0x00865290, 0x008655d4, 0x00865710,
  0x00865848, 0x008658e0, 0x00865974, 0x00865c40, 0x00865d08 and 0x00866060. This body
  re-materialises the base at every use site instead of keeping it in a callee-saved
  register, which is why its count is the highest in the project so far.
- **One is a data word**: 0x00866004 (word 0xe58d0048) is referenced only by a
  data-island misdecoding (the listing prints it as an operand of a phantom instruction at
  0x00865ffc); it has no `ldr` targeting it inside the body and is recorded as data.

## Boundaries

- The concrete storage layer behind the database calls is outside this body.
- **The caller that bumps the version byte is outside this body** — this routine only
  reads offset 13; whether a `>= 3` record is ever presented to it is not determined here.
- **No tile-type name mapping is proven**: the bytes this body writes are raw
  (byte0 8→2 with byte1 = byte2 = 1 in stage A; byte0 = byte1 = 0x3a in stage B;
  byte3 = 0x6a/0x6b in stage C).
- The three stage-A equality guards (`(W*32)/4 × {1,2,3}`) are as-written tests; reading
  them as world quarter-seams is inference from the arithmetic, not from names.
- The runtime layout is known only at the offsets this body touches; see the per-body
  semantics and `BLOCK_SAVE_SYNC.md` for the record layout the siblings established.
