# ClientTileLoader -[getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:] static map

Original ELF SHA-256 `733d8210…b94c7`; types `v20@0:4i8^f12^f16`.
IMP `0x00947af8`, next-IMP boundary `0x009482a0` (490 ARM words) verified
against the pinned bytes by:

```text
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_clienttileloader_getinitialrockdirt.py \
  ~/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so --check
```

This is the client/network counterpart of the larger WorldTileLoader method.
It has no `customRules` struct fetches and no `objc_msgSend_stret` sites. It
uses two `ClientTileLoader` noise objects and a fixed two-pass formula.

## Receiver and field anchors

| role | binary anchor | resolved fact |
|---|---|---|
| `world` | cell `0x00948294` → GOT/ivar `0x0105e2a8` | `OBJC_IVAR_$_ClientTileLoader.world`, offset 4 |
| `heightNoiseFunctionA` | cell `0x0094828c` → `0x0105e2cc` | Client ivar, offset 0x14 |
| `heightNoiseFunctionB` | cell `0x00948284` → `0x0105e2c8` | Client ivar, offset 0x18 |
| `worldWidthMacro` | cell `0x00948290` → selector table `0x00e83904` | width query |
| `getX:Y:octaves:` | cell `0x0094827c` → selector table `0x00e83958` | noise query |
| `objc_msgSend` | cell `0x00948278` → GOT `0x0105b7a0` | all 7 indirect calls |

The selector cells are GNUstep/ObjC data-table-backed rather than plain
C-string cells; the selector identity is resolved through the selector table
and call role, not by pretending the cell itself is a C string.

## Exact call sequence

The seven indirect calls are byte-checked as:

```text
0x00947c44  world.worldWidthMacro()
             q = ((float)x / 32.0f) / (float)width

0x00947cac  A.getX(q + 0.05, 5.0, 3)
0x00947d14  B.getX(q + 0.07, 5.0, 5)
0x00947d74  B.getX(q + 0.05, 7.0, 9)

0x00948000  A.getX(q + 0.07, 5.0, 3)
0x00948068  B.getX(q + 0.07, 5.0, 3)
0x009480c8  B.getX(q + 0.05, 7.0, 9)
```

The noise return is converted from double to float after each call. There is
no `customRules`/nil fallback in this body.

## First pass → rock output

For the first three samples:

```text
p0 = 0.3 * A.getX(q + 0.05, 5, 3) + 5
p1 = 5.0 * B.getX(q + 0.07, 5, 5) + 5
u  = clamp(0.8 * B.getX(q + 0.05, 7, 9) + 0.2, 0, 1)
v  = linearInterpolate(p0, p1, u)
r  = (v - 5) * 2
```

The small-shape correction is exact:

```text
if abs(r) < 0.1:
    negative = (r < 0)
    r = powf(r, 2)       # not powf(2*r, 2)
    if negative:
        r = -r
```

Then the original writes the first output pointer (`r3` at entry):

```text
*rockHeight = 1 + 32 * 3 * (5 + r / 2)
```

The write is anchored at `0x00947f70`, after the first shape correction.

## Second pass → dirt output

The second pass repeats the same shape pipeline with the second call triplet:

```text
p0 = 0.3 * A.getX(q + 0.07, 5, 3) + 5
p1 = 5.0 * B.getX(q + 0.07, 5, 3) + 5
u  = clamp(0.8 * B.getX(q + 0.05, 7, 9) + 0.2, 0, 1)
v  = linearInterpolate(p0, p1, u)
r2 = (v - 5) * 2
```

It applies the identical `<0.1` square/sign correction, then writes the
stack-passed second output pointer (`[fp-0x60]`):

```text
*dirtHeight = 2 + 32 * 3 * (5 + r2 / 2)
```

The final write is `0x00948234`.

## Literal constants

The 15 verified pool entries are:

```text
0.0, 0.2, 0.8, 0.05, 0.07, 0.3, 0.1, 32.0
0.2, 0.8, 0.3, 0.1, 0.05, 0.07, 32.0
```

The duplicate second island is used by the dirt pass. The thresholds and
coefficients are therefore not guessed from the WorldTileLoader body.

## Direct calls and branches

Direct calls are byte-checked as two each of:

- `clamp(float,float,float)` at `0x00947dac`, `0x00948100`;
- `linearInterpolate(float,float,float)` at `0x00947dd0`, `0x00948124`;
- `__wrap_powf` at `0x00947e98`, `0x009481bc`.

Five branch destinations are checked: the two small-shape paths for each
pass, plus the two sign-restoration gates and the first-pass join.

## Comparison with WorldTileLoader

This client body is not a shorter alias for the single-player method:

- WorldTileLoader: 1170 words, 15 `customRules` stret reads, multiple
  rule-byte gates, four noise families and final pair adjustment.
- ClientTileLoader: 490 words, zero stret reads, fixed constants, two client
  noise objects and two output writes.

Both ultimately consume `NoiseFunction -[getX:Y:octaves:]`, but they do not
share a source-level formula. Do not wire the World formula into the client
path.

Claim boundary: static bounded-body map only. Noise internals are covered by
`NOISEFUNCTION_GETXY.md`; runtime width/noise values, actual server/client
call timing, and device behavior are not verified here.
