# WorldTileLoader column-height helpers (static maps)

Original ELF `libApplication.so` (armeabi-v7a), SHA-256
`733d8210…b94c7`. Four bounded static bodies, all word-verified against the
pinned bytes by `tools/recover_worldtileloader_column_heights.py --check`:

| method | IMP | bounded end | words |
|---|---|---|---|
| `-[unmodifiedGroundLevelForX:]` | `0x00857a2c` | `0x00857bf8` | 115 |
| `-[maxOfRockAndDirtHeightForX:]` | `0x00857bf8` | `0x00857dc8` | 116 |
| `-[lakeHeightForX:]` | `0x00857dc8` | `0x00857f48` | 96 |
| `-[getCloudHeightForX:]` | `0x00857340` | `0x00857684` | 209 |

All four are single-int-in / single-int-out queries into the terrain
pipeline that the already-recovered slices feed: `getInitialRockAndDirt`
(heights source), `getRockAndDirtHeightforX:` (array accessor), `refineTerrain`
(carve orchestrator), `faultOffsetForX:y:` / `isCaveForX:y:faultOffset:`
(mask queries). They are the per-column *accessors and surface queries* the
rest of the loader and the placement code consume.

## The two array accessors share one wrap shape

`maxOfRockAndDirtHeightForX:` and `lakeHeightForX:` are the same template:

```text
W = [self->world worldWidthMacro] << 5          ; lsl #5 = ×32, per column
if (x < 0)      x += W;                          ; one worldWidthMacro call
else if (x > W) x -= W;                          ; two more calls: compare, subtract
return <array>[x];                               ; int array, lsl #2 index
```

- `maxOfRockAndDirt` returns `max(rockHeights[x], dirtHeights[x])`
  (`cmp`/`bge` keeps rock on ties).
- `lakeHeight` returns `lakeHeights[x]`.
- The wrap edge `x == W` is **kept** (`ble` skips the subtraction); value
  `W` therefore survives to the array read.
- Each accessor calls `worldWidthMacro` up to three times (branch-local;
  -O0 style, no cached value).

Anchored cells (both methods): ivar `world` @4 via the method-local pool
cells; `rockHeights` @96 / `dirtHeights` @92 / `lakeHeights` @100 ivar
descriptors; selector slot `worldWidthMacro` `0x00e823a8`; msgSend GOT slot
`0x0105b7a0`. The three call sites per method are `bl` through the cached
`loc.imp.objc_msgSend` thunk (`0x001c281c`).

## unmodifiedGroundLevelForX: the surface query

```text
[self getRockAndDirtHeightforX:x rockHeight:&rock dirtHeight:&dirt]
i = max(rock, dirt);  flag = 0;
while (i > 0) {
    off = [self faultOffsetForX:x y:i];
    if (i > rock) return i;              ; dirt-above-rock case returns immediately
    if ([self isCaveForX:x y:i faultOffset:off]) { flag = 1; i--; continue; }
    return i + (flag != 0 ? 1 : 0);      ; first non-cave level, +1 after any cave
}
return 0;
```

- Both out-parameters are ints: the body compares them with integer `cmp`
  and the loop keeps `i` an int (`add r0, r1, r0` after `movne r2,1` /
  `moveq r0,0`).
- The descent exists so a carved sinkhole does not read as the surface:
  while `isCave` holds, `i` walks down; the flag records that the walk
  happened, and the normal exit adds it.
- The three call sites are `blx` through the GOT-loaded `objc_msgSend`,
  selectors `getRockAndDirtHeightforX:rockHeight:dirtHeight:` (cell
  `0x00857be8` → slot `0x00e82438`), `faultOffsetForX:y:` (cell `0x00857bec`
  → `0x00e82404`), `isCaveForX:y:faultOffset:` (cell `0x00857bf0` →
  `0x00e82408`).

## getCloudHeightForX: the cloud-layer noise composition

```text
W = [self->world worldWidthMacro];
q = (float)x / 32.0f / (float)W;
n1 = [heightNoiseFunctionA getX:q+0.1  Y:5.0 octaves:3]
n2 = [heightNoiseFunctionB getX:q+0.07 Y:5.0 octaves:3]
n3 = [heightNoiseFunctionB getX:q+0.05 Y:7.0 octaves:9]
w1 = n1*0.3 + 5.0;  w2 = n2*5.0 + 5.0;  w3 = n3*0.8 + 0.2;
t  = clamp(w3, 0.0f, 1.0f);
return (int)(40.0f + linearInterpolate(w1, w2, t) * 3.0f * 32.0f);
```

- The receiver pair is `heightNoiseFunctionA` @16 / `heightNoiseFunctionB`
  @20 — the same two noise families the height generator uses; the
  threshold noise (n3, octaves 9) is clamped and drives the interpolation
  between the two height clouds.
- **The three doubles are float-precision constants widened to double**:
  pool bits `3fc99999a0000000` / `3fe99999a0000000` / `3fd3333340000000`
  are exactly `(double)0.2f` / `(double)0.8f` / `(double)0.3f` — the same
  "float literal in a double slot" pattern the `getInitialRockAndDirt`
  constants show. The float pool constants are `40.0f`, `32.0f`, `0.0f`,
  `0.05f`, `0.07f`, `0.1f`; `7.0`/`5.0`/`3.0`/`1.0` arrive as `vmov`
  immediates.
- Calls: `blx` ×4 through `objc_msgSend` (the width call plus the three
  `getX:Y:octaves:` sends), then `bl` to `_Z5clampfff` (`0x004be068`) and
  `_Z17linearInterpolatefff` (`0x00582a14`) — the shared math helpers.
- No branches at all in the 209 words.

## Boundary notes

- All four bodies have **no ARM.exidx entry of their own**; each is closed
  by the next method IMP address (the end column above), and the tool
  rejects any extra or missing word in the range.
- The width helpers each spill an unreferenced constant `5` (and the
  max/lake tails a `2`) into a stack slot that no read in the body
  consumes; the cloud tail likewise stores `0x28/0x20/0x1f`. Recorded as
  observed instructions — no purpose is claimed.
- `NoiseFunction` internals (the noise2d/noise3d cores), the
  `customRules` struct layout, and all runtime values are outside these
  bodies; nothing here is a runtime or rendering claim.
- Only `maxOfRockAndDirt`/`lakeHeight` share the flag-free wrap shape;
  `unmodifiedGroundLevel` consumes the accessor family and the two mask
  queries but does not wrap `x`.

## Artifacts

| artifact | role |
|---|---|
| `tools/recover_worldtileloader_column_heights.py` | hash-gated extractor; `--check` re-verifies every anchor |
| `disasm_worldtileloader_{unmodifiedgroundlevel,maxofrockanddirt,lakeheight,getcloudheight}.txt` | the four bounded listings |
| `worldtileloader_column_heights.json` | machine record: selectors/ivars/constants/calls/branches per method |
| `tools/test_worldtileloader_column_heights_evidence.py` | CI contract on the committed JSON (no ELF needed) |
