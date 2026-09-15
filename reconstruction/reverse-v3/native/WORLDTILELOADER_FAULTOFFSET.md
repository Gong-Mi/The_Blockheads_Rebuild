# WorldTileLoader -[faultOffsetForX:y:] static map

Original ELF SHA-256 `733d8210…b94c7`; types `i16@0:4i8i12` (int return;
int x, int y). IMP `0x00856d18`, ARM.exidx end `0x00857188`, 284 words
verified against the pinned bytes
(`tools/recover_worldtileloader_faultoffset.py --check`). PIC/GOT base
`0x0105faf4` — same GOT as the GameView family; this is the first
WorldTileLoader body with reviewed semantics, opening the terrain front that
`refineTerrainCount` (see `WORLDTILELOADER_REFINETERRAINCOUNT.md`) indexes.

## Call sites (all eight, anchors decoded from verified bytes)

| site | callee | route |
|---|---|---|
| 0x00856db0 | `-[World worldWidthMacro]` (IMP 0x005d9824) | `blx lr`, objc_msgSend from GOT slot 0x0105b7a0 |
| 0x00856e08 | `-[World worldWidthMacro]` | `blx r3`, same GOT reload |
| 0x00856e40 | `-[World worldWidthMacro]` | `blx r3`, same GOT reload |
| 0x00856f30 | `-[NoiseFunction getX:Y:octaves:]` (IMP 0x00a6324c) | `blx r4`, same GOT reload |
| 0x00856fdc | `-[NoiseFunction getX:Y:octaves:]` | `blx lr`, same GOT reload |
| 0x00856f68 | `clamp(float,float,float)` = `_Z5clampfff` @0x004be068 | `bl` immediate, decoded |
| 0x00857044 | `__wrap_powf` via PLT 0x001c3f98 → JUMP_SLOT 0x10602ec | `bl` immediate, PLT chain decoded field-by-field |
| 0x008570e0 | `__wrap_powf` via PLT 0x001c3f98 → JUMP_SLOT 0x10602ec | same |

Receiver provenance: all three `worldWidthMacro` sends go to
`self->world` (`OBJC_IVAR_$_WorldTileLoader.world`, offset 4; reloaded before
each send). `getX:Y:octaves:` receivers are `self->heightNoiseFunctionB`
(offset 0x14) and `self->faultNoiseFunction` (offset 0x18) — per the method
map these are `NoiseFunction` instances, so the noise calls are cross-object
dispatches whose internals are NOT claimed here.

Anchored float/double constants: 32.0f (x2), 512.0f, 0.0f, 0.05f, 0.2f,
double 0.2 (weight d2), double 0.8 (weight d3).

## Reviewed semantics (static CFG, exact branch sites)

```text
w  = [self->world worldWidthMacro]          // queried 3x via 3 separate sends
xq = (x / 32.0f) / (float)w                 // fp-0x2c
yq = (y / 64.0f) / (float)w                 // y / 2.0f / 32.0f, fp-0x30
if (w >= 512)                               // bge 0x00856e48
    yq = (y / 64.0f) / 512.0f               // width cap applies to y only
band = clamp(0.8 * [self->heightNoiseFunctionB getX:(double)(xq + 0.05f)
                   Y:7.0 octaves:1] + 0.2, 0.0f, 1.0f)        // fp-0x34
a = fabsf((float)[self->faultNoiseFunction getX:(double)xq
                 Y:(double)yq octaves:1])                      // fp-0x3c
if a <= 0.0f: shaped = 0                    // ble 0x00857004
elif a < 0.2f:                              // bpl 0x00857018
    shaped = powf(2a, 2.0f)
else:
    t = max(2(a - 0.2f), 0.0f)              // bpl 0x0085709c select
    shaped = powf(t, 2.0f) + 5.0f * band
return (int)(512.0f * shaped * band)        // vcvt.s32.f32, truncates toward 0
```

Structural notes:

- The 512 width cap is applied only to the y normalization; x uses the raw
  `worldWidthMacro` value. The cap test re-queries `worldWidthMacro` rather
  than reusing the earlier result.
- The fault profile is valley-shaped: `|faultNoise|` near 0 yields offset 0,
  a quadratic ramp for a < 0.2, and a second quadratic lobe plus a
  `5*band` lift for a >= 0.2, so the ridge only rises where the height band
  noise also permits.
- `getX:Y:octaves:` argument registers are anchored per call: X in r2:r3 as a
  double, Y on the stack as a double, octaves as a stack int (1 in both
  calls; the height call uses the constant Y=7.0 slice).

Claim boundary: static bounded-body map with per-instruction anchors.
`NoiseFunction::getX:Y:octaves:` internals, `worldWidthMacro` units, and all
runtime values are outside this body.
