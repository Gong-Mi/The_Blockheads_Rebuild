# WorldTileLoader -[isCaveForX:y:faultOffset:] static map

Original ELF SHA-256 `733d8210…b94c7`; types `c20@0:4i8i12i16` (signed char
return; int x, int y, int faultOffset stack-passed). IMP `0x00857f48`,
ARM.exidx end `0x00858320`, 246 words verified against the pinned bytes
(`tools/recover_worldtileloader_iscave.py --check`). PIC/GOT base
`0x0105faf4`. Consumes `faultOffsetForX:y:` output as its y-axis shift (see
`WORLDTILELOADER_FAULTOFFSET.md`).

## Call sites (all eight, byte-decoded)

| site | callee | route |
|---|---|---|
| 0x00857fcc | `-[World customRules]` (stret) | `bl` → PLT 0x001c2918 → JUMP_SLOT `objc_msgSend_stret` 0x105fb6c |
| 0x00857ff0 | `memset` | `bl` → PLT 0x001c2924 → JUMP_SLOT 0x105fb70 |
| 0x008580dc | `-[World worldWidthMacro]` | `blx lr`, objc_msgSend GOT slot 0x0105b7a0 |
| 0x0085816c | `-[NoiseFunction getX:Y:octaves:]` (caveNoiseFunctionA) | `blx lr`, same GOT reload |
| 0x008581bc | `-[NoiseFunction getX:Y:octaves:]` (caveNoiseFunctionB) | `blx lr`, same GOT reload |
| 0x00858234 | `-[World customRules]` (stret), second identical query | `bl` → PLT 0x001c2918 |
| 0x00858258 | `memset` | `bl` → PLT 0x001c2924 |
| 0x008582d0 | `__stack_chk_fail` | `bl` → PLT 0x001c28b8 → JUMP_SLOT 0x105fb4c (guard slot 0x0105b7e0) |

Ivar cells (via `__objc_ivar` entries): `world` (offset 4),
`caveNoiseFunctionA` (offset 4), `caveNoiseFunctionB` (offset 8),
`yHeightDivider` (float ivar, loaded with `vldr s8` directly from
self+offset). Selector cells: `customRules` 0x008582f0, `getX:Y:octaves:`
0x00858300, `worldWidthMacro` 0x00858314.

## Reviewed semantics (static CFG, exact branch sites)

```text
Rules r1;                                    // 64-byte struct (movw r2,0x40)
if (self->world) objc_msgSend_stret(&r1, self->world, @selector(customRules));
else memset(&r1, 0, 0x40);                   // beq 0x00857fbc
if (r1.byte[0xc] == 0) return 0;             // bne 0x00857ffc gates; b 0x00858008

xq = (x / 32.0f) / (float)[self->world worldWidthMacro];        // [sp+0x94]
yq = (float)(y - faultOffset) / 32.0f / self->yHeightDivider;   // [sp+0x90]
cave = (float)([self->caveNoiseFunctionA getX:(double)xq Y:(double)yq octaves:2]
        + 0.05 * [self->caveNoiseFunctionB getX:(double)xq Y:(double)yq
                  octaves:1]);               // [sp+0x84]
cave = fabsf(cave);

Rules r2;                                    // SECOND identical customRules query
if (self->world) objc_msgSend_stret(&r2, self->world, @selector(customRules));
else memset(&r2, 0, 0x40);                   // beq 0x00858224
threshold = (r2.byte[0xc] == 2) ? 0.2 : 0.04;   // bne 0x00858264
return cave < threshold;                     // bpl 0x00858284 -> 0 else 1; sxtb
```

Structural notes:

- `customRules` returns a **64-byte struct by value** ( stret + 0x40 memset
  nil path); only byte offset 0xc is observed here: value 0 disables all
  caves, value 2 raises the threshold from 0.04 to 0.2. The full struct
  layout is outside this body.
- The `customRules` query executes **twice, identically** (same receiver
  `self->world`, same selector, no extra args) — the compiler did not reuse
  the first struct. Both queries are nil-guarded with a zero-fill path, so a
  nil world yields r1/r2 of all zeros: gate byte 0 -> early return 0.
- The y coordinate is shifted by the caller-supplied faultOffset and
  divided by the instance float `yHeightDivider`, while x is normalized by
  world width exactly as in `faultOffsetForX:y:` (x/32 over width).
- Cave density is a two-octave-layer sum: full-weight 2-octave
  `caveNoiseFunctionA` plus 5%-weight 1-octave `caveNoiseFunctionB`,
  absolute-valued, compared against a small threshold — i.e. caves form
  where the combined noise crosses near zero.
- The body is stack-protected: guard loaded from GOT slot 0x0105b7e0 at
  entry, re-verified before return (`bne 0x008582bc` -> `__stack_chk_fail`).

Claim boundary: static bounded-body map with per-instruction anchors.
`customRules` struct layout beyond byte 0xc, `NoiseFunction::getX:Y:octaves:`
internals, and all runtime values are outside this body.
