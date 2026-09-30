# WorldTileLoader -[getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:] static map

Original ELF SHA-256 `733d8210…b94c7`; types `v20@0:4i8^f12^f16`. IMP
`0x00855ad0`, boundary end `0x00856d18` (1170 words) verified against the
pinned bytes (`tools/recover_worldtileloader_getinitialrockdirt.py --check`).
PIC/GOT base `0x0105faf4`.

Boundary note: this body has NO ARM.exidx entry of its own; the region is
closed by the next method IMP `-[faultOffsetForX:y:]` at `0x00856d18`
(whose exidx end `0x00857188` covers the already-mapped fault profile).

This is the terrain-height GENERATOR consumed by the refinement pipeline.
Unlike `getRockAndDirtHeightforX:` (array lookup, int outputs), this method
computes float heights from noise functions before any array exists.

A sibling body exists at `0x00947af8`
(`ClientTileLoader getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:`)
— same selector, separate implementation, not yet mapped.

## Exact static behavior

```text
w  = [self->world worldWidthMacro]            (1 blx, 0x00855d24)
xq = ((float)x / 32.0f) / (float)w            stored [rule+0x38]

oct = 3 (default, [sp+0x228])
if (ruleByte@fp-0x8d == 1) oct = 2            0x00855b98
if (ruleByte@fp-0xcd == 3) preset = 4         0x00855c20
oct2 = oct + 2                                (second-family calls)

A  = [self->heightNoiseFunctionA  getX:(double)(xq+0.05f) Y:7.0 octaves:oct]    (0x00855da0)
B  = [self->heightNoiseFunctionB  getX:(double)(xq+0.07f) Y:7.0 octaves:oct2]   (0x00855e20)
cA = [caveNoiseFunctionA getX:(double)(xq+0.05f) Y:(double)(cave+0.05f) octaves:oct2]
                                                                                (0x00855e8c)
cB = [caveNoiseFunctionB getX:(double)(xq+0.05f) Y:(double)(cave+0.07f) octaves:…]
                                                                                (0x00856504)
A2 = second A-family getX (recomputed X from [rule+0x38])                       (0x0085641c)
B2 = second B-family getX                                                      (0x00856498)

rock base = linearInterpolate(clamp(0.2*n + 0.8, lo, hi), base, caveY)
          then (v - 5.0f) * 2.0f                                              (0x00855ec8..0x00855f30)
dirt base = same family with own struct offsets                                (0x00856540..0x008565a8)

ridge: if |v| >= 0.1f and ruleByte != 4:
    v = powf(2.0f, v * 1.0f) / 10.0f                                          (0x00856174)
    dirt mirror                                                               (0x008567bc)

rule-driven sign edits (ldrsb-gated negates at fp-0x56 / fp-0x96 / fp-0xd6,
mirror bytes at sp+0x20f / sp+0x283):
    v = -v for matched rule bytes (3 pairs, rock and dirt sides)

final pair:
    if rock > dirt:  rock = clamp(rock, 511.25, 512.25); dirt = rock - delta
    else:            dirt = clamp(dirt, 511.25, 512.25); rock = dirt - delta
                                                                               (0x00856ac4..0x00856bb8)
    if ruleByte@sp+0x24b == 1:
        rock = (double)(rock - 512) * 5 + 512; dirt likewise                  (0x00856c50)

*rockHeight = rock; *dirtHeight = dirt      (out params [r2]/[r3])
```

## customRules fetch pattern

15 `objc_msgSend_stret` sites, each returning a 0x40-byte struct into a
stack slot; on nil receiver the block `memset`s the slot to zero instead.
All 15 use the same selector slot `0x00e823f4` (selector string not
readable as plain C string — data-table-backed selector; flagged below).

## Anchored dispatch summary

| kind | count | sites |
|---|---:|---|
| objc_msgSend_stret (customRules) | 15 | see JSON `stret_sites` |
| memset fallback | 15 | paired with each stret |
| getX:Y:octaves: blx | 7 | A/B/caveA/caveB/A2/B2 + worldWidthMacro |
| clamp(float,float,float) bl | 2 | 0x00855ec8, 0x00856540 |
| linearInterpolate bl | 2 | 0x00855ef0, 0x00856568 |
| __wrap_powf bl | 2 | 0x00856174, 0x008567bc |
| __stack_chk_fail | 1 | 0x00856cdc (canary at [sp+0x1e8]) |

Ivar offsets used: world=4, heightNoiseFunctionA=16, heightNoiseFunctionB=20.

Claim boundary: static bounded-body map. NoiseFunction::getX:Y:octaves:
internals, the customRules struct field semantics (only byte-equality gates
are mapped), worldWidthMacro units, and runtime values are outside this
body. The 0x00e823f4 selector slot resolves into a data table, not a plain
C string — its string value is pending.
