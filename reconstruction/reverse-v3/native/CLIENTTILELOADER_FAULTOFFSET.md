# ClientTileLoader -[faultOffsetForX:y:] static map

Original ELF SHA-256 `733d8210…b94c7`; types `i16@0:4i8i12`.
IMP `0x00948470`, next-IMP boundary `0x009488e0` (284 ARM words) verified
against the pinned bytes by:

```text
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_clienttileloader_faultoffset.py \
  ~/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so --check
```

The body is the client-side fault profile used by the next
`isCaveForX:y:faultOffset:` method. It is not the WorldTileLoader body copied
under another class: the client uses a fixed band/fault formula and has no
customRules or stret dispatch.

## Field and selector anchors

| role | cell → resolved slot | fact |
|---|---|---|
| world | `0x009488b8` → `0x0105e2a8` | `ClientTileLoader.world`, offset 4 |
| height noise B | `0x009488d4` → `0x0105e2c8` | offset 24 |
| fault noise | `0x009488c8` → `0x0105e2c0` | offset 32 |
| width selector | `0x009488b4` → `0x00e83904` | `worldWidthMacro` |
| noise selector | `0x009488c4` → `0x00e83958` | `getX:Y:octaves:` |
| dispatch | `0x009488b0` → `0x0105b7a0` | `objc_msgSend` GOT |

The `faultNoiseFunction` distinction is byte-verified: the `0xffffe7cc`
cell resolves to `0x0105e2c0`, whose dynsym entry is
`OBJC_IVAR_$_ClientTileLoader.faultNoiseFunction`. It is not
`heightNoiseFunctionA`.

## Coordinate normalization

Entry arguments are saved as:

```text
x = r2 at [fp-0x24]
y = r3 at [fp-0x28]
```

The first width query is `world.worldWidthMacro()` at `0x00948508`.
The resulting normalized x coordinate is:

```text
qx = (float)x / 32.0f / (float)width
```

The second width query is at `0x00948560`; a third independent width query at
`0x00948598` supplies the `< 512` branch gate. The normal y coordinate is:

```text
qy = (float)y / 2.0f / 32.0f / (float)width
   = (float)y / 64.0f / (float)width
```

The condition is exact and opposite in presentation to the World method:

```text
if (width < 512):
    qy = (float)y / 64.0f / 512.0f
else:
    retain qy = (float)y / 64.0f / width
```

The branch is `0x009485a0 bge 0x009485e4`: widths at least 512 skip the
fixed-512 recomputation.

## Band noise

The first noise call is:

```text
bandNoise = heightNoiseFunctionB.getX(16.0f * qx + 0.05f, 0.75, 1)
```

It is the indirect call at `0x00948688`. The return is converted to float
and clamped:

```text
band = clamp(f32(0.8 * double(bandNoise) + 0.2), 0.0f, 1.0f)
```

The clamp call is `0x009486c0`. The band is saved at `[fp-0x34]` and is used
again in the final multiplication.

## Fault noise shaping

The second noise call is:

```text
faultNoise = faultNoiseFunction.getX(qx, qy, 1)
```

It is the indirect call at `0x00948734`. Let:

```text
a = abs((float)faultNoise)
```

The exact piecewise shaping is:

```text
if a <= 0:
    shaped = 0
else if a < 0.2:
    shaped = powf(2.0f * a, 2.0f)
else:
    t = 2.0f * (a - 0.2f)
    t = max(t, 0.0f)
    shaped = powf(t, 2.0f) + 0.5f * band
```

The two `powf` sites are `0x0094879c` and `0x00948838`. The comparison
threshold is the literal `0.2f` at `0x009488d8`.

The fault value is converted to absolute value at `0x00948748` and the
absolute result is used from `[fp-0x3c]`. This body does not preserve or
restore the original fault sign; `shaped` is therefore non-negative before
the final band multiplication.

## Final result

The return path is:

```text
result = (int)(512.0f * shaped * band)
```

Anchors:

- `0x0094885c`: unconditional join to the final shape path;
- `0x00948860`: load 512.0f and multiply by shaped;
- `0x00948878`: multiply by band;
- `0x00948880`: `vcvt.s32.f32` truncation toward zero;
- `0x0094888c`: move result to integer return register.

## Verified constants

```text
32.0f, 0.2 (double), 0.8 (double),
32.0f, 512.0f, 0.0f, 0.05f, 0.2f
```

The `0.8` and `0.2` values are active in the double-precision band
normalization at `0x00948690..0x009486a0`, not dead pool entries.

## Comparison with WorldTileLoader

| property | client | world |
|---|---|---|
| body | 284 words | 284 words for `faultOffset`, 1170 for initial height |
| band source | Client `heightNoiseFunctionB` | World `heightNoiseFunctionB` |
| fault source | Client `faultNoiseFunction` | World `faultNoiseFunction` |
| qy width gate | `width < 512` uses fixed 512 | separate world-body branch layout |
| customRules | none | present in initial-height generator |
| result | `512 * shaped * band`, integer | same broad profile, different surrounding ownership/normalization evidence |

Claim boundary: static bounded-body map only. Noise values, width runtime
values, client method call timing, and the following cave-test behavior are
not runtime-verified here. The next bounded slice is
`ClientTileLoader -[isCaveForX:y:faultOffset:]` at `0x009488e0`.
