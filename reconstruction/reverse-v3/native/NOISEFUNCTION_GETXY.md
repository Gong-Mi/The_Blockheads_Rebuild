# NoiseFunction static map: getX:Y:octaves: (0x00a6324c) and internals

Original ELF SHA-256 `733d8210…b94c7`. Types `d28@0:4d8d16i24` — returns
double, args (double X, double Y, int octaves). PIC base (module delta at
`0x00a6331c`) = 0x005fc890+0xa6325c+8 → GOT-relative field addressing
inside `_structPtr`.

## Function layout (all ARM, from pinned disasm
`disasm_noisefunction_getxy.txt` + r2 spot reads)

| range | body | exidx |
|---|---|---|
| 0x00a6324c..0x00a63318 | `-[getX:Y:octaves:]` wrapper: clamps octaves = max(octaves,1), tail-calls helper | owner 0xdd2fa4 |
| 0x00a63320..0x00a634e8 | static helper `noise2d(self, NoiseState *s, double X, double Y, int octaves)`: **not** tail-called — wrapper `bl 0xa63320` then `vmov d0` returns | owner 0xdd2fac |
| 0x00a63500..0x00a635e8 | `-[getX:Y:Z:octaves:]` wrapper (3D, `d36@0:4d8d16d24i32`), same clamp | owner 0xdd2fb4 |
| 0x00a635e8..0x00a6454c | static `noise3d(self, NoiseState *s, double X, double Y, double Z, int octaves)` — 21 calls into `grad2` | owner 0xdd2fbc |
| 0x00a6454c..0x00a645e8 | `-[dealloc]` (exidx owner 0xdd2fc4) | |
| 0x00a645e8..0x00a64e28 | static `grad2(NoiseState *s, int *permBase, double fx, double fy, double fz, int yFlag)` (528 w) | no own exidx entry |
| 0x00a64e28..0x00a652c8 | static `grad1(NoiseState *s, int *permBase, double fx, double fy, double fz, …)` (296 w), no exidx entry | |
| 0x00a652c8..0x00a653d8 | last 0xNoiseFunction body (init tail, 68 w) | |

Wrapper body (verified in checked-in listing, exact):
```text
oct = octaves
if (oct < 1) oct = 1                  ; bge 0xa632d0 / max select 0xa632e0
return noise2d(self, s?, X, Y, oct)   ; bl 0xa63320
```
(the clamp is `if (octaves >= 1) keep; else use octaves` at
0x00a632c4/0xa632d0 — clamps only negative-to-1 in the noise2d path)

## noise2d core (0x00a63320)

```text
s->_s1 = s->freq * 1<<Xpow  (d*  at [fp-0xc] self/state ptr)
s->_s2 = s->freq2 * 1<<Ypow
for (i = 0; i < octaves; i++):
    Ai = 1<<Xpow << i   (0x00a633d8)
    Bi = 1<<Ypow << i
    if (Ai < 1) Ai = 1  ; 0x00a633f8
    if (Bi < 1) Bi = 1  ; 0x00a63420
    n = grad2(s, permBase, s->x * Ai, s->y * Bi, (unused), i)   ; bl 0xa64e28 at 0x00a63458
    amp   += ampStep * n         ; [fp-0x20] accumulates
    total += n * amp             ; 0x00a63478 vmul d0, d0, d2 → vadd d2
    freqX *= 2 ; freqY *= 2      ; 0x00a63488..0x00a634a4
    ampStep *= persistance       ; [fp-0x28]
return total                      ; [fp-0x20] at 0x00a634d4
```

## noise3d core (0x00a635e8) — same octave loop, 3D lattice

Per octave: computes X/Y/Z grads by `grad2` calls with (x,y,z) permutations
and 8-corner trilinear blend. The blend block at 0x00a63c9c..0x00a63dd0 is
the 8-corner (2×2×2) weighted sum with u,v,w = fade factors, exactly:
```text
d1 = 1.0 (0x00a63c9c vmov.f64 d1, 1)
result = n000*(1-x)*(1-y)*(1-z)
       + n100*x*(1-y)*(1-z) + n010*(1-x)*y*(1-z) + … (8 terms, vadd chain)
```

## grad2 (0x00a645e8) — classic Perlin gradient lerp

```text
X0 = (int)(fx + 4096.0); X1 = (X0+1) & (freqPow-1)   ; 0x00a64648..0x00a6468c
    (mask 0x3ff loaded then AND'd with 0x1000-limited int, via __modsi3 in tileable branch)
xf = fx + 4096.0 - (int)(fx + 4096.0)                ; 0x00a646b4 [fp-0x48]
dx = xf - X                                          ; [fp-0x50]
(tileable X branch: __modsi3 with freqPow → wrap; else direct & 0x3ff)
fade u = dx*dx*(3-2*dx)                              ; 0x00a64a4c: d0*dx*3-2dx → d0²
   v = fy analog at 0x00a64a6c, w = fz analog 0x00a64a84
hash = permBase[(permBase[X0] + Y0)]                 ; 0x00a64a04
gradient table entry = NoiseState + hash*24 + 0x2008 ; 0x00a64ab4 str 0x2008
dot products against 3 gradients; two lerps by u then v:
   r = lerp(dotA, dotB, u); r2 = lerp(dotC, dotD, u); return lerp(r, r2, v)
```

## grad1 (0x00a64e28) — 2-corner variant

Same structure with 2 dots and one lerp (`sp+0x68/0x60` final blend at
0x00a65294..0x00a652a8); 1D lattice (perm idx without Y); used by noise2d.

## NoiseFunction layout (ObjC side)

- `self` ivars: `_structPtr` @+0 (points to malloc'd `NoiseState`, size
  **0x16080** from `__wrap_malloc` at 0x00a62848), `_tileable` @+4 (char).
- Field naming anchor: `-[initWithFrequencyX:…]` 0x00a62848..0x00a62a64
  stores `_structPtr` then computes freq pow2 ints, amplitude, tileable
  chars, calls `fn_seed_rand(seed)`, then builds a permutation table
  (0x400 entries) + 0x402-entry second table (0x00a62fa8..0x00a630fc) with
  `fn_rand` swaps — a Fisher-Yates style shuffle.
- NoiseState fields referenced by bodies:
  - `+0x16058 int freqPowX`, `+0x1605c int freqPowY`, `+0x16060 int freqPowZ`
  - `+0x16068 double amplitude`
  - `+0x16070 double persistance`
  - `+0x16078/79/7a char tileableX/Y/Z`
  - `+0x2008 double[3] gradient vectors` (indexed `hash*24`)
  - `+0xe038 double[2] gradient pair` (grad1 1D lattice, `hash*16`)
  - permutation int tables (built in init) at low offsets (via `permBase`).

## Pool constants

- `0x00a64948` / `0x00a652b8`: double **4096.0** (lattice offset before
  truncation — makes negatives positive)
- `0x00a634e8`: double 0.0 (noise2d init accumulators)
- `0x00a63990`: double 0.0 (noise3d init)

## Claim boundary

Octave-loop shape, fade (3-2x)x³, lattice offset 4096, gradient-table
addressing (+0x2008 hash*24, +0xe038 hash*16), 8-corner trilinear blend,
and clamp-to-1 octaves are byte-anchored. NOT claimed: exact permutation
table init formula, gradient vector values, fn_rand/fn_seed_rand internals
(those are separate symbols, unexamined), and exact NoiseState offsets
below +0x16058. `getX:Y:Z:octaves:`'s noise3d call args (which arg is which
axis at the bl 0xa635e8 boundary) pending one more pass.
