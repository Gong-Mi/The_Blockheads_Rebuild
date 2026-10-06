# Light-emission parameter trio — how emitters feed the light system

Ten bounded bodies (1301 verified words) that produce what the ArtificialLight
engine consumes: the base colour, per-emitter RGB, light position and glow
flags. Recovered from the pinned original `libApplication.so` (1.7.6,
armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_lightemitters.py`; JSON: `lightemitters.json`).

| body | IMP | end | words |
|---|---|---|---|
| `-[ArtificialLight lightColor]` | `0x00a93bbc` | `0x00a93c64` | 42 |
| `-[FireObject getLightRGB]` | `0x006746a4` | `0x00674704` | 24 |
| `-[GlowBlock getLightRGB]` | `0x00ca8334` | `0x00ca83d4` | 40 |
| `-[GlowBlock lightPos]` | `0x00ca955c` | `0x00ca960c` | 44 |
| `-[GlowBlock lightGlowQuadCount]` | `0x00ca9500` | `0x00ca955c` | 23 |
| `-[Torch getLightRGB]` | `0x004b4e98` | `0x004b52ac` | 261 |
| `-[Torch lightGlowQuadCount]` | `0x004bed90` | `0x004bedec` | 23 |
| `-[Torch isDownlight]` | `0x004bedec` | `0x004bee3c` | 20 |
| `-[Torch isUplight]` | `0x004bee3c` | `0x004bee90` | 21 |
| `-[Torch lightPos]` | `0x004be0d4` | `0x004bed60` | 803 |

## Colours

- **ArtificialLight lightColor** = `Vector((float)maxRed, (float)maxGreen,
  (float)maxBlue)` — the int fields @64/@68/@72 (cells
  `0xa93c5c`/`0xa93c58`/`0xa93c54`), `vcvt.f32.s32` each.
- **FireObject getLightRGB** = constant `Vector(128.0, 64.0, 1.0)` (pool
  `0x43000000`/`0x42800000`, `vmov.f32 s4, 1`).
- **GlowBlock getLightRGB**: `self.light@56` (cell `0xca83cc`) nil →
  `memset(out, 0, 0x10)` zero Vector; else
  `objc_msgSend_stret(out, self.light, @selector(lightColor))` — the glow
  block delegates to its light object's `lightColor` (selector cell
  `0xe87b14`, stret import `0x1c2918`).
- **Torch getLightRGB** = item-type dispatch over `Torch.itemType@64` (cell
  `0x4b52a4`), default `(253, 150, 55)`:

| itemType | (r, g, b) |
|---|---|
| default | 253, 150, 55 |
| 0x2f | 255, 255, 127 |
| 0xb7 | 12, 100, 220 |
| 0x96, 0xfe, 0x102 | 300, 300, 170 |
| 0x94 | 510, 130, 130 |
| 0x93 | 130, 510, 130 |
| 0x92 | 130, 130, 510 |
| 0x91 | 270, 230, 510 |
| 0x95 | 400, 510, 510 |
| 0x4b | 220, 0, 0 |
| 0x4c | 0, 220, 0 |
| 0x56 | 0, 0, 220 |
| 0x57 | 135, 115, 220 |
| 0x58 | 200, 255, 255 |

The result is converted `vcvt.f32.s32` and passed to `Vector(r, g, b)`.
The 0x4b/0x4c/0x56/0x57/0x58 kinds are exactly the torch types spawned by
`addToTiles` (cross-consistent with the tiles pair batch).

## Positions

- **GlowBlock lightPos** = `Vector(floatPos.x, floatPos.y + 5.0, 0.0)` — five
  units above the block's `DynamicObject.floatPos@24` (cell `0xca9604`).
- **Torch lightPos** (803 words) — `floatPos@24` base, then:
  - base out = `(floatPos.x, floatPos.y + 5.0, -1.0)`;
  - `Torch.chandelier@78` (ldrsb, cell `0x4bed38`) != 0 →
    `(x, floatPos.y - 0.1, -5.0)`;
  - else `Torch.flatOnSideAndBottom@77` (ldrsb, cell `0x4bed40`) != 0 →
    dispatch on `Torch.connectionType@60` (cell `0x4bed48`) only:
    `0 → (x, y, -1)`; `3 → (x, y, -0.1)`; `1 → (x+0.45, y+5, -1)`;
    `-1 → (x-0.45, y+5, -1)`; `2 → unchanged`; `-2 → z=-2`; else unchanged;
  - else dispatch on `Torch.itemType@64` (cell `0x4bed44`) then
    `connectionType`: `0x96 / 0xfe / 0x102 → y += 0.4`; `0x2f → y += 0.4`;
    anything else `→ y += 0.6`; then:
    - generic (0x96/0xfe/0x102): `3 → z=-5`; `1 → x += 2` (0x96) /
      `x += 0.4` (0xfe,0x102); `-1` mirrored; `2 → keep`; `-2 → z=-2`;
    - `0x2f`: `1 → y = floatPos.y + 0.6, x += 0.4`; `-1` mirrored;
      `2 → y = floatPos.y + 0.9`; `-2 → y = floatPos.y + 0.9, z=-2`;
    - default: `1 → y = floatPos.y + 0.9, x += 0.1`; `-1` mirrored;
      `2 → y = floatPos.y + 0.9`; `-2 → y = floatPos.y + 0.9, z=-2`.
  - Offsets are the pool constants 0.1 (`0x4be5c8`/`0xbe5ccd...` LE words
    0x3dcccccd), 0.4 (`0x3ecccccd`), 0.45 (`0x3ee66666`), 0.6
    (`0x3f19999a`), 0.9 (`0x3f666666`); z-values −1/−2/−5 via `vmov.f32`
    immediates; `connectionType` 1/−1 are wall-side connections (x
    offsets), 3 is the ceiling (z=-5).

## Glow flags

- `GlowBlock lightGlowQuadCount` = `1` unless `GlowBlock.tileType@60` (cell
  `0xca9554`) `== 0x4d` → 0.
- `Torch lightGlowQuadCount` = `1` unless `Torch.itemType@64` `== 0x9d` → 0.
- `Torch isDownlight` = `itemType == 0xfe` (254); `Torch isUplight` =
  `itemType == 0x102` (258).

## Boundaries

- FireObject overrides only `getLightRGB` — `lightPos` /
  `lightGlowQuadCount` are not in its method table (inherited or absent at
  this class level); recorded as observed for this class.
- `-[Torch isDownlight]`'s ARM.exidx region extends over both is-down/up
  twins; both specs are IMP-bounded (end `0x4bee3c` / `0x4bee90`) and their
  disassembly files are trimmed to match — noted in each boundary string.
- The render consumers (draw paths) and runtime values are outside these
  bodies.
