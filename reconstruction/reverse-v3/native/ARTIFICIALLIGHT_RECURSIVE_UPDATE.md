# ArtificialLight propagation engine — recursivelyUpdateLightWithList:

`-[ArtificialLight recursivelyUpdateLightWithList:]`
(`0x00a8f22c` .. `0x00a91d30`, 2753 instructions) — the engine behind
`addToTiles` and `addContributionForPhysicalBlockLoadedAtXPos:yPos:`: the
single-step relaxation that turns a work list of world indices into grid
updates and re-enqueues. Recovered from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_artificiallight_recursiveupdate.py`; JSON:
`artificiallight_recursiveupdate.json`).

## Shape

1. **Pop & resolve.** `pop_front` the work list; idx = popped world index;
   `getWorldPosForWorldIndex(idx, &x, &y, self.world)`; `mt = [self.world
   macroTiles]`; `tile = tileAtWorldPosition(x, y, mt, self.world)`; if
   `!tile` → return.
2. **x wrap.** With `w16 = ([self.world worldWidthMacro] << 5) / 2`
   (three staged sub-branches via `__aeabi_idiv` at `0xa8f3d0`/`0xa8f49c`/
   `0xa8f578`): `x - pos.x >= w16` → `x -= w*32`; `x - pos.x < -w16` →
   `x += w*32`. y never wraps (x-cylindrical world).
3. **Cell & culls.** `dx = x - contributionGridOrigin.x`,
   `dy = y - origin.y`; cull unless `0 <= dx < diameter` and
   `0 <= dy < diameter`; `idx5 = dy*diameter + dx` (`mla` at `0xa8f5e0`);
   `v = (int16)contributionGrid[idx5*5]`. If `(x,y) == self.pos`:
   `v = radius*10` (`movw r0, 0xa` + `mul` at `0xa8f654`/`0xa8f674`) and skip
   straight to commit.
4. **Eight-neighbourhood relaxation** (below), saturating merge
   `v = max(v, nv)` into the running value.
5. **Commit.** If `v <= stored grid16[idx5*5]` → return; else store
   `grid16[idx5*5] = (int16)v` (`strh r1, [r2]` at `0xa9155c`); then, for
   each orthogonal neighbour whose recent value the new `v` exceeds
   (guards at `0xa91564`/`0xa91748`/`0xa91924`/`0xa91b04`), enqueue the
   neighbour index `worldIndexAtWorldPosition(x, y+1 / x, y-1 / x+1, y /
   x-1, y, self.world)` through a std::list insertion sequence (node scans
   at `0xa91628`/`0xa91808`/`0xa919e4`/`0xa91bc4`; `push_back` at
   `0xa9173c`/`0xa91918`/`0xa91af8`/`0xa91cd4`).

## Per-neighbour relaxation (all 8, culls identical)

Per neighbour `(ddx, ddy) in {(0,+1),(0,-1),(+1,0),(-1,0),(+1,+1),
(+1,-1),(-1,+1),(-1,-1)}`: `rel = (dx+ddx, dy+ddy)`; cull against the same
grid bounds; `nv = (int16)contributionGrid[rel_idx*5]`; skip when
`nv <= 1`; `ntile = tileAtWorldPosition(x+ddx, y+ddy, mt, self.world)`;
skip when `!ntile`. With `dir = self.lightDirection`:

| neighbour | water | air | dir special (zero) | dir special (attenuate) |
|---|---|---|---|---|
| N (0,+1) | `nv -= max(r*5/6, 5)` | `-10` | dir==2 → `0` | `max(r*10/6, 10)` |
| S (0,-1) | `max(r*5/6, 5)` | `-10` | dir==1 → `0` | `max(r*10/6, 10)` |
| E (+1,0) | `max(r*5/6, 5)` | `-10` | — | dir∈{1,2} → `max(r*20/6, 20)`; dir∈{0,3} → `max(r*10/6, 10)` |
| W (-1,0) | `max(r*5/6, 5)` | `-10` | — | same as E |
| NE (+1,+1) | `max(r*7/6, 7)` | `-14` | dir==2 → `0` | `max(r*14/6, 14)` |
| SE (+1,-1) | `max(r*7/6, 7)` | `-14` | dir==1 → `0` | `max(r*14/6, 14)` |
| NW (-1,+1) | `max(r*7/6, 7)` | `-14` | dir==2 → `0` | `max(r*14/6, 14)` |
| SW (-1,-1) | `max(r*7/6, 7)` | `-14` | dir==1 → `0` | `max(r*14/6, 14)` |

Solid tiles (`!tileIsAirWaterOrSnow && !tileIsSemiTransparentSolidBlock`)
route into the same direction paths (N/S/diagonals with the block's zero
dir value cannot occur from solid because the dir re-check in the common
tail routes only the matching dir to zero; E/W solid lands on the
`dir∈{0,3}` branch). `r` = `self.radius`; all divisors are the literal 6.

Anchors: every constant is pinned by address in the tool (e.g. water
`movw r0, 5` @`0xa8f888` + `movw r1, 6` @`0xa8f88c`; air `sub r0, r0, 0xa`
@`0xa8f914`; N special `movw r0, 0xa` @`0xa8f944`; zero `movw r0, 0`
@`0xa8f9cc`; diagonal water `movw r0, 7` @`0xa90870`; E/W 20/6 `movw r0,
0x14` @`0xa9010c`/`0xa90580`; dir compares `cmp r0, 1`/`cmp r0, 2` at the
per-block check pairs).

## Class layout anchors

- Selectors: `macroTiles` (`0xa9017c`, `0xa91cf8`), `worldWidthMacro`
  (`0xa90188`); import `objc_msgSend` (`0xa90178`, `0xa91cf4`).
- Ivar descriptor cells: `DynamicObject.world`@4 (`0xa90174`,
  `0xa91cf0`), `DynamicObject.pos`@16 (`0xa90180`),
  `ArtificialLight.contributionGridOrigin`@84 (`0xa904a4`, `0xa91cfc`),
  `diameter`@92 (`0xa90554`, `0xa91d00`), `contributionGrid`@56
  (`0xa905e4`, `0xa91d04`), `radius`@80 (`0xa905e8`, `0xa91d0c`),
  `lightDirection`@96 (`0xa905f0`, `0xa91d08`).
- Direct calls (67 `bl` + 9 `blx` = 76 sites): `tileAtWorldPosition`
  `0xa16e68` (x9), `tileIsAirWaterOrSnow` `0xa126dc` (x8),
  `tileIsSemiTransparentSolidBlock` `0xa128b0` (x8), `tileIsWater`
  `0xa11690` (x8), `__aeabi_idiv` `0x1c3728` (x20),
  `worldIndexAtWorldPosition` `0xa156a8` (x4),
  `getWorldPosForWorldIndex` `0xa15518` (x1),
  `std::__1::list<unsigned int>::pop_front` `0xa91d30`,
  `push_back` `0xa91e48` (x4), `objc_msgSend` `0x1c281c`.

## Boundaries

- The std::list scan scaffolds (`0xa91628` etc.) are compiler bookkeeping:
  only their inputs (neighbour indices), guards and `push_back` sites are
  claimed as semantics; node-link walking is recorded mechanically.
- The commit guard `[fp,-0x230]` is initialized to 0 and never re-written
  in this body; recorded as observed (N re-enqueue degenerate guard).
- `contributionGrid` per-cell layout is 5 int16 (index 0 = the value this
  engine reads/writes at `idx5*5`); the remaining channels belong to the
  addToTiles/removeFromTiles pair batch.
