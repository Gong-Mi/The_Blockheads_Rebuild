# ArtificialLight physical-block-load re-registration hook

`-[ArtificialLight addContributionForPhysicalBlockLoadedAtXPos:yPos:]`
(`0x00a95248` .. `0x00a958bc`, 413 words) — what a torch/lamp does when a
client light block finishes loading: cull the block against the light's
radius, then retract, reset and re-add. Recovered from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_artificiallight_blockload.py`; JSON:
`artificiallight_blockload.json`). Types: `v16@0:4i8i12` (xPos@8, yPos@12).

## Semantics

**Cull.** `pair1 = makeIntpair(xPos << 5, yPos << 5)`;
`pair2 = makeIntpair((xPos+1) << 5, (yPos+1) << 5)` (the block's two tile
corners in world coordinates). With `h = ([self.world worldWidthMacro] << 5)
/ 2` (via `__aeabi_idiv`):

- `dx1 = self.pos.x - xPos*32` wrapped by the world width
  (`dx1 >= h` → `dx1 -= w*32`; `dx1 < -h` → `dx1 += w*32`);
  `dx2 = self.pos.x - (xPos+1)*32` wrapped the same way.
- Return (no work) when any of: `dx1 < -radius`; `dx2 >= radius`;
  `dy1 = self.pos.y - yPos*32 < -radius`;
  `dy2 = self.pos.y - (yPos+1)*32 >= radius`.
- y never wraps — the world is x-cylindrical; only x gets the half-wrap.

**Re-register.**
1. `objc_msgSend(self, @selector(removeFromTiles))` — retracts the old
   contributions. The call site carries an additional staged argument block
   (`r2 = &addToTiles` selector slot, `r3 = 0`,
   stack = `&diameter-descr, 5, 0, &addToTiles slot, PIC base, 1,
   objc_msgSend function pointer`) — recorded as observed; the method
   consumes none of it.
2. `memset(self.contributionGrid, 0, diameter*diameter*2*5)` — clears the
   whole grid (count = `(diameter<<1) * diameter * 5`;
   `and r1, r1, 0xff` anchors the 0 fill byte).
3. `objc_msgSend(self, @selector(addToTiles))` issued through the saved
   `objc_msgSend` function pointer (`blx r2`).

Net effect: stale contributions are retracted, the grid is reset, and
`addToTiles` re-runs the propagation engine + contribution walk against the
newly loaded block data.

## Anchors

- Selector cells: `worldWidthMacro` (`0xa9587c` → slot `0xe854d0`),
  `addToTiles` (`0xa958a4` → slot `0xe854f8`), `removeFromTiles`
  (`0xa958ac` → slot `0xe85518`); import `objc_msgSend`
  (`0xa958a0` → slot `0x0105b7a0`).
- Ivar descriptor cells: `DynamicObject.pos`@16 (`0xa95870`),
  `DynamicObject.world`@4 (`0xa95878`), `ArtificialLight.radius`@80
  (`0xa9588c`), `diameter`@92 (`0xa958a8`), `contributionGrid`@56
  (`0xa958b4`).
- Direct calls: `makeIntpair` `0x4b49fc` (x2), `__aeabi_idiv` `0x1c3728`
  (x4, the half-width / half-wrap divisors), `memset` `0x1c2924`,
  `objc_msgSend` `0x1c281c`, `blx r2` (the saved-pointer `addToTiles`
  dispatch). 17 call sites, 12 branches, all pinned.
- Key instructions: corner shifts (`0xa95278`/`0xa95280`), the two
  `rsb r0, r0, 0` negation seeds (`0xa953ec`, `0xa95624`), staged-arg
  constants (`movw r3, 0` / `movw ip, 5` / `movw r4, 1` at
  `0xa957ac`/`0xa957b0`/`0xa957bc`), the count chain
  (`lsl r0, r0, 1` `0xa95820`, `mul r0, r0, r3` `0xa95838`,
  `mul r2, r0, r3` `0xa95840`), memset fill byte (`0xa9584c`), and the
  `blx r2` tail (`0xa95864`).

## Boundaries

- The `removeFromTiles` / `addToTiles` bodies themselves are mapped in the
  tiles pair batch (`ARTIFICIALLIGHT_TILES.md`) — this hook only dispatches
  into them.
- Whether the propagation engine refills the cleared grid inside
  `addToTiles` step 1 is an engine-boundary claim; recorded as the observed
  call/data flow, not asserted about the engine internals.
- The staged argument block of the first dispatch is recorded mechanically
  (12-argument call site); no semantic load is claimed for unused args.
