# WorldTileLoader -[refineTerrainCount] static map

Original ELF SHA-256 `733d8210…b94c7`; types `i8@0:4` (int return, no
arguments beyond self/_cmd). IMP `0x00854c18`, ARM.exidx end `0x00854c54`,
15 words verified against the pinned bytes
(`tools/recover_worldtileloader_refineterraincount.py --check`). PIC/GOT base
`0x0105faf4` — the same GOT as the GameView compilation-unit family.

First bounded slice of the map-generation front: `WorldTileLoader` owns the
terrain pipeline (`refineTerrain`, `faultOffsetForX:y:`, `isCaveForX:y:
faultOffset:`, `placeGemsInCaveForPhysicalBlock:…` among 52 indexed methods).

## Body (complete, no calls, no branches)

```text
sub sp, sp, 8                       ; 0x00854c18
r2 = 0x00854c28 + 0x80aecc = 0x0105faf4   (GOT base)   ; 0x00854c1c..0x00854c20
r3 = word 0x00854c4c = 0xffffe2c8 (-0x1d38)
r2 = *(0x0105faf4 - 0x1d38) = *(0x0105ddbc) = 0x00f33f7c
     = &OBJC_IVAR_$_WorldTileLoader.refineTerrainCount
spill self/_cmd
r1 = *(0x00f33f7c) = 232            (ivar offset)
r0 = *(self + 232)                  (the stored int)
add sp, sp, 8 ; bx lr               ; 0x00854c44..0x00854c48
```

Reviewed semantics: pure ivar getter — returns `*(int*)(self + 232)`, the
`refineTerrainCount` field. The field name is the compiled-in ivar symbol; the
value's meaning (refinement iteration budget for `-[refineTerrain]`, IMP
`0x00854c54`) is inferred from the selector pair only and is not established
by this body. Writer identity and write timing are outside this body; the
tool explicitly rejects any bl/blx/branch encoding inside the bounded range.

Claim boundary: static bounded-body map with per-word anchors; no runtime
value, writer, or call-order proof.
