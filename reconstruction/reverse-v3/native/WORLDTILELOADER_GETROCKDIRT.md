# WorldTileLoader -[getRockAndDirtHeightforX:rockHeight:dirtHeight:] static map

Original ELF SHA-256 `733d8210…b94c7`; types `v20@0:4i8^i12^i16`. IMP
`0x00857188`, ARM.exidx end `0x00857340`, 110 words verified against the
pinned bytes (`tools/recover_worldtileloader_getrockdirt.py --check`). PIC/GOT
base `0x0105faf4`.

This is the height-array lookup primitive consumed by the terrain refinement
pipeline. It does not generate a new height; it wraps the x index and reads
the already prepared rock/dirt arrays.

## Exact static behavior

```text
width = [self->world worldWidthMacro] * 32
if (x < 0) {
    x += width
} else if (x >= width) {
    x -= width
}
*rockHeight = self->rockHeights[x]
*dirtHeight = self->dirtHeights[x]
```

The two wrap branches are anchored at `0x008571b4` and `0x00857260`.
The negative branch adds one `width`; the positive branch subtracts one
`width`. This is a one-step wrap, not a general modulo loop, so callers are
expected to pass x within one width of the valid interval.

## Anchored cells and dispatch

| literal cell | resolved fact |
|---|---|
| `0x0085731c` → `0x0105dd4c` | `OBJC_IVAR_$_WorldTileLoader.world`, offset 4 |
| `0x00857324` → `0x00e823a8` | selector `worldWidthMacro` |
| `0x00857330` → `0x0105dd60` | `OBJC_IVAR_$_WorldTileLoader.rockHeights`, offset 96 |
| `0x00857338` → `0x0105dd5c` | `OBJC_IVAR_$_WorldTileLoader.dirtHeights`, offset 92 |

There are exactly three `objc_msgSend` calls at `0x008571ec`, `0x00857248`,
and `0x00857298`, all byte-decoded to the shared PLT stub `0x001c281c`
with GOT slot `0x0105b7a0`. The repeated width query occurs separately in
the negative, positive, and final array-read paths; no common cached width is
used across those paths.

Claim boundary: static bounded-body map. Array contents, initialization
order, and caller guarantees about x range require the surrounding
`getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:` and constructor
bodies; this method alone does not prove them.
