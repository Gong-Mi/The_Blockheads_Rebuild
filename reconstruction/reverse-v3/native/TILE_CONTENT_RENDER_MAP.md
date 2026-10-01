# Tile content render map (reloadDrawBlock `Tile[3]`) and its classes

The middle render pass asks a switch on the tile's `Tile[3]` content value for a
draw-image pair. `tools/extract_original_tile_content_render_map.py` closes the
whole domain `[3, 123]` - 121 values, one row each - instead of listing only the
values that assign immediately.

## Classes (current run)

| class | count | evidence |
|---|---:|---|
| `direct` | 61 | the case body assigns an image and column/row inline |
| `shared-body` | 59 | the case target is the shared body at `0x00a22d70` |
| `delegated-dispatch` | 1 | content 46 (`0x00a22b90`): pool loads, then `blx reg`, no inline assignment |

## What "shared-body" means (decoded in R22/R23)

The shared body is a dispatch, not a default: six constants compared against
`[fp,-0x540]` (`0xe0`, `0x100`, `0x109`, `0x112` - twice - `0x1e0`, `0x200`), an
inline 77-entry jump table at `0x00a22ed0` (51 distinct targets), and an arithmetic
path whose result is added to two frame slots. All 51 branch bodies assign from a
five-value set (`0`, `2`, `3`, `109`, `129`). See `TILE_SHARED_BODY_STRUCTURE.md`.

## Content 46

Previously the single `unresolved` row and counted as such. Its case body was
decoded: no `movw` draw-image assignment in the first 64 instructions, but pool
loads followed by **indirect calls through registers** (`blx r2` at `0x00a22c38`,
`blx r3` at `0x00a22c58`) - it delegates to a method instead of computing a cell in
this table. Classified `delegated-dispatch` **with that evidence**, not resolved:
what the callee draws is not claimed here.

## Boundaries

- A classification says what the case body does, not what pixels appear.
- `shared-body` and `delegated-dispatch` rows carry no draw cell on purpose; the
  table never guesses one.
- The 51 branch targets' smaller assignment values may be modes rather than image
  ids; distinguishing them needs the consuming store (see the shared-body doc).
