# Item sprite coordinates (Items.png) - A-grade, read from the pinned ELF

ELF `libApplication.so` (armeabi-v7a), sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## The two original paths

| path | function | domain |
|---|---|---|
| inventory icon cell | `texCoordsForItemType` @ `0x004d6040` | every item type |
| atlas image index | `imageTypeForItemType` @ `0x004d71dc` (jump table) | collectibles 1024..1105 + three low specials |

`tileTexCoordsForItemType` @ `0x005f0450` is a third path (tile rendering) and is
not what this table describes.

## What `texCoordsForItemType` computes

Disassembly of the prologue loads five literal-pool constants before any
arithmetic:

```text
0x004d604c  vldr s0, [pc, #0xcc]   ; pool 0x004d6120  f32 0.0615234375 = 126/2048  (u span)
0x004d6050  vldr d1, [pc, #0xb0]   ; pool 0x004d6108  f64 0.00048828125 =   1/2048  (half texel)
0x004d6054  vldr d2, [pc, #0xb4]   ; pool 0x004d6110  f64 0.0625        =   1/16    (v step)
0x004d6058  vldr s6, [pc, #0xc4]   ; pool 0x004d6124  f32 0.0302734375 =  62/2048  (v span)
0x004d605c  vldr d4, [pc, #0xb4]   ; pool 0x004d6118  f64 0.03125       =   1/32    (u step)
0x004d6060  movw r2, #0x20         ; divisor 32
```

Note the widths: the two spans are **single-precision** pool floats while the
half-texel and the steps are **doubles**. Reading a span with the double reader
is what a first pass of the extractor got wrong, and the assertion in
`tools/extract_original_item_sprite_map.py` now fails loudly on any such mixup.

The body then divides the item type by 32 twice (quotient and remainder via PLT
helpers) and stores a four-field structure:

```text
out[0] = f(quotient)  * (1/32) + (1/2048)     ; u
out[1] = f(remainder) * (1/16) + (1/2048)     ; v
out[2] = 62/2048                              ; v span
out[3] = 126/2048                             ; u span
```

The only assignment that fits a 2048x1024 atlas is **32 columns x 16 rows of
64x64 cells**:

```text
col = type % 32      u = col/32 + 1/2048
row = type / 32      v = row/16 + 1/2048
u span = 126/2048    v span = 62/2048
```

(512 cells; item type 511 is the last that fits. Types at or above 1024 therefore
cannot use this formula - they belong to the jump-table image domain, which is
why the table keeps their `imageTypeForItemType` image index instead of a
formula cell.)

## Coverage

`tools/extract_original_item_sprite_map.py` joins both paths over every item type
in `original_item_types.tsv`:

| source | rows |
|---|---:|
| `formula@0x4d6040` (types < 1024) | 344 |
| `imageTypeForItemType@0x004d71dc` (types >= 1024) | 82 |
| unresolved | 0 |
| **total** | **426** |

Artifacts: `original_item_sprite_map.tsv`, `item_sprite_map.json` (both
regenerated and `--check`-gated), enforced by `tools/test_item_sprite_map.py`
and required by `tools/validate_reverse_evidence.py`.

## Boundaries

- The formula domain is asserted, not the renderer's use of it: whether the
  replacement draws inventory icons from these cells is a separate integration
  step and is not claimed here.
- HD vs SD: the pool constants describe a 2048x1024 atlas, i.e. the HD
  `HDTex/Items.png` the renderer already loads; the SD `Items.png` shares the
  same 32x16 logical grid at 32x32 px cells.
- The three low specials (58, 168, 174) keep their tabulated jump-table rows in
  `original_item_image_map.tsv`; this table lists them through the formula path
  because that is the path every type below 1024 goes through.
- No device run and no visual comparison is claimed.
