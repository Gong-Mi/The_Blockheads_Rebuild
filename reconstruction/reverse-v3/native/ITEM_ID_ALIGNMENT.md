# ItemType namespace alignment (rebuild <-> original)

This document records how the rebuild's item table is aligned with the
original 1.7.6 ItemType namespace, and where each fact comes from.  Original
ELF: `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## The three numbering systems

| System | Range | Role |
|---|---|---|
| Original ItemType | sparse 0..343 and 1024..1105 (426 values) | what saves, wire data and the native helpers speak |
| Rebuild `items.json` ids | dense 0..272 (87 items) | the app's compatibility layer; **not** original |
| Rust server item ids | dense 0..63 | a separate placeholder line (out of scope here) |

## Evidence sources

A-grade (in-repo ELF extractions of the original binary):

* `tools/extract_original_item_image_map.py` -> `original_item_image_map.tsv`:
  every case of `imageTypeForItemType` @0x4D71DC, including the full
  [0x400, 0x451] block, the low cases 58/168/174, and the documented default
  image 32 (atlas 0,1) for unmapped types.
* `tools/extract_original_tile_item_map.py` -> `original_tile_item_map.tsv`:
  the direct `itemTypeFromTileIsForegorund` @0x00A18044 tile -> item
  assignments.

Original APK asset:

* `assets/defaultPrices` (binary plist): 266 priced ItemType ids with
  `price`/`old_price` as originally shipped.

C+ correlation names (independent project, MIT):

* `reference_itemtype_enum.txt` and `reference_voxeltype_enum.txt` are
  snapshots of `medioqrity/TheBlockheadsTools` @
  `c9bc7eea11ecdefa7de47000bfe70b14be374f3c` (source sha256s in the file
  headers).  These provide the human-readable names; the NUMBERS are
  corroborated by the A-grade extractions wherever the ranges overlap
  (e.g. Stone=1024 with image 33 (1,1) and tile 10 -> 1024; Ice=1060 with
  tile 4 -> 1060; Shop=168 with the arg2 image pair 304/305; Window=58 with
  109 (13,3); BlackWindow=174 with 118).  They are not an original header.

## Assembled table

`tools/extract_original_item_types.py` joins the four sources into
`original_item_types.tsv` (426 rows): item type, hex, name, both image
variants and atlas cells, price, and a `sources` column listing which
evidence covers the row (`enum`, `tileN(Name)`, `price`, `imagetype@VA`).
The tool refuses to write on cross-source contradiction; the shipped file is
additionally pinned by `tools/test_item_id_alignment_evidence.py`
(reference snapshot shas, 426 rows, spot rows, 266 priced, 85 imagetype rows,
per-row agreement with the image map, default-image rule, negative controls).

The image index is `row * 32 + col` on the original atlas (`Items.png`,
32 columns x 16 rows; HD variant 64 px cells).  `image_a0` is the arg2==0
variant, `image_a1` the arg2!=0 variant of the five conditional pairs plus
Shop.

## Rebuild alignment

`tools/align_rebuild_items.py` resolves every rebuild entry against the
assembled table (normalised-name match plus the curated decisions in the
tool) and writes:

* `original_type` into every `assets/gamedata/items.json` entry (null when
  there is no original counterpart);
* `item_id_alignment.tsv`: the per-item decision record with status, original
  name, atlas cell, the original row's sources, and a note.

Result for the current 87 rebuild entries: 69 map onto original types
(62 normalised-equal names, 6 genuinely different original names, 1 engine
placeholder), and 18 have no original counterpart:

* 5 terrain-only materials (`BLOCK_LEAVES`, `BLOCK_GRASS`, `BLOCK_SNOW`,
  `BLOCK_CACTUS`, `BLOCK_TC_ORE`) - the original has these only as VoxelType
  terrain; `BLOCK_TC_ORE` additionally mines into item TimeCrystal 11;
* 9 rebuild-only items (`ITEM_COAL_GENERATOR`, `ITEM_ELECTRIC_LAMP`,
  `ITEM_SUNFLOWER`, `BLOCK_STONE_WALL`, `ITEM_BRONZE_AXE`,
  `ITEM_BRONZE_SPADE`, `ITEM_IRON_SPADE`, `ITEM_GOLD_AXE`,
  `ITEM_GOLD_SWORD`) - no such item exists in the original table;
* 4 entity markers (`ENTITY_DODO`, `ENTITY_DROP_ITEM`, `ENTITY_YAK`,
  `ENTITY_DROPBEAR`) - not item ids at all.

Mapped values are unique (no two rebuild items claim one original type) and
every mapped value resolves in the 426-row table; both facts are asserted by
the evidence test and the render contract now requires `original_type` on
every item definition.

## What this changes and what it does not

Changed:

* every item definition carries its aligned `original_type`;
* the relation is reproducible (`extract_original_item_types.py`,
  `align_rebuild_items.py`), documented and guarded in both CI workflows.

Not changed (explicit boundaries):

* the rebuild's own numeric ids are NOT renumbered: they remain the app
  compatibility layer noted in `STATIC_RENDER_CONTRACT.md`;
* renderer draw cells (`texRow`/`texCol`) stay as they are; the alignment
  provides the evidence to revisit them, it does not re-derive the three
  original draw-pass slots;
* save assembly / `OriginalClientWorld` consumers do not yet resolve original
  item types through this table at runtime - that wiring is follow-up work;
* the reference names remain C+ except where corroborated; the 169..1023
  range without explicit cases uses the documented default image and is
  marked `imagetype(default)`.

Regenerate:

```sh
python3 tools/extract_original_item_types.py
python3 tools/align_rebuild_items.py
python3 tools/test_item_id_alignment_evidence.py
```
