# Item ID domains and the explicit compatibility bridge

Client input: Android 1.7.6 ARM ELF SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## Evidence identity

`original_item_types.tsv` keeps these fields separate:

- `reference_name`: independent TheBlockheadsTools labels (MIT), commit
  `c9bc7eea11ecdefa7de47000bfe70b14be374f3c`; NOT original developer identifiers.
- `server171_symbol`: verbatim Linux server 1.7.1 DWARF enum symbols, extracted
  on the `methods/dwarf` line at `a4508b92b2db2fd9862b8b52a5af872c4e98403e`.
  `server171_itemtype_enum.txt` pins the source JSON and ELF hashes. Its 428
  entries include sentinels `ITEM_SPRITE_ITEM_COUNT=344` and `ITEM_MAX=1106`.
  The remaining numeric set matches the 426 reference entries. This does NOT
  establish Android 1.7.6 semantics or ABI equivalence for every entry.
- Client numeric evidence: 85 switch entries from `imageTypeForItemType`, direct
  TileType-to-ItemType assignments, and 266 `defaultPrices` id/price records.
  Prices contain no names. Agreement with a table used as input is a generation
  check, not an independent semantic oracle.

Examples of distinct labels: 1024 is reference `Stone` / server `ITEM_COBBLESTONE`;
73 is `GoldNugget` / `ITEM_GOLD_ORE`; 1057 is `ReinforcedPlatform` /
`ITEM_WOODEN_PLATFORM`. Neither column silently replaces the other.

## Atlas and terrain domains

`texCoordsForItemType` at 0x004d6040 is the Items sprite-coordinate path.
`tileTexCoordsForItemType` at 0x005f0450 calls `imageTypeForItemType` at
0x004d71dc: the latter's images belong to **TileMap, 32x32**, not Items, 32x16.
The assembled columns are therefore explicitly `tile_image/col/row_a0/a1`,
with `atlas_domain=TileMap:32x32`. Image32 is this tile helper's fallback; it
is NOT the inventory icon for all low-range items. Elevator images at row18
are valid TileMap cells and must not be sampled from Items.

`reference_voxeltype_enum.txt` is a third-party GUI/GPU enum. It combines
terrain and content variants; it is no longer used to label original TileType
values. In particular its Cactus115/116 are not client Tile byte3's 43/44.

## Runtime boundary

Legacy `ItemID` and `world.bin` numbers are unchanged. All 87 decisions are in
`align_rebuild_items.py`, with frozen compatibility IDs. There are 68 positive
mappings, empty0, and 18 unmapped entries. `tile_only` / `no_original` mean
conservative unmapped decisions, NOT proof that a reference omission proves
absence in the client. Entity markers are not inventory items.

`process_items.py` validates the complete list before writing, then generates
`ItemDef.originalType` and `ORIGINAL_*` constants. Unknown/unmapped is -1;
empty is0. `ItemManager::{toOriginalType,fromOriginalType,getDefFromOriginalType}`
never falls back to identity conversion. Thus original31 resolves to legacy7
(Copper Ore), while legacy31 remains Dodo Meat; original1048 resolves to Dirt.

`Player::addOriginalItem` consumes this conversion before using the existing
inventory implementation; `originalItemType(slot)` exports the ID. Default
new-world supplies call the original-ID entry. Their legacy slots/counts are
asserted unchanged. The bridge handles ID/count only, not dataA/dataB, nested
containers, clothing, or the original InventoryItem codec. Recovered snapshot
objects are still not the active gameplay world. TexRow/texCol rendering,
world.bin format and the separate Rust prototype are not migrated here.

## Reproduction and acceptance

    python3 tools/extract_original_item_types.py
    python3 tools/align_rebuild_items.py
    python3 tools/extract_original_item_types.py --check
    python3 tools/align_rebuild_items.py --check
    python3 tools/test_item_id_alignment_evidence.py
    python3 tools/test_item_alignment.py

Generation rejects duplicate keys, replaces rather than prefixes existing
original_type, accepts JSON independently of formatting, and is idempotent.
The guard compares ALL JSON decisions and ALL TSV rows, pins all reviewed
numeric mappings, and mutates each entry independently as a negative control.
CMake's gameplay tests compile the actual ItemManager/Player and generated data:
`gameplay_item_namespace` covers all87 decisions and all65536 uint16 inputs;
`gameplay_original_ids` imports original31/1088, edits real inventory/terrain,
saves the development world.bin, reloads it and exports the same original IDs.
These are host production-source tests with the worker stopped, not JNI/GPU,
original-save compatibility or device acceptance.
