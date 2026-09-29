#!/usr/bin/env python3
"""Static contract for the original ItemType table and the rebuild alignment.

Pins:

* the two vendored reference enum snapshots (sha256 + source project pins),
* ``original_item_types.tsv`` - the assembled original table (426 types) and
  its cross-source agreement with the in-repo ELF extractions,
* ``assets/gamedata/items.json`` - every rebuild entry carries
  ``original_type``, mapped values are unique and resolve to the table,
* ``item_id_alignment.tsv`` - the per-item decision record.

Negative controls prove the checks bite on mutation.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction/reverse-v3/native"

REFERENCE_SHA256 = {
    "reference_itemtype_enum.txt":
        "77bf858c6a91cd5af8a62357e036654b066304728af8c7add8c9ae97db933436",
    "reference_voxeltype_enum.txt":
        "5108e7a7b1268ce4b604009e42098de1abd69bf2dc66ec0c311f10c7efff35ad",
}
TBHT_COMMIT = "c9bc7eea11ecdefa7de47000bfe70b14be374f3c"
TBHT_SOURCE_SHA256 = {
    "crates/lib/src/game/item.rs":
        "dce6f5fbb0f313e6d5c008deccc3a606688cd148444ba7e900e20fa384ce945c",
    "crates/gui/src/gpu/voxel.rs":
        "0c0201670729bc5e238cbbe7851d90356899a9efac48a2851d0f0bf2773859e1",
}
OUTPUT_SHA256 = {
    "original_item_types.tsv":
        "4756fdb69106bf0f2b8570e9f2e186a2972f95f0cfb2c91c912b8633bebb0420",
    "item_id_alignment.tsv":
        "9d037282abfdb9bbf77d369f134e53d1792aebfc53e708d659a41cfc9a885f5b",
}

ITEM_ROWS = {
    0: ("Unknown", 32, 0, 1),
    58: ("Window", 109, 13, 3),
    168: ("Shop", 304, 16, 9),
    174: ("BlackWindow", 118, 22, 3),
    1024: ("Stone", 33, 1, 1),
    1043: ("Chest", 342, 22, 10),
    1048: ("Dirt", 64, 0, 2),
    1049: ("Wood", 196, 4, 6),
    1051: ("Sand", 65, 1, 2),
    1057: ("ReinforcedPlatform", 164, 4, 5),
    1060: ("Ice", 110, 14, 3),
    1087: ("ElevatorShaft", 583, 7, 18),
    1088: ("ElectricElevatorMotor", 584, 8, 18),
    1105: ("LuminousPlaster", 746, 10, 23),
}

ITEMS_SPOT = {
    "ITEM_DIRT": 1048, "ITEM_STONE": 1024, "BLOCK_WOOD": 1049,
    "BLOCK_SAND": 1051, "ITEM_GOLD_ORE": 73, "ITEM_CHILI": 112,
    "ITEM_PICKAXE": 8, "ITEM_TIME_CRYSTAL": 11, "ITEM_COPPER_WIRE": 178,
    "BLOCK_PLATFORM": 1057, "ITEM_ELEVATOR_MOTOR": 1088,
    "ITEM_ELECTRIC_FURNACE": 1079, "ITEM_EMPTY": 0,
}
NULL_ITEMS = {
    "BLOCK_LEAVES", "BLOCK_GRASS", "BLOCK_SNOW", "BLOCK_CACTUS",
    "ITEM_COAL_GENERATOR", "ITEM_ELECTRIC_LAMP", "ITEM_SUNFLOWER",
    "ENTITY_DODO", "ENTITY_DROP_ITEM", "ENTITY_YAK", "ENTITY_DROPBEAR",
    "BLOCK_TC_ORE", "BLOCK_STONE_WALL", "ITEM_BRONZE_AXE",
    "ITEM_BRONZE_SPADE", "ITEM_IRON_SPADE", "ITEM_GOLD_AXE",
    "ITEM_GOLD_SWORD",
}
STATUS_TALLY = {"placeholder": 1, "aligned": 62, "aligned_differs": 6,
                "tile_only": 5, "no_original": 9, "entity": 4}


def parse_table(text: str) -> dict[int, dict[str, str]]:
    rows: dict[int, dict[str, str]] = {}
    lines = text.splitlines()
    header = lines[0].split("\t")
    for line in lines[1:]:
        if line.strip():
            row = dict(zip(header, line.split("\t")))
            rows[int(row["item_type"])] = row
    return rows


def check_items_json(text: str, table: dict[int, dict[str, str]]) -> list[str]:
    errors: list[str] = []
    items = json.loads(text)
    if len(items) != 87:
        errors.append(f"expected 87 rebuild items, got {len(items)}")
    ids = [item.get("string_id") for item in items]
    if len(ids) != len(set(ids)):
        errors.append("duplicate string_id")
    mapped: list[int] = []
    for item in items:
        if "original_type" not in item:
            errors.append(f"{item.get('string_id')}: missing original_type")
            continue
        value = item["original_type"]
        if value is None:
            if item["string_id"] not in NULL_ITEMS:
                errors.append(f"{item['string_id']}: unexpected null mapping")
            continue
        mapped.append(value)
        if value not in table:
            errors.append(f"{item['string_id']}: {value} absent from table")
    if len(mapped) != len(set(mapped)):
        errors.append("duplicate original_type mappings")
    if len(mapped) != 69:
        errors.append(f"expected 69 mapped values, got {len(mapped)}")
    by_id = {item["string_id"]: item.get("original_type") for item in items}
    for string_id, expected in ITEMS_SPOT.items():
        if by_id.get(string_id) != expected:
            errors.append(f"{string_id}: expected {expected}, "
                          f"got {by_id.get(string_id)}")
    for item in items:
        if item["string_id"] in NULL_ITEMS and item["original_type"] is not None:
            errors.append(f"{item['string_id']}: expected null mapping")
    return errors


def check_cross_source(table: dict[int, dict[str, str]],
                       image_map_text: str) -> list[str]:
    errors: list[str] = []
    for line in image_map_text.splitlines()[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        item_type = int(parts[0])
        row = table.get(item_type)
        if row is None:
            errors.append(f"image map type {item_type} missing from table")
            continue
        expected = (parts[1], parts[2], parts[3], parts[4], parts[5], parts[6])
        actual = (row["image_a0"], row["col_a0"], row["row_a0"],
                  row["image_a1"], row["col_a1"], row["row_a1"])
        if expected != actual:
            errors.append(f"type {item_type}: image map {expected} != "
                          f"table {actual}")
    return errors


def main() -> None:
    for name, expected in REFERENCE_SHA256.items():
        actual = hashlib.sha256((NATIVE / name).read_bytes()).hexdigest()
        assert actual == expected, f"{name} sha256 changed: {actual}"
        text = (NATIVE / name).read_text()
        assert TBHT_COMMIT in text, f"{name}: missing pinned commit"
        source = "item.rs" if "itemtype" in name else "voxel.rs"
        source_sha = TBHT_SOURCE_SHA256[f"crates/lib/src/game/{source}"] \
            if source == "item.rs" else TBHT_SOURCE_SHA256[
                "crates/gui/src/gpu/voxel.rs"]
        assert source_sha in text, f"{name}: missing source sha256"

    table_text = (NATIVE / "original_item_types.tsv").read_text()
    actual = hashlib.sha256(table_text.encode()).hexdigest()
    assert actual == OUTPUT_SHA256["original_item_types.tsv"], actual
    table = parse_table(table_text)
    assert len(table) == 426, len(table)
    for item_type, (name, image, col, row) in ITEM_ROWS.items():
        entry = table[item_type]
        assert entry["name"] == name, (item_type, entry)
        assert entry["image_a0"] == str(image), (item_type, entry)
        assert entry["col_a0"] == str(col), (item_type, entry)
        assert entry["row_a0"] == str(row), (item_type, entry)
    assert table[168]["image_a1"] == "305" and table[168]["col_a1"] == "17"
    assert "tile10(MinedStone)" in table[1024]["sources"]
    assert "price" in table[1024]["sources"]
    assert "imagetype@0x004d73c0" in table[1024]["sources"]
    assert "tile9(Wood)" in table[1049]["sources"]
    assert "tile4(Ice)" in table[1060]["sources"]
    priced = sum(1 for row in table.values() if row["price"])
    assert priced == 266, priced
    imagetype = sum(1 for row in table.values()
                    if "imagetype" in row["sources"]
                    and not row["sources"].split(";")[0] == "enum;placeholder")
    assert imagetype == 85, imagetype
    # the documented default rule: unmapped types resolve to image 32 (0, 1)
    for item_type in (3, 200, 343):
        entry = table[item_type]
        assert (entry["image_a0"], entry["col_a0"], entry["row_a0"]) == \
            ("32", "0", "1"), (item_type, entry)

    image_map_text = (NATIVE / "original_item_image_map.tsv").read_text()
    assert check_cross_source(table, image_map_text) == []
    mutated_map = image_map_text.replace(
        "1024\t33\t1\t1\t33\t1\t1\t0x004d73c0",
        "1024\t34\t2\t1\t34\t2\t1\t0x004d73c0")
    assert check_cross_source(table, mutated_map)

    items_text = (ROOT / "assets/gamedata/items.json").read_text()
    assert check_items_json(items_text, table) == []
    mutated_items = items_text.replace(
        '"original_type": 1024, "string_id": "ITEM_STONE"',
        '"original_type": 1048, "string_id": "ITEM_STONE"')
    assert mutated_items != items_text
    assert check_items_json(mutated_items, table)

    alignment_text = (NATIVE / "item_id_alignment.tsv").read_text()
    actual = hashlib.sha256(alignment_text.encode()).hexdigest()
    assert actual == OUTPUT_SHA256["item_id_alignment.tsv"], actual
    rows = [line.split("\t")
            for line in alignment_text.splitlines()[1:] if line.strip()]
    assert len(rows) == 87, len(rows)
    tally: dict[str, int] = {}
    for row in rows:
        tally[row[5]] = tally.get(row[5], 0) + 1
    assert tally == STATUS_TALLY, tally
    by_id = {row[1]: row for row in rows}
    for string_id, expected in ITEMS_SPOT.items():
        assert by_id[string_id][3] == str(expected), (string_id, by_id[string_id])
    for string_id in NULL_ITEMS:
        assert by_id[string_id][3] == "null", (string_id, by_id[string_id])

    print("item-id-alignment-evidence: PASS (426 original types, 266 priced, "
          "87 rebuild items, 69 mapped, cross-source agreement x85)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
