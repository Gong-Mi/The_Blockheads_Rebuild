#!/usr/bin/env python3
"""Align the rebuild item table with the original ItemType namespace.

For every entry of ``assets/gamedata/items.json`` this tool resolves the
original ItemType value (when one exists) from the assembled
``reconstruction/reverse-v3/native/original_item_types.tsv`` table, records the
decision in ``item_id_alignment.tsv`` and writes the ``original_type`` field
back into ``items.json``.

The rebuild's own numeric ids are NOT renumbered here: they are the app's
compatibility layer (see STATIC_RENDER_CONTRACT.md).  This tool makes the
rebuild <-> original relation explicit and machine-checked so saves, rendering
and the recovered native helpers can speak the original namespace.

Statuses:
  aligned        - same item after name normalisation (case/spacing/punct)
  aligned_differs- mapped, but the original display name differs
  placeholder    - engine placeholder id (Air = original Unknown 0)
  tile_only      - the original has this only as terrain (VoxelType), no item
  entity         - rebuild creature marker, not an item id
  no_original    - no counterpart in the original item table (rebuild content)

`aligned` is asserted to mean exactly "normalised names equal"; the tool fails
if a row's status contradicts its names in either direction.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ITEMS_JSON = ROOT / "assets/gamedata/items.json"
NATIVE = ROOT / "reconstruction/reverse-v3/native"
ORIGINAL_TABLE = NATIVE / "original_item_types.tsv"
ALIGNMENT_TSV = NATIVE / "item_id_alignment.tsv"

# Curated decisions, keyed by the rebuild string_id.
# (original ItemType or None, status, note)
ALIGNMENT: dict[str, tuple[int | None, str, str]] = {
    "ITEM_EMPTY": (0, "placeholder", "original Unknown = 0"),
    "ITEM_DIRT": (1048, "aligned", ""),
    "ITEM_STONE": (1024, "aligned", ""),
    "BLOCK_WOOD": (1049, "aligned", ""),
    "BLOCK_LEAVES": (None, "tile_only",
                     "tree leaves are terrain only (VoxelType 92..134); "
                     "no original item"),
    "BLOCK_GRASS": (None, "tile_only",
                    "GrassDirt is terrain only (VoxelType 27); no original item"),
    "BLOCK_SAND": (1051, "aligned", ""),
    "ITEM_COPPER_ORE": (31, "aligned", ""),
    "ITEM_TIN_ORE": (36, "aligned", ""),
    "ITEM_GOLD_ORE": (73, "aligned_differs",
                      "original name GoldNugget; gold terrain yields nuggets"),
    "BLOCK_SNOW": (None, "tile_only",
                   "Snow is terrain only (VoxelType 5); no original item"),
    "ITEM_WORKBENCH": (1050, "aligned", "original spelling WorkBench"),
    "ITEM_TOOLBENCH": (1052, "aligned", "original spelling ToolBench"),
    "BLOCK_ICE": (1060, "aligned", ""),
    "BLOCK_CACTUS": (None, "tile_only",
                     "Cactus is terrain only (VoxelType 115/116); "
                     "no original item"),
    "BLOCK_GLASS": (1042, "aligned", ""),
    "ITEM_CRAFTBENCH": (1055, "aligned", "original spelling CraftBench"),
    "ITEM_FURNACE": (1031, "aligned", ""),
    "ITEM_IRON_ORE": (32, "aligned", ""),
    "ITEM_CHEST": (1043, "aligned", ""),
    "ITEM_TORCH": (17, "aligned", ""),
    "ITEM_FLINT": (3, "aligned", ""),
    "ITEM_STICK": (4, "aligned", ""),
    "ITEM_CAMPFIRE": (15, "aligned", ""),
    "ITEM_CHILI": (112, "aligned_differs", "original name Chilli"),
    "ITEM_DODO_MEAT": (29, "aligned", ""),
    "ITEM_COCONUT": (46, "aligned", ""),
    "ITEM_FUR": (121, "aligned", ""),
    "ITEM_COPPER_INGOT": (35, "aligned", ""),
    "ITEM_TIN_INGOT": (37, "aligned", ""),
    "ITEM_IRON_INGOT": (65, "aligned", ""),
    "ITEM_STEEL_INGOT": (92, "aligned", ""),
    "ITEM_BRONZE_INGOT": (38, "aligned", ""),
    "ITEM_GOLD_INGOT": (72, "aligned", ""),
    "ITEM_PICKAXE": (8, "aligned", ""),
    "ITEM_AXE": (6, "aligned", ""),
    "ITEM_SPADE": (16, "aligned", ""),
    "ITEM_COAL": (51, "aligned", ""),
    "ITEM_COPPER_WIRE": (178, "aligned", ""),
    "ITEM_COAL_GENERATOR": (None, "no_original",
                            "no coal generator in the original table "
                            "(power sources: SteamGenerator 1077, "
                            "SolarPanel 1082, Flywheel 1083)"),
    "ITEM_ELECTRIC_LAMP": (None, "no_original",
                           "no electric lamp in the original table "
                           "(lamps: OilLantern 47, SteelLantern 150, "
                           "IceTorch 183)"),
    "ITEM_WOOD_DOOR": (52, "aligned_differs", "original name Door"),
    "ITEM_WOOD_TRAPDOOR": (69, "aligned", ""),
    "ITEM_LADDER": (53, "aligned", ""),
    "ITEM_FLAX_SEED": (54, "aligned", ""),
    "ITEM_FLAX": (55, "aligned", ""),
    "ITEM_SUNFLOWER_SEED": (61, "aligned", ""),
    "ITEM_SUNFLOWER": (None, "no_original",
                       "only the seed exists in the original table "
                       "(SunflowerSeed 61)"),
    "ITEM_LINEN_CAP": (115, "aligned", ""),
    "ITEM_LINEN_PANTS": (84, "aligned", ""),
    "ENTITY_DODO": (None, "entity",
                    "creature marker; the caged item is CagedDodo 303"),
    "ENTITY_DROP_ITEM": (None, "entity", "creature marker, not an item id"),
    "ENTITY_YAK": (None, "entity", "creature marker, not an item id"),
    "ENTITY_DROPBEAR": (None, "entity", "creature marker, not an item id"),
    "ITEM_SOFT_BED": (169, "aligned", ""),
    "ITEM_WOOD_SHELF": (161, "aligned_differs", "original name Shelf"),
    "ITEM_PORTAL": (134, "aligned", ""),
    "ITEM_TIME_CRYSTAL": (11, "aligned", ""),
    "BLOCK_TC_ORE": (None, "tile_only",
                     "TimeCrystal is a terrain type (VoxelType 16) that mines "
                     "into item TimeCrystal 11; no separate ore item"),
    "BLOCK_PLATFORM": (1057, "aligned_differs",
                       "tile-level match: platform terrain is "
                       "ReinforcedPlatform (ELF tile32 -> 1057)"),
    "BLOCK_STONE_WALL": (None, "no_original",
                         "no wall item; columns/stairs exist "
                         "(StoneColumn 222, StoneStairs 229)"),
    "ITEM_IRON_DOOR": (164, "aligned", ""),
    "ITEM_IRON_TRAPDOOR": (165, "aligned", ""),
    "ITEM_APPLE": (21, "aligned", ""),
    "ITEM_ORANGE": (60, "aligned", ""),
    "ITEM_CORN": (62, "aligned", ""),
    "ITEM_CARROT": (71, "aligned", ""),
    "ITEM_AMETHYST": (87, "aligned", ""),
    "ITEM_SAPPHIRE": (86, "aligned", ""),
    "ITEM_EMERALD": (76, "aligned", ""),
    "ITEM_RUBY": (75, "aligned", ""),
    "ITEM_DIAMOND": (88, "aligned", ""),
    "ITEM_BRONZE_PICKAXE": (43, "aligned", ""),
    "ITEM_BRONZE_AXE": (None, "no_original",
                        "no bronze axe; axes are FlintAxe 6, StoneAxe 33, "
                        "IronAxe 70"),
    "ITEM_BRONZE_SPADE": (None, "no_original",
                          "no bronze spade; spades are Flint 16, Tin 40, "
                          "Stone 64, Gold 89"),
    "ITEM_BRONZE_SWORD": (50, "aligned", ""),
    "ITEM_IRON_PICKAXE": (66, "aligned", ""),
    "ITEM_IRON_AXE": (70, "aligned", ""),
    "ITEM_IRON_SPADE": (None, "no_original",
                        "no iron spade in the original table"),
    "ITEM_IRON_SWORD": (68, "aligned", ""),
    "ITEM_GOLD_PICKAXE": (90, "aligned", ""),
    "ITEM_GOLD_AXE": (None, "no_original",
                      "no gold axe in the original table"),
    "ITEM_GOLD_SPADE": (89, "aligned", ""),
    "ITEM_GOLD_SWORD": (None, "no_original",
                        "no gold sword in the original table"),
    "ITEM_ELEVATOR_MOTOR": (1088, "aligned_differs",
                            "original name ElectricElevatorMotor"),
    "ITEM_ELEVATOR_SHAFT": (1087, "aligned", ""),
    "ITEM_ELECTRIC_FURNACE": (1079, "aligned", ""),
}

ID_LINE = re.compile(r'^(\s*\{ "id": (\d+), )(.*)$')


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def load_original_table() -> dict[int, dict[str, str]]:
    rows: dict[int, dict[str, str]] = {}
    lines = ORIGINAL_TABLE.read_text().splitlines()
    header = lines[0].split("\t")
    for line in lines[1:]:
        if not line.strip():
            continue
        row = dict(zip(header, line.split("\t")))
        rows[int(row["item_type"])] = row
    return rows


def main() -> int:
    original = load_original_table()
    lines = ITEMS_JSON.read_text().splitlines()

    seen: list[str] = []
    out_lines: list[str] = []
    alignment_rows: list[tuple] = []
    errors: list[str] = []

    for line in lines:
        match = ID_LINE.match(line)
        if not match:
            out_lines.append(line)
            continue
        rest = line[match.end(1):]
        payload = json.loads("{" + rest.rstrip().rstrip(","))
        string_id = payload["string_id"]
        seen.append(string_id)
        decision = ALIGNMENT.get(string_id)
        if decision is None:
            errors.append(f"no curated decision for {string_id}")
            decision = (None, "no_original", "")
        original_type, status, note = decision

        if original_type is None:
            entry, original_name, cell, evidence = "null", "", "", ""
            if status in ("aligned", "aligned_differs"):
                errors.append(f"{string_id}: mapped status without type")
        else:
            row = original.get(original_type)
            if row is None:
                errors.append(f"{string_id}: type {original_type} missing "
                              "from the original table")
                continue
            entry = str(original_type)
            original_name = row["name"]
            cell = f'{row["col_a0"]},{row["row_a0"]}'
            evidence = row["sources"]
            names_equal = normalize(payload["name"]) == normalize(original_name)
            if status == "aligned" and not names_equal:
                errors.append(f"{string_id}: aligned but names differ "
                              f"({payload['name']} vs {original_name})")
            if status == "aligned_differs" and names_equal:
                errors.append(f"{string_id}: marked differs but names match "
                              f"({payload['name']})")

        out_lines.append(
            f'{match.group(1)}"original_type": {entry}, {rest}')
        alignment_rows.append((
            match.group(2), string_id, payload["name"],
            entry, original_name, status, cell, evidence, note))

    if len(seen) != len(set(seen)):
        errors.append("duplicate string_id in items.json")
    missing = set(ALIGNMENT) - set(seen)
    if missing:
        errors.append(f"curated entries unused: {sorted(missing)}")
    if len(seen) != 87:
        errors.append(f"expected 87 rebuild items, got {len(seen)}")

    if errors:
        for error in errors:
            print(f"item-align: FAIL {error}")
        return 1

    ITEMS_JSON.write_text("\n".join(out_lines) + "\n")
    check = json.loads(ITEMS_JSON.read_text())
    assert all("original_type" in item for item in check)

    header = ["rebuild_id", "string_id", "rebuild_name", "original_type",
              "original_name", "status", "atlas_a0", "original_sources", "note"]
    tsv = ["\t".join(header)]
    for row in alignment_rows:
        tsv.append("\t".join(str(value) for value in row))
    ALIGNMENT_TSV.write_text("\n".join(tsv) + "\n")

    mapped = sum(1 for row in alignment_rows if row[3] != "null")
    print(f"item-align: {len(alignment_rows)} rebuild items, {mapped} mapped "
          f"to original types -> {ITEMS_JSON.relative_to(ROOT)}, "
          f"{ALIGNMENT_TSV.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
