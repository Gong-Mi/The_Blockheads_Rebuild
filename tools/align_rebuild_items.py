#!/usr/bin/env python3
"""Generate explicit rebuild/original ItemType decisions, not implicit renumbering.

aligned/aligned_differs describe agreement with THIRD-PARTY reference labels,
not original developer names. server171_symbol is a separate versioned DWARF
column. tile_only/no_original are conservative unmapped decisions pending
client evidence; they are not proof of absence. entity is a non-item marker.
Neither TileType nor GUI VoxelType is an inventory ItemType.
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
    "ITEM_EMPTY": (0, "placeholder", "empty compatibility sentinel, not a transferable inventory item"),
    "ITEM_DIRT": (1048, "aligned", ""),
    "ITEM_STONE": (1024, "aligned", ""),
    "BLOCK_WOOD": (1049, "aligned", ""),
    "BLOCK_LEAVES": (None, "tile_only",
                     "unmapped terrain/content; original Tile byte3 uses species-specific values"),
    "BLOCK_GRASS": (None, "tile_only",
                    "unmapped terrain; original TileType27 is not an inventory id"),
    "BLOCK_SAND": (1051, "aligned", ""),
    "ITEM_COPPER_ORE": (31, "aligned", ""),
    "ITEM_TIN_ORE": (36, "aligned", ""),
    "ITEM_GOLD_ORE": (73, "aligned_differs",
                      "reference alias GoldNugget; server171 symbol ITEM_GOLD_ORE"),
    "BLOCK_SNOW": (None, "tile_only",
                   "unmapped terrain; no same-name inventory entry in the reference"),
    "ITEM_WORKBENCH": (1050, "aligned", "reference spelling WorkBench"),
    "ITEM_TOOLBENCH": (1052, "aligned", "reference spelling ToolBench"),
    "BLOCK_ICE": (1060, "aligned", ""),
    "BLOCK_CACTUS": (None, "tile_only",
                     "unmapped content; client Tile byte3 Cactus/DeadCactus=43/44; not GUI Voxel115/116"),
    "BLOCK_GLASS": (1042, "aligned", ""),
    "ITEM_CRAFTBENCH": (1055, "aligned", "reference spelling CraftBench"),
    "ITEM_FURNACE": (1031, "aligned", ""),
    "ITEM_IRON_ORE": (32, "aligned", ""),
    "ITEM_CHEST": (1043, "aligned", ""),
    "ITEM_TORCH": (17, "aligned", ""),
    "ITEM_FLINT": (3, "aligned", ""),
    "ITEM_STICK": (4, "aligned", ""),
    "ITEM_CAMPFIRE": (15, "aligned", ""),
    "ITEM_CHILI": (112, "aligned_differs", "reference name Chilli"),
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
                            "no coal generator in the pinned reference table "
                            "(power sources: SteamGenerator 1077, "
                            "SolarPanel 1082, Flywheel 1083)"),
    "ITEM_ELECTRIC_LAMP": (None, "no_original",
                           "no electric lamp in the pinned reference table "
                           "(lamps: OilLantern 47, SteelLantern 150, "
                           "IceTorch 183)"),
    "ITEM_WOOD_DOOR": (52, "aligned_differs", "reference name Door"),
    "ITEM_WOOD_TRAPDOOR": (69, "aligned", ""),
    "ITEM_LADDER": (53, "aligned", ""),
    "ITEM_FLAX_SEED": (54, "aligned", ""),
    "ITEM_FLAX": (55, "aligned", ""),
    "ITEM_SUNFLOWER_SEED": (61, "aligned", ""),
    "ITEM_SUNFLOWER": (None, "no_original",
                       "only the seed exists in the pinned reference table "
                       "(SunflowerSeed 61)"),
    "ITEM_LINEN_CAP": (115, "aligned", ""),
    "ITEM_LINEN_PANTS": (84, "aligned", ""),
    "ENTITY_DODO": (None, "entity",
                    "creature marker; the caged item is CagedDodo 303"),
    "ENTITY_DROP_ITEM": (None, "entity", "creature marker, not an item id"),
    "ENTITY_YAK": (None, "entity", "creature marker, not an item id"),
    "ENTITY_DROPBEAR": (None, "entity", "creature marker, not an item id"),
    "ITEM_SOFT_BED": (169, "aligned", ""),
    "ITEM_WOOD_SHELF": (161, "aligned_differs", "reference name Shelf"),
    "ITEM_PORTAL": (134, "aligned", ""),
    "ITEM_TIME_CRYSTAL": (11, "aligned", ""),
    "BLOCK_TC_ORE": (None, "tile_only",
                     "unmapped terrain TileType16; direct client tile conversion returns item11"),
    "BLOCK_PLATFORM": (1057, "aligned_differs",
                       "reference alias ReinforcedPlatform; server171 ITEM_WOODEN_PLATFORM; client tile32 -> 1057"),
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
                        "no iron spade in the pinned reference table"),
    "ITEM_IRON_SWORD": (68, "aligned", ""),
    "ITEM_GOLD_PICKAXE": (90, "aligned", ""),
    "ITEM_GOLD_AXE": (None, "no_original",
                      "no gold axe in the pinned reference table"),
    "ITEM_GOLD_SPADE": (89, "aligned", ""),
    "ITEM_GOLD_SWORD": (None, "no_original",
                        "no gold sword in the pinned reference table"),
    "ITEM_ELEVATOR_MOTOR": (1088, "aligned_differs",
                            "reference name ElectricElevatorMotor"),
    "ITEM_ELEVATOR_SHAFT": (1087, "aligned", ""),
    "ITEM_ELECTRIC_FURNACE": (1079, "aligned", ""),
}

# Frozen compatibility ids: changing these requires an explicit world.bin migration.
LEGACY_IDS = {
    "ITEM_EMPTY": 0,
    "ITEM_DIRT": 1,
    "ITEM_STONE": 2,
    "BLOCK_WOOD": 3,
    "BLOCK_LEAVES": 4,
    "BLOCK_GRASS": 5,
    "BLOCK_SAND": 6,
    "ITEM_COPPER_ORE": 7,
    "ITEM_TIN_ORE": 8,
    "ITEM_GOLD_ORE": 9,
    "BLOCK_SNOW": 10,
    "ITEM_WORKBENCH": 11,
    "ITEM_TOOLBENCH": 12,
    "BLOCK_ICE": 13,
    "BLOCK_CACTUS": 14,
    "BLOCK_GLASS": 15,
    "ITEM_CRAFTBENCH": 16,
    "ITEM_FURNACE": 17,
    "ITEM_IRON_ORE": 18,
    "ITEM_CHEST": 19,
    "ITEM_TORCH": 20,
    "ITEM_FLINT": 21,
    "ITEM_STICK": 22,
    "ITEM_CAMPFIRE": 23,
    "ITEM_CHILI": 30,
    "ITEM_DODO_MEAT": 31,
    "ITEM_COCONUT": 32,
    "ITEM_FUR": 33,
    "ITEM_COPPER_INGOT": 40,
    "ITEM_TIN_INGOT": 41,
    "ITEM_IRON_INGOT": 42,
    "ITEM_STEEL_INGOT": 43,
    "ITEM_BRONZE_INGOT": 44,
    "ITEM_GOLD_INGOT": 45,
    "ITEM_PICKAXE": 50,
    "ITEM_AXE": 51,
    "ITEM_SPADE": 52,
    "ITEM_COAL": 70,
    "ITEM_COPPER_WIRE": 71,
    "ITEM_COAL_GENERATOR": 72,
    "ITEM_ELECTRIC_LAMP": 73,
    "ITEM_WOOD_DOOR": 80,
    "ITEM_WOOD_TRAPDOOR": 81,
    "ITEM_LADDER": 82,
    "ITEM_FLAX_SEED": 90,
    "ITEM_FLAX": 91,
    "ITEM_SUNFLOWER_SEED": 92,
    "ITEM_SUNFLOWER": 93,
    "ITEM_LINEN_CAP": 97,
    "ITEM_LINEN_PANTS": 98,
    "ENTITY_DODO": 100,
    "ENTITY_DROP_ITEM": 101,
    "ENTITY_YAK": 102,
    "ENTITY_DROPBEAR": 103,
    "ITEM_SOFT_BED": 110,
    "ITEM_WOOD_SHELF": 111,
    "ITEM_PORTAL": 150,
    "ITEM_TIME_CRYSTAL": 151,
    "BLOCK_TC_ORE": 152,
    "BLOCK_PLATFORM": 200,
    "BLOCK_STONE_WALL": 201,
    "ITEM_IRON_DOOR": 205,
    "ITEM_IRON_TRAPDOOR": 206,
    "ITEM_APPLE": 210,
    "ITEM_ORANGE": 211,
    "ITEM_CORN": 214,
    "ITEM_CARROT": 215,
    "ITEM_AMETHYST": 220,
    "ITEM_SAPPHIRE": 221,
    "ITEM_EMERALD": 222,
    "ITEM_RUBY": 223,
    "ITEM_DIAMOND": 224,
    "ITEM_BRONZE_PICKAXE": 230,
    "ITEM_BRONZE_AXE": 231,
    "ITEM_BRONZE_SPADE": 232,
    "ITEM_BRONZE_SWORD": 233,
    "ITEM_IRON_PICKAXE": 240,
    "ITEM_IRON_AXE": 241,
    "ITEM_IRON_SPADE": 242,
    "ITEM_IRON_SWORD": 243,
    "ITEM_GOLD_PICKAXE": 260,
    "ITEM_GOLD_AXE": 261,
    "ITEM_GOLD_SPADE": 262,
    "ITEM_GOLD_SWORD": 263,
    "ITEM_ELEVATOR_MOTOR": 270,
    "ITEM_ELEVATOR_SHAFT": 271,
    "ITEM_ELECTRIC_FURNACE": 272
}

def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse_items(text):
    items = json.loads(text, object_pairs_hook=unique_keys)
    if not isinstance(items, list) or len(items) != len(ALIGNMENT):
        raise ValueError('expected the complete rebuild item list')
    names, ids = set(), set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('item must be an object')
        name, value = item.get('string_id'), item.get('id')
        if not isinstance(name, str) or name not in ALIGNMENT or name in names:
            raise ValueError(f'unknown/duplicate string_id: {name}')
        if type(value) is not int or value != LEGACY_IDS[name] or value in ids:
            raise ValueError(f'changed/duplicate compatibility id: {name}')
        names.add(name)
        ids.add(value)
    if names != ALIGNMENT.keys():
        raise ValueError('missing rebuild entries')
    return items


def normalize(name):
    return re.sub(r'[^a-z0-9]', '', name.lower())


def load_original_table():
    from extract_original_item_types import build_table
    return {int(row['item_type']): row for row in build_table()}


def validate_items(items, original):
    errors, mapped = [], []
    for item in items:
        name = item['string_id']
        expected = ALIGNMENT[name][0]
        if 'original_type' not in item or item['original_type'] != expected:
            errors.append(f'{name}: original_type must be {expected}')
        value = item.get('original_type')
        if value is not None:
            if type(value) is not int or value not in original:
                errors.append(f'{name}: invalid original_type')
            else:
                mapped.append(value)
    if len(mapped) != len(set(mapped)):
        errors.append('duplicate original_type mapping')
    return errors


def aligned_outputs(text, original):
    from extract_original_item_types import render_tsv
    items = parse_items(text)
    output, rows = [], []
    for item in sorted(items, key=lambda x: x['id']):
        name = item['string_id']
        value, status, note = ALIGNMENT[name]
        reference = original[value] if value is not None else None
        if reference is not None and status in ('aligned', 'aligned_differs'):
            equal = normalize(item['name']) == normalize(reference['reference_name'])
            if equal != (status == 'aligned'):
                raise ValueError(f'{name}: reference-name classification drift')
        updated = dict(id=item['id'], original_type=value)
        updated.update({k: v for k, v in item.items() if k not in updated})
        output.append(updated)
        rows.append(dict(rebuild_id=item['id'], string_id=name, rebuild_name=item['name'],
                         original_type=str(value) if value is not None else 'null',
                         reference_name=reference['reference_name'] if reference else '',
                         server171_symbol=reference['server171_symbol'] if reference else '',
                         status=status,
                         tilemap_cell_a0=(reference['tile_col_a0'] + ',' + reference['tile_row_a0']) if reference else '',
                         sources=reference['sources'] if reference else '', note=note or '-'))
    errors = validate_items(output, original)
    if errors:
        raise ValueError('; '.join(errors))
    # One object per line, deterministic regardless of incoming JSON formatting.
    json_text = '[\n' + ',\n'.join('  { ' + json.dumps(x, ensure_ascii=False)[1:-1] + ' }' for x in output) + '\n]\n'
    fields = ['rebuild_id', 'string_id', 'rebuild_name', 'original_type',
              'reference_name', 'server171_symbol', 'status', 'tilemap_cell_a0', 'sources', 'note']
    return json_text, render_tsv(fields, rows)


def main(check=False):
    try:
        text, table = aligned_outputs(ITEMS_JSON.read_text(), load_original_table())
        if check:
            if ITEMS_JSON.read_text() != text or ALIGNMENT_TSV.read_text() != table:
                raise ValueError('alignment outputs differ; regenerate after reviewing decisions')
        else:
            # Everything, including duplicate-key validation, completed before either write.
            ITEMS_JSON.write_text(text)
            ALIGNMENT_TSV.write_text(table)
    except (ValueError, KeyError, OSError) as error:
        print('item-align: FAIL', error)
        return 1
    print('item-align: PASS (all rebuild decisions; stable compatibility ids; no runtime renumbering)')
    return 0


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    raise SystemExit(main(parser.parse_args().check))
