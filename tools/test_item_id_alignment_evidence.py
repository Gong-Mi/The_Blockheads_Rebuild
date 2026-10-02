#!/usr/bin/env python3
"""Full-table consistency guard. This is NOT original-app semantic acceptance."""
import csv
import hashlib
import io
import json
from pathlib import Path

from align_rebuild_items import (ALIGNMENT, LEGACY_IDS, aligned_outputs,
                                 parse_items, validate_items)
from extract_original_item_types import FIELDS, build_table, render_tsv

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
# All 87 reviewed (symbol, compatibility id, original id/null) decisions.
# Any semantic change needs review, not merely another successful regeneration.
DECISIONS_SHA256 = '6a0aba5de3985aef205ff877b50c90546e4a47b7c0b56057cd6fc805b151afa3'


def parse_table(text):
    rows = list(csv.DictReader(io.StringIO(text), delimiter='\t'))
    result = {int(row['item_type']): row for row in rows}
    if len(result) != len(rows):
        raise ValueError('duplicate item_type in table')
    return result


def check_items_json(text, table):
    try:
        return validate_items(parse_items(text), table)
    except (ValueError, KeyError, TypeError) as error:
        return [str(error)]


def check_alignment(text, items_text, table):
    expected = aligned_outputs(items_text, table)[1]
    return [] if text == expected else ['alignment.tsv disagrees with the complete item decisions']


def main():
    decisions = sorted((name, LEGACY_IDS[name], decision[0]) for name, decision in ALIGNMENT.items())
    digest = hashlib.sha256(json.dumps(decisions, separators=(',', ':')).encode()).hexdigest()
    assert digest == DECISIONS_SHA256, 'reviewed numeric decisions changed'
    rows = build_table()  # checks hashes, domains and overlapping numeric sources
    text = render_tsv(FIELDS, rows)
    assert (NATIVE / 'original_item_types.tsv').read_text() == text, 'regenerate original item table'
    table = parse_table(text)
    assert len(table) == 426
    assert sum(bool(x['price']) for x in rows) == 266
    assert all(x['atlas_domain'] == 'TileMap:32x32' for x in rows)
    assert table[1024]['reference_name'] == 'Stone'
    assert table[1024]['server171_symbol'] == 'ITEM_COBBLESTONE'
    assert table[73]['server171_symbol'] == 'ITEM_GOLD_ORE'
    assert table[1057]['server171_symbol'] == 'ITEM_WOODEN_PLATFORM'
    assert table[1088]['tile_row_a0'] == '18'  # legal TileMap row, NOT an Items row
    items_text = (ROOT / 'assets/gamedata/items.json').read_text()
    errors = check_items_json(items_text, table)
    assert not errors, errors
    errors = check_alignment((NATIVE / 'item_id_alignment.tsv').read_text(), items_text, table)
    assert not errors, errors
    # Full mutation domain, not a handful of spot ids. Test a still-legal,
    # previously unused original value so range/uniqueness cannot catch it.
    items = parse_items(items_text)
    used = {x['original_type'] for x in items if x['original_type'] is not None}
    alternate = next(value for value in table if value not in used)
    for idx in range(len(items)):
        changed = [dict(x) for x in items]
        changed[idx]['original_type'] = alternate
        assert check_items_json(json.dumps(changed), table), items[idx]['string_id']
    print('item-id-alignment-evidence: PASS (87/87 mappings and mutations; '
          '426 provenance-separated rows; TileMap domain; no app-parity claim)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
