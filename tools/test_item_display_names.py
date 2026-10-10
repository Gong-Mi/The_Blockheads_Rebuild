#!/usr/bin/env python3
"""Contract test for the item display-name recovery (E142)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'ITEM_DISPLAY_NAMES.md').read_text(encoding='utf-8')
DATA = json.loads((NATIVE / 'item_display_names.json').read_text(encoding='utf-8'))
BY = {row['item_type']: row for row in DATA['items']}


def test_shape():
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert DATA['item_type_count'] == 425
    assert len(DATA['items']) == 425
    assert DATA['tables'][0]['entries'] == 343
    assert DATA['tables'][1]['entries'] == 82
    assert DATA['unknown_count'] == 29
    assert DATA['function_address'] == '0x004db268'
    assert DATA['tail'] == '0x004ddb9c'
    assert DATA['default_stub']['name'] == 'UNKNOWN'
    ids = [row['item_type'] for row in DATA['items']]
    assert ids == list(range(1, 344)) + list(range(1024, 1106))


def test_spot_rows():
    expect = {
        1: 'CLOTHING', 3: 'FLINT', 4: 'STICK', 6: 'FLINT AXE',
        9: 'DOUBLE-TIME', 11: 'TIME CRYSTAL', 17: 'BASIC TORCH',
        19: 'BLOCKHEAD', 21: 'APPLE', 336: 'EMERALD COLUMN',
        343: 'DIAMOND STAIRS', 1024: 'STONE', 1105: 'LUMINOUS PLASTER',
        2: 'UNKNOWN',
    }
    for item_type, name in expect.items():
        assert BY[item_type]['name'] == name, (item_type, BY[item_type]['name'])
    unknown = sorted(r['item_type'] for r in DATA['items'] if r['name'] == 'UNKNOWN')
    assert unknown == DATA['unknown_ids']
    assert len(unknown) == 29
    assert 298 in unknown and 1092 in unknown


def test_doc_needles():
    for needle in ('0x004db268', '0x004db2bc', '0x004db840', '0x004ddb8c',
                   '0x004ddb9c', 'UNKNOWN', '425', 'nameForItemType'):
        assert needle in DOC, needle


if __name__ == '__main__':
    test_shape()
    test_spot_rows()
    test_doc_needles()
    print('test_item_display_names: OK')
