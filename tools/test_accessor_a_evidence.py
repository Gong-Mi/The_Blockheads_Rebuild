#!/usr/bin/env python3
"""Contract test for the DynamicWorld typed accessor family A (E36)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'ACCESSOR_A.md').read_text()
DATA = json.loads((NATIVE / 'accessor_a.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_placefireatposition_', 'wtl_objectoftype_atpos_', 'wtl_torchatpos_',
         'wtl_removetorchatpos_', 'wtl_eggatpos_', 'wtl_addeggatpos_savedict_',
         'wtl_removeeggatpos_', 'wtl_paintingwithid_', 'wtl_paintingatpos_',
         'wtl_removepaintingatpos_']

IMPS = ['0x008e80e4', '0x008e86b4', '0x008e888c', '0x008e8fe8', '0x008ea738',
        '0x008ea7a8', '0x008eaa28', '0x008eaadc', '0x008eabf8', '0x008eb00c']

COUNTS = {
    'wtl_placefireatposition_': (4, 1, 0, 1, 6, 6),
    'wtl_objectoftype_atpos_': (1, 1, 0, 2, 5, 4),
    'wtl_torchatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_removetorchatpos_': (2, 1, 0, 0, 2, 0),
    'wtl_eggatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_addeggatpos_savedict_': (5, 1, 1, 4, 9, 1),
    'wtl_removeeggatpos_': (2, 1, 0, 0, 2, 0),
    'wtl_paintingwithid_': (0, 0, 0, 2, 4, 4),
    'wtl_paintingatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_removepaintingatpos_': (2, 1, 0, 0, 2, 0),
}

WORDS = [143, 118, 28, 45, 28, 160, 45, 71, 28, 45]

FILES = ['disasm_worldtileloader_placefireatposition_.txt', 'disasm_worldtileloader_objectoftype_atpos_.txt',
         'disasm_worldtileloader_torchatpos_.txt', 'disasm_worldtileloader_removetorchatpos_.txt',
         'disasm_worldtileloader_eggatpos_.txt', 'disasm_worldtileloader_addeggatpos_savedict_.txt',
         'disasm_worldtileloader_removeeggatpos_.txt', 'disasm_worldtileloader_paintingwithid_.txt',
         'disasm_worldtileloader_paintingatpos_.txt', 'disasm_worldtileloader_removepaintingatpos_.txt']


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 711
    for needle in ('711', '0x11 (17)', '0x1e (30)', '0x34 (52)', '0x10 (16)',
                   'tileAtWorldPositionLoaded', 'tileIsPlant', '0x270', 'ffe234ac'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_type_codes():
    for name, t in (('wtl_torchatpos_', '0x11'), ('wtl_eggatpos_', '0x1e'), ('wtl_paintingatpos_', '0x34')):
        s = BY[name]['semantics']
        assert t in s, (name, t)
        assert 'ffe235f0' in s, name
    for name, cell in (('wtl_removetorchatpos_', 'ffe23564'),
                       ('wtl_removeeggatpos_', 'ffe23618'),
                       ('wtl_removepaintingatpos_', 'ffe23558')):
        s = BY[name]['semantics']
        assert 'ffe23600' in s and cell in s, name


def test_fire_and_resolvers():
    s = BY['wtl_placefireatposition_']['semantics']
    for needle in ('tileAtWorldPositionLoaded', 'tileIsPlant', '+0xb', '0x10'):
        assert needle in s, needle
    s = BY['wtl_paintingwithid_']['semantics']
    for needle in ('0x270', '__count_unique', 'ffffe54c', 'ffffe550'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_type_codes()
    test_fire_and_resolvers()
    print('test_accessor_a_evidence: OK')
