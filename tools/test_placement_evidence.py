#!/usr/bin/env python3
"""Contract test for the DynamicWorld placement-actions cluster (E30)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'PLACEMENT.md').read_text()
DATA = json.loads((NATIVE / 'placement.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_sowtreeorplantatpositi', 'wtl_workbenchplacedatposit', 'wtl_dynamicworldchangedatp',
         'wtl_createbackgroundconten', 'wtl_addrailatpos_oftype_ow', 'wtl_addstandardobjectatpos',
         'wtl_addpaintingatpos_oftyp', 'wtl_poleitemtaken_']

IMPS = ['0x008e49c8', '0x008e7608', '0x008e1390', '0x008df3c4', '0x008ecea4', '0x008eb0c0',
        '0x008eac68', '0x0090365c']

COUNTS = {
    'wtl_sowtreeorplantatpositi': (2, 0, 0, 0, 5, 2),
    'wtl_workbenchplacedatposit': (8, 1, 1, 6, 15, 7),
    'wtl_dynamicworldchangedatp': (1, 0, 0, 1, 6, 15),
    'wtl_createbackgroundconten': (5, 0, 0, 0, 10, 12),
    'wtl_addrailatpos_oftype_ow': (7, 1, 1, 4, 13, 5),
    'wtl_addstandardobjectatpos': (6, 1, 0, 4, 13, 5),
    'wtl_addpaintingatpos_oftyp': (6, 1, 1, 4, 12, 5),
    'wtl_poleitemtaken_': (7, 3, 3, 3, 11, 9),
}

WORDS = [89, 278, 263, 248, 236, 234, 233, 227]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1808
    for needle in ('1808', 'treeTypeForSeedItemType', 'plantTypeForSeedItemType', '0x47c34f80',
                   'classForDynamicObjectType', 'ffffe578', '0xaa', '0xfff34284', 'ffffe558'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_sow_and_workbench():
    s = BY['wtl_sowtreeorplantatpositi']['semantics']
    for needle in ('treeTypeForSeedItemType', 'plantTypeForSeedItemType', 'ffe23414', 'ffe233f8'):
        assert needle in s, needle
    s = BY['wtl_workbenchplacedatposit']['semantics']
    for needle in ('ffffe550', 'worldIndexAtWorldPos', 'ffffe554', 'ffffe558'):
        assert needle in s, needle


def test_recorder_and_adders():
    s = BY['wtl_dynamicworldchangedatp']['semantics']
    for needle in ('0x16', '0x1d', 'makeIntpair', 'ffffe578', 'movw r1, 0xc'):
        assert needle in s, needle
    for name, cells in (('wtl_addrailatpos_oftype_ow', ('+ 0x1e0', 'ffe2af88', 'ffe23644')),
                        ('wtl_addstandardobjectatpos', ('classForDynamicObjectType', 'ffe23620')),
                        ('wtl_addpaintingatpos_oftyp', ('+ 0x270', 'ffe2af84', 'ffe2361c'))):
        s = BY[name]['semantics']
        for needle in cells:
            assert needle in s, needle
        for needle in ('__count_unique', 'ffffe550'):
            assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_sow_and_workbench()
    test_recorder_and_adders()
    print('test_placement_evidence: OK')
