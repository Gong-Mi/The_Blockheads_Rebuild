#!/usr/bin/env python3
"""Contract test for the DynamicWorld object query & lifecycle cluster (E24).

Pins the JSON artifact and the prose doc to the recovered semantics of the nine
bodies: the teardown, the removal receiver, the repair pass, the occupant
queries, the interaction probe lattice, the disconnect cleanup and the two
free-block factories.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'OBJECT_LIFE.md').read_text()
DATA = json.loads((NATIVE / 'object_life.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['dyn_dealloc', 'wtl_remoteremove_forobject', 'wtl_dorepairfortileatpos_',
         'wtl_blockheadatpos_', 'wtl_blockheadoccupiestilea', 'wtl_interactionobjectatpos',
         'wtl_clientdisconnected_sim', 'dyn_freeblock_fg', 'dyn_freeblock_full']

IMPS = ['0x008ad320', '0x008c420c', '0x00905dd0', '0x008f45a4', '0x008f3b80', '0x008f0550',
        '0x008f85a0', '0x008de880', '0x008ddc78']

COUNTS = {
    'dyn_dealloc': (6, 3, 1, 18, 41, 30),
    'wtl_remoteremove_forobject': (16, 1, 1, 4, 31, 47),
    'wtl_dorepairfortileatpos_': (7, 1, 0, 4, 25, 32),
    'wtl_blockheadoccupiestilea': (3, 1, 0, 3, 33, 54),
    'wtl_blockheadatpos_': (3, 1, 0, 3, 33, 51),
    'wtl_interactionobjectatpos': (5, 1, 0, 1, 36, 52),
    'wtl_clientdisconnected_sim': (17, 1, 1, 5, 28, 27),
    'dyn_freeblock_fg': (15, 1, 0, 1, 28, 30),
    'dyn_freeblock_full': (13, 5, 2, 7, 32, 18),
}

WORDS = [1116, 602, 644, 633, 649, 702, 651, 481, 630]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 6108
    for needle in ('6108', '0x00E4AA0C', '0x00E4AA90', 'blockheadWillBeUnloaded:',
                   'getBytes:length:8', 'objectTypeHasStaticPosition', 'itemTypeFromTileIsForegorund',
                   'tileIsWorkbench', 'vcvt.f32.f64', '0xfff34094', '__tree insert_unique',
                   'ffffe588'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_dealloc_and_remove():
    s = BY['dyn_dealloc']['semantics']
    for needle in ('ffffe4f8', 'ffffe4f4', 'ffffe4f0', 'blockheadWillBeUnloaded:', '0x00E4AA0C',
                   'clear()', '0x41 (65)'):
        assert needle in s, needle
    s = BY['wtl_remoteremove_forobject']['semantics']
    for needle in ('ffe23430', 'objectTypeIsNPC', 'getBytes:length:8', 'ffffe4f4', 'ffe2332c',
                   '__count_unique', '0x130'):
        assert needle in s, needle


def test_repair_and_queries():
    s = BY['wtl_dorepairfortileatpos_']['semantics']
    for needle in ('ffffe51c', 'ffe23410', '0x41 (65)', 'objectTypeHasStaticPosition',
                   'worldWidthMacro', 'ffe237f0'):
        assert needle in s, needle
    for name in ('wtl_blockheadoccupiestilea', 'wtl_blockheadatpos_'):
        s = BY[name]['semantics']
        for needle in ('ffffe4f8', 'ffffe4f4', 'ffffe4f0', 'ffe236b8', 'pos.y - 1'):
            assert needle in s, needle


def test_probe_and_disconnect():
    s = BY['wtl_interactionobjectatpos']['semantics']
    for needle in ('ffe235f0', 'ffe23680', 'ffe23684', '0x2f', '0x3c', '0x31', '0x32',
                   '0x00E4AA90'):
        assert needle in s, needle
    s = BY['wtl_clientdisconnected_sim']['semantics']
    for needle in ('ffffe4f4', '0x00E4AA90', 'ffffe54c', 'ffe236f0', 'ffffe5ac',
                   'ffe232f4', 'ffe232fc', 'ffffe4f0'):
        assert needle in s, needle


def test_freeblock_factories():
    s = BY['dyn_freeblock_fg']['semantics']
    for needle in ('itemTypeFromTileIsForegorund', 'itemTypeIsPainting', 'itemTypeIsColumn',
                   'itemTypeIsStairs', 'itemTypeIsTorch', '0xb2', 'ffe23410', 'tileIsWorkbench',
                   '0x8df004', '0x30'):
        assert needle in s, needle
    s = BY['dyn_freeblock_full']['semantics']
    for needle in ('0xb', 'ffffe518', 'vcvt.f32.f64', '0xfff34094', '0xfff340a4', '0xfff340b4',
                   'ffffe5a4', 'uniqueID', 'worldIndexAtWorldPos', 'ffffe588', '__insert_unique'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_dealloc_and_remove()
    test_repair_and_queries()
    test_probe_and_disconnect()
    test_freeblock_factories()
    print('test_object_life_evidence: OK')
