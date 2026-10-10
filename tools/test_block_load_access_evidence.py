#!/usr/bin/env python3
"""Contract test for the DynamicWorld block-load/accessor smalls (E35)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BLOCK_LOAD_ACCESS.md').read_text()
DATA = json.loads((NATIVE / 'block_load_access.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_removeobjectduetorepai', 'wtl_clientblockheadsreciev', 'wtl_portalisbeingremovedat',
         'wtl_loadedcountofobjectsof', 'wtl_loadgatherblockatpos_', 'wtl_isclient',
         'wtl_netblockheads', 'wtl_gatherblockatpos_', 'wtl_isserver', 'wtl_allblockheadsincluding',
         'wtl_portalpositions', 'wtl_blockheads', 'wtl_connectiontoserverlost']

IMPS = ['0x00905b2c', '0x008fb168', '0x00902f3c', '0x00903594', '0x008f5530', '0x008f64c0',
        '0x008f676c', '0x008f55e8', '0x008f6514', '0x008f6698', '0x008fdeac', '0x00902f00',
        '0x008f956c']

COUNTS = {
    'wtl_removeobjectduetorepai': (9, 1, 0, 1, 12, 8),
    'wtl_clientblockheadsreciev': (3, 2, 1, 1, 4, 1),
    'wtl_portalisbeingremovedat': (1, 1, 0, 2, 2, 0),
    'wtl_loadedcountofobjectsof': (0, 0, 0, 2, 0, 0),
    'wtl_loadgatherblockatpos_': (1, 0, 0, 1, 1, 2),
    'wtl_isclient': (0, 0, 0, 2, 0, 0),
    'wtl_netblockheads': (1, 1, 0, 2, 1, 0),
    'wtl_gatherblockatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_isserver': (0, 0, 0, 1, 0, 0),
    'wtl_allblockheadsincluding': (1, 1, 0, 3, 2, 0),
    'wtl_portalpositions': (0, 0, 0, 1, 0, 0),
    'wtl_blockheads': (0, 0, 0, 1, 0, 0),
    'wtl_connectiontoserverlost': (0, 0, 0, 0, 0, 0),
}

WORDS = [169, 72, 54, 50, 46, 42, 35, 28, 21, 53, 15, 15, 5]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 605
    for needle in ('605', 'objectTypeIsInteractionObject', '0x8b1db0', '0x1a', 'ffffe518',
                   'ffffe51c', 'ffffe4f8', 'ffffe4e8'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_booleans_and_getters():
    s = BY['wtl_isclient']['semantics']
    assert 'ffffe518' in s and 'movne' in s
    s = BY['wtl_isserver']['semantics']
    assert 'ffffe51c' in s and 'movne' in s
    s = BY['wtl_blockheads']['semantics']
    assert 'ffffe4f8' in s
    s = BY['wtl_portalpositions']['semantics']
    assert 'ffffe4e8' in s


def test_removal_and_recv():
    s = BY['wtl_removeobjectduetorepai']['semantics']
    for needle in ('objectTypeIsInteractionObject', 'ffe23690', 'ffe237e0', 'ffe23600'):
        assert needle in s, needle
    s = BY['wtl_clientblockheadsreciev']['semantics']
    for needle in ('0x8b1db0', 'ffffe50c', '0xfff33df4'):
        assert needle in s, needle
    s = BY['wtl_gatherblockatpos_']['semantics']
    assert '0x1a (26)' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_booleans_and_getters()
    test_removal_and_recv()
    print('test_block_load_access_evidence: OK')
