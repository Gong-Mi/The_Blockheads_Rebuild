#!/usr/bin/env python3
"""Contract test for the World ownership-signs line (E111)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_OWN.md').read_text()
DATA = json.loads((NATIVE / 'world_own.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wo_00', 'wo_01', 'wo_02', 'wo_03', 'wo_04', 'wo_05', 'wo_06']
IMPS = ['0x005d35cc', '0x005d4144', '0x005d3e08', '0x005d53b0', '0x005d3538', '0x005daa14', '0x005c88b0']
COUNTS = {'wo_00': (15, 7, 4, 2, 28, 16), 'wo_01': (9, 7, 3, 3, 18, 6), 'wo_02': (4, 7, 0, 0, 14, 2), 'wo_03': (4, 1, 1, 3, 4, 2), 'wo_04': (2, 1, 0, 1, 2, 0), 'wo_05': (0, 0, 0, 0, 0, 0), 'wo_06': (4, 1, 0, 3, 10, 18)}
WORDS = [527, 373, 207, 97, 37, 15, 286]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1542
    for needle in ('1542', '527', '373', 'ownershipSignPositions', 'OwnershipAreaRenderer',
                   'signOwnershipUI', 'loadLightBlockForClientLightBlockIndex',
                   'sendNetworkData:toPeers:reliable:', '0x55468c', 'macroPosForWorldPos'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_own():
    s = BY['wo_01']['semantics']
    assert 'sendNetworkData' in s
    s = BY['wo_03']['semantics']
    assert 'OwnershipAreaRenderer' in s
    s = BY['wo_06']['semantics']
    assert 'loadLightBlockForClientLightBlockIndex' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.ownershipSignPositions' in symbols
    assert 'OBJC_IVAR_$_World.ownershipAreaRenderer' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_own()
    print('test_worldown_evidence: OK')
