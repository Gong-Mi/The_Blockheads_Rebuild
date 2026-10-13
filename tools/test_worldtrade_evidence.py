#!/usr/bin/env python3
"""Contract test for the World trade prices and IAP line (E108)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_TRADE.md').read_text()
DATA = json.loads((NATIVE / 'world_trade.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wt_00', 'wt_01', 'wt_02', 'wt_03', 'wt_04', 'wt_05', 'wt_06', 'wt_07', 'wt_08', 'wt_09']
IMPS = ['0x005cbc30', '0x005cd6a8', '0x005ce260', '0x005c44a0', '0x005ceb18', '0x005c4228', '0x005d32ac', '0x005c2858', '0x005da150', '0x005da10c']
COUNTS = {'wt_00': (19, 8, 11, 6, 34, 19), 'wt_01': (10, 2, 2, 5, 18, 9), 'wt_02': (13, 2, 3, 3, 20, 10), 'wt_03': (6, 1, 0, 2, 10, 9), 'wt_04': (4, 1, 0, 1, 8, 7), 'wt_05': (6, 3, 2, 2, 7, 1), 'wt_06': (2, 1, 0, 1, 2, 0), 'wt_07': (2, 1, 0, 0, 2, 0), 'wt_08': (0, 0, 0, 1, 0, 0), 'wt_09': (0, 0, 0, 1, 0, 0)}
WORDS = [707, 453, 430, 198, 165, 158, 39, 35, 17, 17]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2219
    for needle in ('2219', '707', '453', 'NSPropertyListSerialization',
                   'timeIntervalSinceReferenceDate', 'unsentGlobalTradeTransactions',
                   'gzipDeflate', 'storeUsername', 'checkIfCanWarpInSecondBlockhead',
                   '0x55468c'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_trade():
    s = BY['wt_00']['semantics']
    assert 'NSPropertyListSerialization' in s
    s = BY['wt_01']['semantics']
    assert 'pow()' in s
    s = BY['wt_02']['semantics']
    assert 'sendNetworkData' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.unsentGlobalTradeTransactions' in symbols
    sels = {v.get('selector') for e in DATA['classes'] for v in e['selectors'].values()}
    assert 'checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB:' in sels


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_trade()
    print('test_worldtrade_evidence: OK')
