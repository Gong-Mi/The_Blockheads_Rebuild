#!/usr/bin/env python3
"""Contract test for the World lifecycle and cloud/prices IO batch (E106)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_LOAD.md').read_text()
DATA = json.loads((NATIVE / 'world_load.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wl_00', 'wl_01', 'wl_02', 'wl_03', 'wl_04', 'wl_05', 'wl_06', 'wl_07', 'wl_08', 'wl_09', 'wl_10', 'wl_11', 'wl_12']
IMPS = ['0x00563604', '0x005b59f8', '0x005ccc88', '0x005cc994', '0x005cc864', '0x005cc73c', '0x005d0d2c', '0x005d3158', '0x005c6ef8', '0x005d9ca4', '0x005d8d3c', '0x005d8da4', '0x005d97c0']
COUNTS = {'wl_00': (26, 18, 14, 34, 66, 36), 'wl_01': (1, 1, 0, 3, 1, 0), 'wl_02': (16, 5, 3, 7, 23, 18), 'wl_03': (3, 3, 0, 4, 10, 4), 'wl_04': (1, 1, 0, 4, 2, 4), 'wl_05': (1, 1, 0, 4, 2, 4), 'wl_06': (1, 1, 0, 2, 2, 5), 'wl_07': (2, 1, 0, 3, 2, 0), 'wl_08': (1, 0, 1, 3, 12, 29), 'wl_09': (0, 0, 0, 1, 0, 0), 'wl_10': (1, 1, 0, 1, 1, 0), 'wl_11': (2, 1, 0, 2, 2, 0), 'wl_12': (1, 1, 0, 0, 1, 0)}
WORDS = [1428, 87, 540, 189, 76, 74, 74, 60, 627, 15, 26, 45, 25]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 3266
    for needle in ('3266', '1428', '540', '627', 'SFHFKeychainUtils',
                   'getPasswordForUsername', 'globalPrices', 'updateTradePricesIfNeeded',
                   'checkIfMacroTileCanBeDecommissioned', 'startBulkTransaction'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_load():
    s = BY['wl_00']['semantics']
    assert 'SFHFKeychainUtils' in s
    assert 'saveQueue' in s
    s = BY['wl_02']['semantics']
    assert 'globalPrices' in s
    assert '_NSConcreteStackBlock' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.incrementalLoadCount' in symbols
    sels = {v.get('selector') for e in DATA['classes'] for v in e['selectors'].values()}
    assert 'startBulkTransaction' in sels


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_load()
    print('test_worldload_evidence: OK')
