#!/usr/bin/env python3
"""Contract test for the World craft-interaction chain (E105)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_CRAFT.md').read_text()
DATA = json.loads((NATIVE / 'world_craft.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cb_00', 'cb_01', 'cb_02', 'cb_03', 'cb_04', 'cb_05', 'cb_06', 'cb_07', 'cb_08', 'cb_09']
IMPS = ['0x005bbdd0', '0x005b6fa8', '0x005b88f8', '0x005b83d0', '0x005b82b0', '0x005bb634', '0x005b9368', '0x005bd68c', '0x005bdb14', '0x005b90c0']
COUNTS = {'cb_00': (37, 14, 6, 6, 91, 65), 'cb_01': (28, 12, 2, 7, 61, 64), 'cb_02': (10, 1, 0, 2, 33, 29), 'cb_03': (9, 1, 0, 4, 20, 11), 'cb_04': (3, 1, 0, 2, 3, 2), 'cb_05': (14, 4, 2, 2, 31, 12), 'cb_06': (10, 1, 5, 2, 43, 27), 'cb_07': (7, 1, 5, 2, 16, 15), 'cb_08': (7, 2, 1, 2, 9, 4), 'cb_09': (9, 2, 0, 2, 9, 7)}
WORDS = [1583, 1218, 461, 330, 72, 487, 682, 290, 151, 170]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5444
    for needle in ('5444', '1583', '1218', '0xc350', 'CrystalManager',
                   'requestUniqueIDFromServerWithDict', 'showUIForTappedWorkbench',
                   'craftProgressUI', 'queueActionWithGoalPos', 'itemTypeCanBeColored'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_craft():
    s = BY['cb_00']['semantics']
    assert '0xc350' in s
    assert 'requestUniqueIDFromServerWithDict' in s
    s = BY['cb_06']['semantics']
    assert 'showUIForTappedWorkbench' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.unableToCraftBlockheadDueToWaitingForServer' in symbols
    sels = {v.get('selector') for e in DATA['classes'] for v in e['selectors'].values()}
    assert 'upgradeToNextLevel' in sels


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_craft()
    print('test_worldcraft_evidence: OK')
