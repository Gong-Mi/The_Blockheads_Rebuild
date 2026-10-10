#!/usr/bin/env python3
"""Contract test for the World store/repair/idle line (E110)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_UI.md').read_text()
DATA = json.loads((NATIVE / 'world_ui.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wu_00', 'wu_01', 'wu_02', 'wu_03', 'wu_04', 'wu_05', 'wu_06', 'wu_07', 'wu_08', 'wu_09', 'wu_10', 'wu_11', 'wu_12', 'wu_13']
IMPS = ['0x005b5b54', '0x005d8f78', '0x005d4718', '0x005c6898', '0x005bde9c', '0x005c28e4', '0x005d5308', '0x005d971c', '0x005d790c', '0x005ac350', '0x005d3260', '0x005d9e8c', '0x005d9784', '0x005d3248']
COUNTS = {'wu_00': (13, 1, 0, 10, 25, 13), 'wu_01': (8, 0, 1, 3, 24, 42), 'wu_02': (7, 7, 1, 5, 28, 59), 'wu_03': (14, 1, 1, 5, 23, 19), 'wu_04': (7, 1, 1, 6, 10, 16), 'wu_05': (3, 1, 1, 0, 3, 0), 'wu_06': (2, 0, 0, 0, 2, 0), 'wu_07': (0, 0, 0, 2, 0, 0), 'wu_08': (1, 1, 0, 1, 1, 0), 'wu_09': (0, 0, 0, 1, 0, 0), 'wu_10': (1, 1, 0, 0, 1, 0), 'wu_11': (0, 0, 0, 1, 0, 0), 'wu_12': (0, 0, 0, 1, 0, 0), 'wu_13': (0, 0, 0, 0, 0, 0)}
WORDS = [517, 489, 764, 390, 268, 49, 42, 26, 25, 20, 19, 15, 15, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2645
    for needle in ('2645', '764', '517', 'showTimeCrystalUITapped',
                   'ownershipSignPositions', 'playerIsAdminWithID', 'SKPaymentQueue',
                   'setIdleTimerDisabled', 'tileIsNotUnminedBlockSoCanBeRemovedOnRepair',
                   'backWallRemovesWithRepairTool'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_ui():
    s = BY['wu_00']['semantics']
    assert 'workbenchTapped' in s
    s = BY['wu_01']['semantics']
    assert 'tileIsNotUnminedBlockSoCanBeRemovedOnRepair' in s
    s = BY['wu_05']['semantics']
    assert 'SKPaymentQueue' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.repairMode' in symbols
    assert 'OBJC_IVAR_$_World.idleTimerDisabled' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_ui()
    print('test_worldui_evidence: OK')
