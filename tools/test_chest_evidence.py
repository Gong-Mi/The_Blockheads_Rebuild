#!/usr/bin/env python3
"""Contract test for Chest (E139)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CHEST.md').read_text()
DATA = json.loads((NATIVE / 'chest.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['ce_00', 'ce_01', 'ce_02', 'ce_03', 'ce_04', 'ce_05', 'ce_06', 'ce_07', 'ce_08', 'ce_09', 'ce_10', 'ce_11', 'ce_12', 'ce_13', 'ce_14', 'ce_15', 'ce_16', 'ce_17', 'ce_18', 'ce_19', 'ce_20', 'ce_21', 'ce_22', 'ce_23', 'ce_24', 'ce_25', 'ce_26', 'ce_27', 'ce_28', 'ce_29', 'ce_30', 'ce_31', 'ce_32', 'ce_33', 'ce_34', 'ce_35', 'ce_36', 'ce_37', 'ce_38', 'ce_39', 'ce_40', 'ce_41', 'ce_42', 'ce_43', 'ce_44', 'ce_45', 'ce_46', 'ce_47']
IMPS = ['0x00cbd834', '0x00cc3430', '0x00cbe5c0', '0x00cc21d4', '0x00cc1a64', '0x00cbd940', '0x00cbd904', '0x00cbc1d0', '0x00cb94ec', '0x00cbd634', '0x00cbb1d0', '0x00cbd274', '0x00cbd290', '0x00cbd228', '0x00cbd140', '0x00cb9638', '0x00cb4ee0', '0x00cb517c', '0x00cb6e5c', '0x00cba410', '0x00cc39d0', '0x00cc41bc', '0x00cb7ac8', '0x00cc3d04', '0x00cc3bbc', '0x00cc3bd8', '0x00cbc100', '0x00cbb3f8', '0x00cc3e24', '0x00cc3a18', '0x00cb88b4', '0x00cba42c', '0x00cbd2ac', '0x00cbdce4', '0x00cc3e40', '0x00cbd8e8', '0x00cbd524', '0x00cbe330', '0x00cc3140', '0x00cbe030', '0x00cc1e78', '0x00cc19fc', '0x00cbd67c', '0x00cb8140', '0x00cb8908', '0x00cbdb90', '0x00cbc704', '0x00cbd0ec']
COUNTS = {'ce_00': (2, 2, 1, 0, 2, 0), 'ce_01': (5, 1, 0, 6, 9, 17), 'ce_02': (11, 2, 2, 12, 39, 28), 'ce_03': (5, 1, 0, 6, 11, 18), 'ce_04': (0, 0, 0, 4, 8, 3), 'ce_05': (5, 2, 1, 3, 5, 8), 'ce_06': (0, 0, 0, 1, 0, 0), 'ce_07': (4, 1, 0, 7, 9, 4), 'ce_08': (2, 2, 1, 1, 2, 0), 'ce_09': (0, 0, 0, 1, 1, 0), 'ce_10': (0, 0, 0, 0, 0, 0), 'ce_11': (0, 0, 0, 0, 0, 0), 'ce_12': (0, 0, 0, 0, 0, 0), 'ce_13': (1, 1, 0, 0, 1, 0), 'ce_14': (0, 0, 0, 1, 1, 0), 'ce_15': (17, 7, 4, 4, 44, 33), 'ce_16': (1, 0, 0, 3, 8, 4), 'ce_17': (18, 4, 3, 4, 54, 59), 'ce_18': (20, 7, 3, 8, 39, 30), 'ce_19': (0, 0, 0, 0, 0, 0), 'ce_20': (0, 0, 0, 1, 1, 0), 'ce_21': (0, 0, 0, 1, 0, 0), 'ce_22': (0, 0, 0, 0, 15, 16), 'ce_23': (3, 1, 0, 3, 3, 2), 'ce_24': (0, 0, 0, 0, 0, 0), 'ce_25': (2, 1, 0, 4, 2, 3), 'ce_26': (1, 0, 0, 0, 5, 1), 'ce_27': (10, 3, 0, 3, 46, 46), 'ce_28': (0, 0, 0, 0, 0, 0), 'ce_29': (3, 0, 0, 6, 4, 1), 'ce_30': (1, 1, 0, 0, 1, 0), 'ce_31': (20, 5, 3, 14, 39, 37), 'ce_32': (4, 1, 0, 8, 4, 9), 'ce_33': (3, 2, 1, 4, 10, 4), 'ce_34': (7, 1, 0, 1, 11, 10), 'ce_35': (0, 0, 0, 0, 0, 0), 'ce_36': (2, 2, 1, 2, 2, 2), 'ce_37': (5, 2, 1, 5, 6, 7), 'ce_38': (5, 1, 0, 4, 5, 16), 'ce_39': (4, 1, 0, 3, 5, 18), 'ce_40': (5, 1, 0, 4, 7, 17), 'ce_41': (0, 0, 0, 1, 0, 2), 'ce_42': (0, 7, 0, 1, 0, 17), 'ce_43': (13, 1, 2, 5, 24, 22), 'ce_44': (18, 5, 3, 8, 35, 37), 'ce_45': (2, 1, 1, 3, 2, 3), 'ce_46': (2, 1, 0, 4, 27, 41), 'ce_47': (1, 1, 0, 0, 1, 0)}
WORDS = [45, 360, 2373, 396, 261, 148, 15, 200, 49, 18, 138, 7, 7, 19, 18, 886, 167, 1072, 786, 7, 18, 15, 323, 72, 7, 75, 52, 834, 7, 105, 21, 873, 158, 211, 223, 7, 68, 164, 188, 192, 195, 26, 110, 477, 761, 85, 619, 21]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 12879
    for needle in ('12879', 'inventory', 'chestType', 'netData'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_chest():
    assert len(DATA['classes']) == 48
    s = BY['ce_00']['semantics']
    assert '0xcbd834' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_chest()
    print('test_chest_evidence: OK')
