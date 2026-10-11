#!/usr/bin/env python3
"""Contract test for Scorpion (E143)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'SCORPION.md').read_text()
DATA = json.loads((NATIVE / 'scorpion.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['sc_00', 'sc_01', 'sc_02', 'sc_03', 'sc_04', 'sc_05', 'sc_06', 'sc_07', 'sc_08', 'sc_09', 'sc_10', 'sc_11', 'sc_12', 'sc_13', 'sc_14', 'sc_15', 'sc_16', 'sc_17', 'sc_18', 'sc_19', 'sc_20', 'sc_21', 'sc_22', 'sc_23', 'sc_24', 'sc_25', 'sc_26', 'sc_27', 'sc_28', 'sc_29', 'sc_30', 'sc_31', 'sc_32', 'sc_33', 'sc_34', 'sc_35', 'sc_36', 'sc_37', 'sc_38', 'sc_39', 'sc_40', 'sc_41']
IMPS = ['0x008ac49c', '0x008ac0b4', '0x008ac260', '0x008ac3a4', '0x008abeac', '0x008abb20', '0x008abbc8', '0x008931bc', '0x008931a0', '0x00894820', '0x00894260', '0x00894614', '0x008a4448', '0x00895080', '0x00895630', '0x00893184', '0x008931d8', '0x00893208', '0x008ab644', '0x00893be0', '0x00893e80', '0x008ab4bc', '0x008ac388', '0x00893224', '0x00893124', '0x008aaf70', '0x00893108', '0x008ab8a0', '0x008ab3c8', '0x0089483c', '0x00895498', '0x008ac184', '0x008ab858', '0x008abfb8', '0x008abf10', '0x008abdb8', '0x008ac480', '0x008940fc', '0x008abf54', '0x00893154', '0x008aaf8c', '0x00894528']
COUNTS = {'sc_00': (0, 0, 0, 0, 0, 0), 'sc_01': (1, 1, 1, 2, 1, 1), 'sc_02': (2, 1, 0, 2, 2, 3), 'sc_03': (1, 1, 1, 2, 1, 1), 'sc_04': (1, 0, 1, 0, 1, 0), 'sc_05': (1, 1, 0, 0, 1, 4), 'sc_06': (4, 3, 1, 0, 6, 7), 'sc_07': (0, 0, 0, 0, 0, 0), 'sc_08': (0, 0, 0, 0, 0, 0), 'sc_09': (0, 0, 0, 0, 0, 0), 'sc_10': (5, 1, 1, 2, 8, 5), 'sc_11': (2, 2, 1, 7, 8, 0), 'sc_12': (4, 2, 2, 3, 4, 2), 'sc_13': (2, 1, 0, 9, 6, 9), 'sc_14': (13, 3, 0, 31, 255, 63), 'sc_15': (0, 0, 0, 0, 0, 0), 'sc_16': (0, 0, 0, 0, 0, 0), 'sc_17': (0, 0, 0, 0, 0, 0), 'sc_18': (2, 2, 1, 7, 3, 2), 'sc_19': (2, 1, 1, 0, 2, 2), 'sc_20': (3, 2, 1, 4, 3, 2), 'sc_21': (1, 1, 0, 2, 2, 4), 'sc_22': (0, 0, 0, 0, 0, 0), 'sc_23': (6, 11, 2, 18, 21, 3), 'sc_24': (0, 0, 0, 0, 0, 0), 'sc_25': (0, 0, 0, 0, 0, 0), 'sc_26': (0, 0, 0, 0, 0, 0), 'sc_27': (4, 3, 2, 5, 7, 0), 'sc_28': (3, 1, 1, 2, 3, 1), 'sc_29': (9, 2, 1, 11, 15, 32), 'sc_30': (3, 1, 1, 1, 3, 1), 'sc_31': (1, 1, 1, 2, 1, 1), 'sc_32': (0, 0, 0, 1, 0, 0), 'sc_33': (0, 0, 0, 2, 0, 4), 'sc_34': (0, 0, 0, 1, 0, 0), 'sc_35': (1, 0, 0, 0, 7, 2), 'sc_36': (0, 0, 0, 0, 0, 0), 'sc_37': (1, 0, 0, 3, 2, 2), 'sc_38': (0, 0, 0, 1, 1, 0), 'sc_39': (0, 1, 0, 0, 0, 0), 'sc_40': (1, 0, 0, 3, 20, 11), 'sc_41': (2, 1, 1, 0, 3, 2)}
WORDS = [6, 52, 74, 55, 25, 42, 124, 7, 7, 7, 178, 131, 106, 262, 14029, 7, 12, 7, 133, 94, 128, 98, 7, 619, 12, 7, 7, 160, 61, 529, 102, 55, 18, 63, 17, 61, 7, 89, 25, 12, 271, 59]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 17765
    for needle in ('17765', 'Scorpion', 'update', 'spit'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_scorpion():
    assert len(DATA['classes']) == 42
    s = BY['sc_00']['semantics']
    assert '0x8ac49c' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_scorpion()
    print('test_scorpion_evidence: OK')
