#!/usr/bin/env python3
"""Contract test for DropBear (E145)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DROPBEAR.md').read_text()
DATA = json.loads((NATIVE / 'dropbear.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['db_00', 'db_01', 'db_02', 'db_03', 'db_04', 'db_05', 'db_06', 'db_07', 'db_08', 'db_09', 'db_10', 'db_11', 'db_12', 'db_13', 'db_14', 'db_15', 'db_16', 'db_17', 'db_18', 'db_19', 'db_20', 'db_21', 'db_22', 'db_23', 'db_24', 'db_25', 'db_26', 'db_27', 'db_28', 'db_29', 'db_30', 'db_31', 'db_32']
IMPS = ['0x007b24b8', '0x007b1eec', '0x007b2204', '0x007b22ac', '0x0079c834', '0x0079c818', '0x0079efb0', '0x0079e43c', '0x0079e734', '0x0079e974', '0x0079f160', '0x0079e2b8', '0x0079c7fc', '0x0079c850', '0x0079c880', '0x007b1de0', '0x0079d2ac', '0x0079db88', '0x0079c89c', '0x0079c79c', '0x007b18b4', '0x0079c780', '0x007b1fac', '0x007b1d1c', '0x0079ee1c', '0x0079efcc', '0x007b1e8c', '0x007b249c', '0x0079c7cc', '0x007b20f0', '0x007b18d0', '0x0079e648', '0x007b1ed4']
COUNTS = {'db_00': (0, 0, 0, 1, 9, 0), 'db_01': (1, 1, 0, 1, 1, 1), 'db_02': (1, 1, 0, 0, 1, 4), 'db_03': (4, 3, 1, 0, 6, 7), 'db_04': (0, 0, 0, 0, 0, 0), 'db_05': (0, 0, 0, 0, 0, 0), 'db_06': (0, 0, 0, 0, 0, 0), 'db_07': (4, 1, 1, 0, 8, 4), 'db_08': (2, 2, 1, 8, 9, 0), 'db_09': (4, 2, 1, 13, 7, 7), 'db_10': (14, 3, 0, 40, 248, 85), 'db_11': (1, 0, 0, 4, 2, 2), 'db_12': (0, 0, 0, 0, 0, 0), 'db_13': (0, 0, 0, 0, 0, 0), 'db_14': (0, 0, 0, 0, 0, 0), 'db_15': (1, 1, 1, 1, 1, 0), 'db_16': (2, 1, 1, 4, 4, 5), 'db_17': (3, 2, 1, 4, 3, 4), 'db_18': (6, 14, 2, 22, 24, 1), 'db_19': (0, 0, 0, 0, 0, 0), 'db_20': (0, 0, 0, 0, 0, 0), 'db_21': (0, 0, 0, 0, 0, 0), 'db_22': (3, 1, 1, 3, 3, 0), 'db_23': (3, 1, 1, 1, 3, 0), 'db_24': (3, 1, 1, 1, 3, 1), 'db_25': (3, 1, 1, 1, 3, 1), 'db_26': (0, 0, 0, 1, 0, 0), 'db_27': (0, 0, 0, 0, 0, 0), 'db_28': (0, 1, 0, 0, 0, 0), 'db_29': (4, 2, 2, 1, 4, 0), 'db_30': (1, 0, 0, 3, 20, 11), 'db_31': (2, 1, 1, 0, 3, 2), 'db_32': (0, 0, 0, 0, 0, 0)}
WORDS = [187, 48, 42, 124, 7, 7, 7, 131, 144, 298, 11364, 97, 7, 12, 7, 43, 163, 142, 640, 12, 7, 7, 81, 49, 101, 101, 18, 7, 12, 69, 275, 59, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 14274
    for needle in ('14274', 'DropBear', 'drop', 'provoke'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_dropbear():
    assert len(DATA['classes']) == 33
    s = BY['db_00']['semantics']
    assert '0x7b24b8' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_dropbear()
    print('test_dropbear_evidence: OK')
