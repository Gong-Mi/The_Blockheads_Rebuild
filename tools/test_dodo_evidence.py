#!/usr/bin/env python3
"""Contract test for Dodo (E141)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DODO.md').read_text()
DATA = json.loads((NATIVE / 'dodo.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['dd_00', 'dd_01', 'dd_02', 'dd_03', 'dd_04', 'dd_05', 'dd_06', 'dd_07', 'dd_08', 'dd_09', 'dd_10', 'dd_11', 'dd_12', 'dd_13', 'dd_14', 'dd_15', 'dd_16', 'dd_17', 'dd_18', 'dd_19', 'dd_20', 'dd_21', 'dd_22', 'dd_23', 'dd_24', 'dd_25', 'dd_26', 'dd_27', 'dd_28', 'dd_29', 'dd_30', 'dd_31', 'dd_32', 'dd_33', 'dd_34', 'dd_35', 'dd_36', 'dd_37', 'dd_38', 'dd_39', 'dd_40', 'dd_41', 'dd_42', 'dd_43', 'dd_44', 'dd_45']
IMPS = ['0x00a80aa0', '0x00a805c8', '0x00a80814', '0x00a809a8', '0x00a7ff88', '0x00a803d4', '0x00a80094', '0x00a80178', '0x00a6a49c', '0x00a6a480', '0x00a776ec', '0x00a6c88c', '0x00a6bd3c', '0x00a6c034', '0x00a76fc8', '0x00a6c1d8', '0x00a6bb80', '0x00a6c940', '0x00a6a464', '0x00a6a4b8', '0x00a6a4e8', '0x00a6c8a8', '0x00a7f76c', '0x00a6b664', '0x00a6b904', '0x00a77280', '0x00a8098c', '0x00a6a508', '0x00a6a404', '0x00a7f11c', '0x00a6a3e8', '0x00a7f98c', '0x00a7f56c', '0x00a6c724', '0x00a6c590', '0x00a80738', '0x00a7f8f8', '0x00a804e0', '0x00a80438', '0x00a802e0', '0x00a80a84', '0x00a8047c', '0x00a6a434', '0x00a7fd68', '0x00a7f138', '0x00a6bf48']
COUNTS = {'dd_00': (0, 0, 0, 0, 0, 34), 'dd_01': (1, 1, 1, 7, 1, 1), 'dd_02': (2, 1, 0, 3, 2, 4), 'dd_03': (1, 1, 1, 2, 1, 1), 'dd_04': (1, 3, 1, 1, 3, 2), 'dd_05': (1, 0, 1, 0, 1, 0), 'dd_06': (2, 1, 0, 0, 2, 5), 'dd_07': (4, 2, 1, 0, 4, 5), 'dd_08': (0, 0, 0, 0, 0, 0), 'dd_09': (0, 0, 0, 0, 0, 0), 'dd_10': (1, 0, 0, 6, 6, 8), 'dd_11': (0, 0, 0, 0, 0, 0), 'dd_12': (4, 1, 1, 0, 8, 4), 'dd_13': (2, 2, 1, 5, 6, 0), 'dd_14': (5, 3, 2, 4, 6, 4), 'dd_15': (3, 1, 0, 8, 6, 9), 'dd_16': (1, 0, 0, 4, 2, 3), 'dd_17': (31, 8, 2, 47, 272, 83), 'dd_18': (0, 0, 0, 0, 0, 0), 'dd_19': (0, 0, 0, 0, 0, 0), 'dd_20': (0, 0, 0, 0, 0, 0), 'dd_21': (0, 0, 0, 0, 1, 2), 'dd_22': (1, 1, 1, 5, 2, 2), 'dd_23': (2, 1, 1, 0, 2, 2), 'dd_24': (3, 2, 1, 4, 3, 2), 'dd_25': (5, 5, 1, 11, 8, 13), 'dd_26': (0, 0, 0, 0, 0, 0), 'dd_27': (8, 21, 2, 27, 32, 3), 'dd_28': (0, 0, 0, 0, 0, 0), 'dd_29': (0, 0, 0, 0, 0, 0), 'dd_30': (0, 0, 0, 0, 0, 0), 'dd_31': (5, 4, 2, 7, 9, 2), 'dd_32': (4, 2, 1, 3, 5, 3), 'dd_33': (3, 1, 1, 0, 3, 0), 'dd_34': (3, 1, 1, 1, 3, 1), 'dd_35': (1, 1, 1, 2, 1, 1), 'dd_36': (0, 0, 0, 3, 2, 0), 'dd_37': (0, 0, 0, 2, 0, 4), 'dd_38': (0, 0, 0, 1, 0, 0), 'dd_39': (1, 0, 0, 0, 7, 2), 'dd_40': (0, 0, 0, 0, 0, 0), 'dd_41': (0, 0, 0, 1, 1, 0), 'dd_42': (0, 1, 0, 0, 0, 0), 'dd_43': (5, 3, 2, 2, 6, 2), 'dd_44': (2, 0, 0, 2, 24, 13), 'dd_45': (2, 1, 1, 0, 3, 2)}
WORDS = [152, 92, 94, 55, 67, 25, 57, 90, 7, 7, 220, 7, 131, 105, 174, 238, 111, 9339, 7, 12, 8, 38, 99, 94, 128, 283, 7, 961, 12, 7, 7, 247, 128, 90, 101, 55, 37, 58, 17, 61, 7, 25, 12, 136, 269, 59]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 13936
    for needle in ('13936', 'Dodo', 'update', 'egg'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_dodo():
    assert len(DATA['classes']) == 46
    s = BY['dd_00']['semantics']
    assert '0xa80aa0' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_dodo()
    print('test_dodo_evidence: OK')
