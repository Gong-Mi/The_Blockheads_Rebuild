#!/usr/bin/env python3
"""Contract test for JoinWorldUI (E137)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'JOINWORLDUI.md').read_text()
DATA = json.loads((NATIVE / 'joinworldui.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['jw_00', 'jw_01', 'jw_02', 'jw_03', 'jw_04', 'jw_05', 'jw_06', 'jw_07', 'jw_08', 'jw_09', 'jw_10', 'jw_11', 'jw_12', 'jw_13', 'jw_14', 'jw_15', 'jw_16', 'jw_17', 'jw_18', 'jw_19', 'jw_20', 'jw_21', 'jw_22', 'jw_23', 'jw_24', 'jw_25', 'jw_26', 'jw_27', 'jw_28', 'jw_29', 'jw_30', 'jw_31', 'jw_32', 'jw_33', 'jw_34', 'jw_35', 'jw_36', 'jw_37', 'jw_38', 'jw_39', 'jw_40', 'jw_41', 'jw_42', 'jw_43', 'jw_44', 'jw_45', 'jw_46', 'jw_47', 'jw_48', 'jw_49']
IMPS = ['0x0061b710', '0x0061c704', '0x0061c74c', '0x0061c8c0', '0x0061fd00', '0x0061e914', '0x006221fc', '0x00622018', '0x00622260', '0x006188d4', '0x00625498', '0x0061f580', '0x006254dc', '0x0061f940', '0x00603b38', '0x00603b24', '0x00624918', '0x00618a64', '0x00618bf4', '0x006194e4', '0x00603134', '0x00602fac', '0x0062279c', '0x006225cc', '0x00610e58', '0x00611bec', '0x00601af0', '0x0061499c', '0x00623e20', '0x0061f25c', '0x00622460', '0x00618744', '0x0060a798', '0x0062191c', '0x00622430', '0x00622330', '0x00615360', '0x00621da4', '0x00621ccc', '0x00619bc8', '0x00622444', '0x006034e4', '0x0061e690', '0x00622bfc', '0x00625520', '0x0061e398', '0x0061f1d8', '0x00625410', '0x00625454', '0x00604210']
COUNTS = {'jw_00': (9, 8, 1, 6, 27, 27), 'jw_01': (0, 0, 0, 1, 0, 0), 'jw_02': (4, 2, 0, 2, 4, 0), 'jw_03': (26, 8, 6, 15, 38, 56), 'jw_04': (24, 8, 3, 11, 39, 62), 'jw_05': (15, 3, 1, 10, 30, 19), 'jw_06': (1, 1, 0, 1, 1, 0), 'jw_07': (3, 1, 0, 4, 3, 8), 'jw_08': (1, 1, 0, 3, 1, 0), 'jw_09': (4, 2, 2, 2, 4, 0), 'jw_10': (0, 0, 0, 1, 0, 0), 'jw_11': (12, 5, 1, 3, 12, 0), 'jw_12': (0, 0, 0, 1, 0, 0), 'jw_13': (12, 5, 1, 3, 12, 0), 'jw_14': (4, 2, 1, 29, 31, 0), 'jw_15': (0, 0, 0, 0, 0, 0), 'jw_16': (1, 0, 0, 19, 34, 24), 'jw_17': (4, 2, 2, 2, 4, 0), 'jw_18': (5, 2, 0, 4, 10, 38), 'jw_19': (10, 3, 0, 10, 19, 16), 'jw_20': (9, 3, 1, 4, 11, 2), 'jw_21': (4, 1, 0, 2, 6, 0), 'jw_22': (11, 2, 2, 3, 15, 5), 'jw_23': (2, 0, 0, 0, 9, 7), 'jw_24': (9, 7, 1, 5, 21, 29), 'jw_25': (22, 9, 4, 10, 54, 145), 'jw_26': (25, 18, 8, 20, 46, 29), 'jw_27': (12, 5, 1, 5, 16, 18), 'jw_28': (1, 0, 0, 19, 34, 24), 'jw_29': (10, 5, 1, 2, 10, 0), 'jw_30': (2, 0, 0, 1, 4, 2), 'jw_31': (4, 2, 2, 2, 4, 0), 'jw_32': (5, 1, 0, 43, 50, 26), 'jw_33': (12, 4, 1, 3, 12, 0), 'jw_34': (0, 0, 0, 0, 0, 0), 'jw_35': (2, 1, 0, 3, 2, 2), 'jw_36': (27, 21, 8, 20, 69, 148), 'jw_37': (6, 2, 0, 5, 6, 7), 'jw_38': (2, 1, 0, 2, 2, 0), 'jw_39': (14, 19, 3, 11, 44, 73), 'jw_40': (0, 0, 0, 0, 0, 0), 'jw_41': (14, 3, 3, 8, 19, 5), 'jw_42': (6, 1, 0, 7, 6, 1), 'jw_43': (2, 0, 0, 20, 34, 58), 'jw_44': (0, 0, 0, 1, 0, 0), 'jw_45': (7, 1, 1, 1, 10, 9), 'jw_46': (1, 1, 0, 1, 1, 0), 'jw_47': (0, 0, 0, 1, 0, 0), 'jw_48': (0, 0, 0, 1, 0, 0), 'jw_49': (10, 10, 0, 38, 107, 295)}
WORDS = [1021, 18, 93, 1718, 1799, 561, 25, 121, 52, 100, 17, 240, 17, 240, 438, 5, 702, 100, 572, 441, 236, 98, 280, 116, 869, 2924, 1272, 625, 702, 201, 80, 100, 6576, 236, 5, 64, 3321, 157, 54, 1746, 7, 400, 161, 1161, 15, 190, 33, 17, 17, 6498]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 36441
    for needle in ('36441', 'server', 'world'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_joinworldui():
    assert len(DATA['classes']) == 50
    s = BY['jw_00']['semantics']
    assert '0x61c66c' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_joinworldui()
    print('test_joinworldui_evidence: OK')
