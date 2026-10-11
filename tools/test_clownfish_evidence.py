#!/usr/bin/env python3
"""Contract test for ClownFish (E144)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CLOWNFISH.md').read_text()
DATA = json.loads((NATIVE / 'clownfish.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['clf_00', 'clf_01', 'clf_02', 'clf_03', 'clf_04', 'clf_05', 'clf_06', 'clf_07', 'clf_08', 'clf_09', 'clf_10', 'clf_11', 'clf_12', 'clf_13', 'clf_14', 'clf_15', 'clf_16', 'clf_17', 'clf_18', 'clf_19', 'clf_20', 'clf_21', 'clf_22', 'clf_23', 'clf_24', 'clf_25', 'clf_26', 'clf_27', 'clf_28', 'clf_29', 'clf_30', 'clf_31', 'clf_32', 'clf_33']
IMPS = ['0x0079c14c', '0x0079be1c', '0x0078dc38', '0x0078dd18', '0x0078d42c', '0x0078d410', '0x0078e7e8', '0x0078f5b8', '0x0078e94c', '0x0078ec44', '0x00796ff8', '0x0078ee20', '0x0078f5d8', '0x0078d3a8', '0x0078d3c4', '0x0078d3f4', '0x0079b96c', '0x0078df00', '0x0078e548', '0x0078d448', '0x0078d348', '0x0079b3e4', '0x0078d32c', '0x0079bf18', '0x0079b83c', '0x0079bc7c', '0x0078f368', '0x0078f118', '0x0079baf8', '0x0079befc', '0x0079bb7c', '0x0078d378', '0x0079b400', '0x0078eb58']
COUNTS = {'clf_00': (0, 0, 0, 0, 0, 0), 'clf_01': (2, 1, 0, 1, 2, 1), 'clf_02': (2, 1, 0, 0, 2, 5), 'clf_03': (4, 3, 1, 0, 6, 6), 'clf_04': (0, 0, 0, 0, 0, 0), 'clf_05': (0, 0, 0, 0, 0, 0), 'clf_06': (1, 0, 0, 3, 2, 2), 'clf_07': (0, 0, 0, 0, 0, 0), 'clf_08': (4, 1, 1, 0, 8, 4), 'clf_09': (4, 2, 1, 4, 6, 0), 'clf_10': (6, 3, 2, 6, 8, 6), 'clf_11': (1, 1, 0, 9, 2, 3), 'clf_12': (16, 3, 1, 34, 161, 75), 'clf_13': (0, 0, 0, 0, 0, 0), 'clf_14': (0, 0, 0, 0, 0, 0), 'clf_15': (0, 0, 0, 0, 0, 0), 'clf_16': (1, 1, 1, 5, 2, 2), 'clf_17': (7, 1, 1, 3, 14, 13), 'clf_18': (3, 2, 1, 4, 3, 4), 'clf_19': (6, 12, 2, 17, 14, 5), 'clf_20': (0, 0, 0, 0, 0, 0), 'clf_21': (0, 0, 0, 0, 0, 0), 'clf_22': (0, 0, 0, 0, 0, 0), 'clf_23': (4, 3, 2, 3, 7, 0), 'clf_24': (3, 1, 1, 3, 3, 1), 'clf_25': (5, 1, 0, 1, 5, 3), 'clf_26': (4, 2, 1, 4, 4, 5), 'clf_27': (4, 2, 1, 4, 4, 5), 'clf_28': (0, 0, 0, 2, 2, 0), 'clf_29': (0, 0, 0, 0, 0, 0), 'clf_30': (2, 2, 1, 1, 2, 0), 'clf_31': (0, 1, 0, 0, 0, 0), 'clf_32': (1, 0, 0, 3, 20, 11), 'clf_33': (2, 1, 1, 0, 3, 2)}
WORDS = [6, 56, 56, 122, 7, 7, 89, 8, 131, 119, 194, 190, 6419, 7, 12, 7, 99, 328, 137, 504, 12, 7, 7, 141, 76, 104, 148, 148, 33, 7, 64, 12, 271, 59]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 9587
    for needle in ('9587', 'ClownFish', 'update', 'queue'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_clownfish():
    assert len(DATA['classes']) == 34
    s = BY['clf_00']['semantics']
    assert '0x79c14c' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_clownfish()
    print('test_clownfish_evidence: OK')
