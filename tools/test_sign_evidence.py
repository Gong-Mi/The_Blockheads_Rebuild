#!/usr/bin/env python3
"""Contract test for Sign (E147)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'SIGN.md').read_text()
DATA = json.loads((NATIVE / 'sign.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['sg_00', 'sg_01', 'sg_02', 'sg_03', 'sg_04', 'sg_05', 'sg_06', 'sg_07', 'sg_08', 'sg_09', 'sg_10', 'sg_11', 'sg_12', 'sg_13', 'sg_14', 'sg_15', 'sg_16', 'sg_17', 'sg_18', 'sg_19', 'sg_20', 'sg_21', 'sg_22', 'sg_23', 'sg_24', 'sg_25', 'sg_26', 'sg_27', 'sg_28', 'sg_29', 'sg_30', 'sg_31', 'sg_32', 'sg_33', 'sg_34', 'sg_35']
IMPS = ['0x00600b94', '0x00600f24', '0x006012d8', '0x005fb474', '0x005fb7ec', '0x00600b48', '0x005fcaf0', '0x00600540', '0x0060055c', '0x006004f4', '0x006004a8', '0x005f9b00', '0x005fa1b8', '0x005fa89c', '0x005fa5e8', '0x00601104', '0x00601264', '0x005fae98', '0x005fc5a4', '0x005fb268', '0x00601280', '0x0060129c', '0x00601120', '0x005fc784', '0x00600578', '0x005fb8ec', '0x00600bc4', '0x00600f08', '0x00600be0', '0x005fc3e8', '0x005fc568', '0x00600b64', '0x00600eb8', '0x005fb958', '0x005fb214', '0x005ffb58']
COUNTS = {'sg_00': (0, 1, 0, 0, 0, 0), 'sg_01': (5, 2, 1, 2, 5, 5), 'sg_02': (0, 0, 0, 1, 0, 0), 'sg_03': (5, 1, 1, 2, 8, 2), 'sg_04': (2, 2, 1, 2, 3, 0), 'sg_05': (0, 0, 0, 0, 0, 0), 'sg_06': (15, 2, 0, 12, 117, 45), 'sg_07': (0, 0, 0, 0, 0, 0), 'sg_08': (0, 0, 0, 0, 0, 0), 'sg_09': (1, 1, 0, 0, 1, 0), 'sg_10': (1, 1, 0, 0, 1, 0), 'sg_11': (6, 14, 1, 9, 14, 15), 'sg_12': (4, 2, 1, 6, 7, 13), 'sg_13': (12, 5, 1, 6, 20, 9), 'sg_14': (0, 0, 0, 0, 0, 0), 'sg_15': (0, 0, 0, 0, 0, 0), 'sg_16': (0, 0, 0, 0, 0, 0), 'sg_17': (0, 0, 0, 0, 0, 0), 'sg_18': (4, 4, 0, 2, 8, 0), 'sg_19': (2, 4, 1, 3, 4, 3), 'sg_20': (0, 0, 0, 0, 0, 0), 'sg_21': (0, 0, 0, 1, 0, 0), 'sg_22': (3, 1, 0, 5, 3, 1), 'sg_23': (7, 2, 1, 4, 8, 2), 'sg_24': (8, 1, 0, 10, 13, 17), 'sg_25': (1, 1, 1, 0, 1, 0), 'sg_26': (0, 0, 0, 0, 0, 0), 'sg_27': (0, 0, 0, 0, 0, 0), 'sg_28': (2, 1, 1, 4, 7, 8), 'sg_29': (6, 1, 0, 3, 6, 1), 'sg_30': (0, 0, 0, 1, 0, 0), 'sg_31': (0, 1, 0, 0, 0, 0), 'sg_32': (0, 0, 0, 1, 0, 0), 'sg_33': (5, 1, 2, 5, 12, 6), 'sg_34': (1, 1, 0, 0, 1, 0), 'sg_35': (4, 1, 0, 8, 16, 31)}
WORDS = [12, 120, 15, 131, 64, 7, 2498, 7, 7, 19, 19, 430, 268, 374, 7, 7, 7, 7, 120, 131, 7, 15, 81, 165, 372, 27, 7, 7, 182, 96, 15, 12, 20, 259, 21, 596]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 6132
    for needle in ('6132', 'Sign', 'connectionType', 'bitmap'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_sign():
    assert len(DATA['classes']) == 36
    s = BY['sg_00']['semantics']
    assert '0x600b94' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_sign()
    print('test_sign_evidence: OK')
