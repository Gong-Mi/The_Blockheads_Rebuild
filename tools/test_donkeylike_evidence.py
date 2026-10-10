#!/usr/bin/env python3
"""Contract test for DonkeyLike (E97)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DONKEYLIKE.md').read_text()
DATA = json.loads((NATIVE / 'donkeylike.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['dl_00', 'dl_01', 'dl_02', 'dl_03', 'dl_04', 'dl_05', 'dl_06', 'dl_07', 'dl_08', 'dl_09', 'dl_10', 'dl_11', 'dl_12', 'dl_13', 'dl_14', 'dl_15', 'dl_16', 'dl_17', 'dl_18', 'dl_19', 'dl_20', 'dl_21', 'dl_22', 'dl_23', 'dl_24', 'dl_25', 'dl_26', 'dl_27', 'dl_28', 'dl_29', 'dl_30', 'dl_31', 'dl_32', 'dl_33', 'dl_34', 'dl_35', 'dl_36', 'dl_37', 'dl_38', 'dl_39', 'dl_40', 'dl_41', 'dl_42', 'dl_43', 'dl_44', 'dl_45']
IMPS = ['0x00ab0710', '0x00ab0aa8', '0x00ab0ac4', '0x00ab0d64', '0x00ab0eb0', '0x00ab1008', '0x00ab11cc', '0x00ab12f0', '0x00ab13dc', '0x00ab13f8', '0x00ab14c4', '0x00ab1d18', '0x00ab1e84', '0x00ab1fc4', '0x00ab2130', '0x00abc508', '0x00ac2ef0', '0x00ac2f10', '0x00ac35ec', '0x00ac381c', '0x00ac398c', '0x00ac4260', '0x00ac42e0', '0x00ac43d4', '0x00ac457c', '0x00ac45a8', '0x00ac46e4', '0x00ac47dc', '0x00ac4858', '0x00ac489c', '0x00ac48d0', '0x00ac4a84', '0x00ac4a9c', '0x00ac4ab8', '0x00ac4ba8', '0x00ac4bc4', '0x00ac4be0', '0x00ac4cd8', '0x00ac4f84', '0x00ac4fa0', '0x00ac4fbc', '0x00ac4fd8', '0x00ac4ff4', '0x00ac50d8', '0x00ac5240', '0x00ac525c']
COUNTS = {'dl_00': (2, 9, 1, 8, 5, 0), 'dl_01': (0, 0, 0, 0, 0, 0), 'dl_02': (2, 1, 1, 0, 2, 2), 'dl_03': (3, 2, 1, 0, 3, 2), 'dl_04': (2, 0, 0, 0, 6, 4), 'dl_05': (1, 0, 0, 4, 2, 2), 'dl_06': (3, 1, 1, 0, 4, 2), 'dl_07': (2, 1, 1, 0, 3, 2), 'dl_08': (0, 0, 0, 0, 0, 0), 'dl_09': (2, 2, 1, 1, 2, 0), 'dl_10': (4, 1, 0, 14, 15, 23), 'dl_11': (3, 1, 1, 1, 3, 1), 'dl_12': (3, 1, 1, 0, 3, 0), 'dl_13': (1, 1, 0, 4, 1, 4), 'dl_14': (44, 5, 4, 73, 361, 348), 'dl_15': (16, 2, 2, 29, 176, 50), 'dl_16': (0, 0, 0, 0, 0, 0), 'dl_17': (1, 0, 0, 4, 30, 18), 'dl_18': (2, 1, 1, 6, 3, 4), 'dl_19': (2, 1, 0, 5, 2, 4), 'dl_20': (2, 1, 1, 12, 26, 25), 'dl_21': (0, 0, 0, 3, 7, 0), 'dl_22': (0, 0, 0, 2, 5, 0), 'dl_23': (2, 1, 0, 4, 3, 4), 'dl_24': (0, 0, 0, 0, 0, 0), 'dl_25': (1, 1, 1, 5, 1, 2), 'dl_26': (1, 1, 1, 3, 1, 1), 'dl_27': (0, 0, 0, 3, 0, 0), 'dl_28': (0, 0, 0, 1, 0, 0), 'dl_29': (0, 0, 0, 0, 0, 0), 'dl_30': (2, 0, 0, 2, 6, 2), 'dl_31': (0, 0, 0, 0, 0, 0), 'dl_32': (0, 0, 0, 0, 0, 0), 'dl_33': (0, 0, 0, 2, 0, 4), 'dl_34': (0, 0, 0, 0, 0, 0), 'dl_35': (0, 0, 0, 0, 0, 0), 'dl_36': (1, 1, 1, 3, 1, 1), 'dl_37': (4, 2, 2, 7, 5, 2), 'dl_38': (0, 0, 0, 0, 0, 0), 'dl_39': (0, 0, 0, 0, 0, 0), 'dl_40': (0, 0, 0, 0, 0, 0), 'dl_41': (0, 0, 0, 0, 0, 0), 'dl_42': (2, 1, 0, 0, 2, 5), 'dl_43': (4, 2, 1, 0, 4, 5), 'dl_44': (0, 0, 0, 0, 0, 0), 'dl_45': (0, 0, 0, 2, 12, 0)}
WORDS = [230, 7, 94, 83, 86, 113, 73, 59, 7, 51, 518, 91, 80, 91, 7982, 6288, 8, 439, 140, 92, 565, 93, 61, 106, 11, 79, 62, 31, 17, 13, 109, 6, 7, 60, 14, 7, 62, 171, 28, 21, 14, 7, 57, 90, 7, 250]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 18480
    for needle in ('18480', 'tileIsAirWaterOrSnow', 'tileContainsGate', 'cosf', '0x1518', 'glUniformMatrix4fv'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_animal():
    s = BY['dl_14']['semantics']
    assert 'tileIsAirWaterOrSnow' in s and '0x1518' in s
    s = BY['dl_20']['semantics']
    assert 'tileContainsGate' in s
    s = BY['dl_45']['semantics']
    assert 'cosf' in s and 'sinf' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_animal()
    print('test_donkeylike_evidence: OK')
