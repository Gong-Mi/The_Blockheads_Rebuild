#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BLOCKHEAD2.md').read_text()
DATA = json.loads((NATIVE / 'blockhead2.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['hb_00', 'hb_01', 'hb_02', 'hb_03', 'hb_04', 'hb_05', 'hb_06', 'hb_07', 'hb_08', 'hb_09', 'hb_10', 'hb_11', 'hb_12', 'hb_13', 'hb_14', 'hb_15', 'hb_16', 'hb_17', 'hb_18', 'hb_19', 'hb_20', 'hb_21', 'hb_22', 'hb_23', 'hb_24', 'hb_25', 'hb_26', 'hb_27', 'hb_28', 'hb_29', 'hb_30', 'hb_31', 'hb_32', 'hb_33', 'hb_34', 'hb_35', 'hb_36', 'hb_37', 'hb_38', 'hb_39', 'hb_40', 'hb_41', 'hb_42', 'hb_43', 'hb_44', 'hb_45', 'hb_46', 'hb_47', 'hb_48', 'hb_49', 'hb_50', 'hb_51', 'hb_52', 'hb_53', 'hb_54', 'hb_55']
IMPS = ['0x00c87be8', '0x00c803b8', '0x00c8a644', '0x00c81f74', '0x00c833bc', '0x00ba9d8c', '0x00c7cde8', '0x00c5ec34', '0x00c644e4', '0x00c638dc', '0x00c73100', '0x00c88c08', '0x00c89c2c', '0x00bac27c', '0x00baa1dc', '0x00c8015c', '0x00baa364', '0x00baa3a0', '0x00bb3488', '0x00bac194', '0x00b9ea28', '0x00ba097c', '0x00bacd0c', '0x00c800e4', '0x00c7d2b8', '0x00c74e24', '0x00c82628', '0x00c881f8', '0x00c89c48', '0x00c6dd30', '0x00c6e6b0', '0x00c6cb54', '0x00c6be48', '0x00c6becc', '0x00b91e08', '0x00c82a4c', '0x00bac728', '0x00ba0fe0', '0x00bac158', '0x00c67a58', '0x00c837b8', '0x00c82fc4', '0x00b9b6a0', '0x00c7d680', '0x00c7d590', '0x00c74c70', '0x00bac674', '0x00bac0a4', '0x00c5c9f0', '0x00bb0e70', '0x00c80940', '0x00bb2c6c', '0x00c7c320', '0x00babab0', '0x00bab850', '0x00babc70']
COUNTS = {'hb_00': (10, 2, 3, 5, 24, 2), 'hb_01': (1, 1, 0, 1, 1, 0), 'hb_02': (0, 0, 0, 1, 0, 0), 'hb_03': (0, 0, 0, 1, 1, 3), 'hb_04': (9, 2, 1, 3, 16, 11), 'hb_05': (3, 1, 0, 1, 9, 38), 'hb_06': (10, 1, 0, 5, 13, 18), 'hb_07': (18, 4, 3, 1, 29, 38), 'hb_08': (1, 1, 0, 0, 1, 0), 'hb_09': (15, 2, 1, 5, 39, 46), 'hb_10': (2, 1, 0, 1, 2, 0), 'hb_11': (27, 4, 5, 6, 66, 34), 'hb_12': (0, 0, 0, 0, 0, 0), 'hb_13': (4, 1, 0, 2, 8, 6), 'hb_14': (3, 1, 0, 2, 4, 7), 'hb_15': (3, 1, 0, 4, 3, 8), 'hb_16': (0, 0, 0, 1, 0, 0), 'hb_17': (2, 0, 0, 0, 2, 0), 'hb_18': (4, 2, 0, 2, 60, 91), 'hb_19': (1, 1, 0, 2, 1, 3), 'hb_20': (20, 26, 7, 25, 63, 34), 'hb_21': (9, 1, 1, 0, 17, 27), 'hb_22': (17, 2, 1, 3, 75, 226), 'hb_23': (1, 1, 0, 1, 1, 0), 'hb_24': (5, 1, 0, 1, 8, 18), 'hb_25': (6, 1, 0, 2, 15, 22), 'hb_26': (5, 1, 1, 3, 6, 5), 'hb_27': (16, 4, 4, 4, 39, 9), 'hb_28': (0, 0, 0, 0, 1, 8), 'hb_29': (15, 3, 1, 6, 28, 28), 'hb_30': (7, 1, 0, 3, 16, 17), 'hb_31': (5, 1, 0, 3, 5, 1), 'hb_32': (1, 1, 0, 0, 1, 0), 'hb_33': (20, 3, 1, 9, 47, 33), 'hb_34': (33, 5, 6, 23, 200, 182), 'hb_35': (0, 0, 0, 1, 0, 0), 'hb_36': (0, 0, 0, 1, 0, 0), 'hb_37': (90, 17, 0, 16, 472, 976), 'hb_38': (0, 0, 0, 1, 0, 0), 'hb_39': (5, 1, 0, 1, 27, 92), 'hb_40': (1, 1, 0, 1, 1, 4), 'hb_41': (5, 1, 0, 2, 11, 16), 'hb_42': (5, 2, 0, 2, 5, 3), 'hb_43': (51, 12, 6, 14, 127, 170), 'hb_44': (1, 0, 0, 0, 1, 0), 'hb_45': (5, 1, 0, 3, 5, 1), 'hb_46': (2, 1, 0, 1, 2, 0), 'hb_47': (2, 1, 0, 1, 2, 0), 'hb_48': (21, 7, 1, 21, 37, 41), 'hb_49': (46, 10, 2, 22, 84, 71), 'hb_50': (7, 1, 0, 4, 7, 2), 'hb_51': (14, 3, 2, 18, 22, 8), 'hb_52': (1, 1, 0, 4, 2, 8), 'hb_53': (2, 1, 0, 1, 3, 6), 'hb_54': (3, 1, 0, 1, 5, 9), 'hb_55': (5, 1, 0, 1, 8, 14)}
WORDS = [388, 25, 17, 93, 255, 276, 308, 547, 30, 723, 49, 1033, 7, 171, 98, 151, 15, 58, 1220, 58, 1391, 343, 1433, 30, 182, 336, 167, 644, 106, 519, 324, 109, 33, 781, 4047, 15, 15, 8735, 15, 602, 43, 254, 115, 2669, 60, 109, 45, 45, 854, 1919, 145, 511, 98, 112, 152, 229]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 32709
    for needle in ('32709',
                   '28-arm jump table',
                   'jetpack',
                   '0x4000',
                   'toolBreak.wav'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_blockhead2():
    assert len(DATA['classes']) == 56
    s = BY['hb_04']['semantics']
    assert '0x666' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_blockhead2()
    print('test_blockhead2_evidence: OK')
