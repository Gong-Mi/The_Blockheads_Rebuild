#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BLOCKHEAD4.md').read_text()
DATA = json.loads((NATIVE / 'blockhead4.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['hf_00', 'hf_01', 'hf_02', 'hf_03', 'hf_04', 'hf_05', 'hf_06', 'hf_07', 'hf_08', 'hf_09', 'hf_10', 'hf_11', 'hf_12', 'hf_13', 'hf_14', 'hf_15', 'hf_16', 'hf_17', 'hf_18', 'hf_19', 'hf_20', 'hf_21', 'hf_22', 'hf_23', 'hf_24', 'hf_25', 'hf_26', 'hf_27', 'hf_28', 'hf_29', 'hf_30', 'hf_31', 'hf_32', 'hf_33', 'hf_34', 'hf_35', 'hf_36', 'hf_37', 'hf_38', 'hf_39', 'hf_40', 'hf_41', 'hf_42', 'hf_43', 'hf_44', 'hf_45', 'hf_46', 'hf_47', 'hf_48', 'hf_49', 'hf_50', 'hf_51', 'hf_52', 'hf_53', 'hf_54', 'hf_55', 'hf_56', 'hf_57', 'hf_58', 'hf_59', 'hf_60', 'hf_61', 'hf_62', 'hf_63', 'hf_64', 'hf_65', 'hf_66', 'hf_67', 'hf_68', 'hf_69', 'hf_70']
IMPS = ['0x00c811e0', '0x00c7b990', '0x00c86e4c', '0x00c7b5fc', '0x00c7b8a0', '0x00c81a44', '0x00c8122c', '0x00c82900', '0x00c8a1f8', '0x00c8a27c', '0x00c8a300', '0x00bac9a8', '0x00c89e3c', '0x00c89eec', '0x00c8a014', '0x00b9ffe4', '0x00c86e88', '0x00c7c0d0', '0x00c86ae4', '0x00c38e68', '0x00bed9ac', '0x00b8c9f8', '0x00b8ca78', '0x00b8cab8', '0x00c80b84', '0x00c83864', '0x00b9e9d4', '0x00c75410', '0x00b9111c', '0x00b9d0f8', '0x00c8a484', '0x00bac764', '0x00c83a54', '0x00c81e80', '0x00c7b4a0', '0x00c8a030', '0x00b91dec', '0x00c8a0d4', '0x00c80584', '0x00c01a98', '0x00b9d59c', '0x00bb7114', '0x00c8a154', '0x00c7bee4', '0x00c731c4', '0x00c7c224', '0x00c8a440', '0x00c8a230', '0x00c8a2b4', '0x00c8a338', '0x00c7b31c', '0x00bb91a8', '0x00c79494', '0x00c8a110', '0x00c8041c', '0x00c7bd30', '0x00c7922c', '0x00c89df0', '0x00bb01f0', '0x00c7b560', '0x00c8219c', '0x00c81750', '0x00ba0ed8', '0x00c83a90', '0x00b9dedc', '0x00baa488', '0x00c8a384', '0x00c81da4', '0x00c794d4', '0x00c730d0', '0x00c730e8']
COUNTS = {'hf_00': (0, 0, 0, 1, 0, 0), 'hf_01': (5, 1, 0, 2, 5, 4), 'hf_02': (0, 0, 0, 1, 0, 0), 'hf_03': (3, 1, 0, 7, 7, 11), 'hf_04': (1, 1, 0, 3, 2, 3), 'hf_05': (1, 1, 0, 6, 2, 10), 'hf_06': (2, 1, 0, 8, 10, 16), 'hf_07': (0, 0, 0, 2, 4, 3), 'hf_08': (0, 0, 0, 1, 0, 0), 'hf_09': (0, 0, 0, 1, 0, 0), 'hf_10': (0, 0, 0, 1, 0, 0), 'hf_11': (0, 0, 0, 1, 0, 0), 'hf_12': (1, 1, 0, 1, 2, 0), 'hf_13': (3, 0, 0, 4, 4, 0), 'hf_14': (0, 0, 0, 0, 0, 0), 'hf_15': (4, 2, 1, 36, 38, 3), 'hf_16': (0, 0, 0, 5, 5, 1), 'hf_17': (2, 1, 0, 3, 2, 3), 'hf_18': (7, 1, 0, 6, 8, 10), 'hf_19': (50, 8, 1, 83, 618, 111), 'hf_20': (49, 9, 0, 86, 620, 66), 'hf_21': (0, 0, 0, 1, 0, 0), 'hf_22': (0, 0, 0, 1, 0, 0), 'hf_23': (0, 0, 0, 1, 0, 0), 'hf_24': (2, 1, 0, 2, 5, 10), 'hf_25': (3, 1, 0, 7, 4, 0), 'hf_26': (1, 1, 0, 0, 1, 0), 'hf_27': (62, 28, 8, 27, 243, 141), 'hf_28': (7, 31, 3, 16, 35, 1), 'hf_29': (4, 2, 1, 17, 5, 4), 'hf_30': (0, 0, 0, 1, 0, 0), 'hf_31': (4, 2, 0, 3, 5, 8), 'hf_32': (0, 0, 0, 1, 0, 0), 'hf_33': (1, 1, 0, 4, 1, 3), 'hf_34': (1, 1, 0, 1, 1, 3), 'hf_35': (0, 0, 0, 1, 1, 0), 'hf_36': (0, 0, 0, 0, 0, 0), 'hf_37': (0, 0, 0, 1, 0, 0), 'hf_38': (0, 0, 0, 1, 0, 0), 'hf_39': (69, 18, 12, 197, 886, 906), 'hf_40': (3, 1, 1, 11, 4, 0), 'hf_41': (26, 5, 5, 44, 64, 79), 'hf_42': (0, 0, 0, 1, 1, 0), 'hf_43': (2, 1, 0, 6, 2, 6), 'hf_44': (1, 1, 0, 2, 1, 1), 'hf_45': (0, 0, 0, 4, 0, 3), 'hf_46': (0, 0, 0, 1, 0, 0), 'hf_47': (0, 0, 0, 1, 1, 0), 'hf_48': (0, 0, 0, 1, 1, 0), 'hf_49': (0, 0, 0, 1, 1, 0), 'hf_50': (2, 1, 0, 5, 2, 6), 'hf_51': (1, 1, 1, 0, 1, 0), 'hf_52': (0, 0, 0, 1, 0, 0), 'hf_53': (0, 0, 0, 1, 0, 0), 'hf_54': (1, 1, 0, 5, 3, 1), 'hf_55': (5, 1, 0, 2, 5, 1), 'hf_56': (2, 0, 0, 4, 5, 3), 'hf_57': (0, 0, 0, 1, 1, 0), 'hf_58': (7, 1, 0, 17, 22, 18), 'hf_59': (1, 1, 0, 1, 1, 1), 'hf_60': (3, 1, 0, 2, 22, 12), 'hf_61': (2, 0, 0, 11, 4, 2), 'hf_62': (1, 0, 0, 3, 1, 2), 'hf_63': (5, 2, 0, 34, 121, 127), 'hf_64': (11, 1, 1, 26, 18, 23), 'hf_65': (17, 8, 1, 12, 58, 84), 'hf_66': (0, 0, 0, 1, 0, 0), 'hf_67': (0, 0, 0, 3, 1, 3), 'hf_68': (0, 0, 0, 1, 0, 0), 'hf_69': (0, 0, 0, 0, 0, 0), 'hf_70': (0, 0, 0, 0, 0, 0)}
WORDS = [19, 111, 15, 169, 60, 165, 329, 75, 14, 14, 14, 15, 44, 74, 7, 614, 118, 85, 218, 17088, 17891, 16, 16, 16, 151, 124, 21, 3975, 816, 297, 15, 145, 15, 61, 48, 24, 7, 15, 15, 55344, 190, 1814, 24, 123, 49, 63, 17, 19, 19, 19, 97, 36, 16, 17, 90, 109, 154, 19, 523, 39, 291, 189, 66, 2644, 702, 1266, 15, 55, 15, 6, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 106952
    for needle in ('106952',
                   'preDrawUpdate',
                   '55,344',
                   '221 ivar',
                   'instanceStart'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_blockhead4():
    assert len(DATA['classes']) == 71
    s = BY['hf_39']['semantics']
    assert 'sinf' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_blockhead4()
    print('test_blockhead4_evidence: OK')
