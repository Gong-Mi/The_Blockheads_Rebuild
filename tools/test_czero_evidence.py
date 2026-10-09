#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CZERO.md').read_text()
DATA = json.loads((NATIVE / 'czero.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cz_00', 'cz_01', 'cz_02', 'cz_03', 'cz_04', 'cz_05', 'cz_06', 'cz_07', 'cz_08', 'cz_09', 'cz_10', 'cz_11', 'cz_12', 'cz_13', 'cz_14', 'cz_15', 'cz_16', 'cz_17', 'cz_18', 'cz_19', 'cz_20', 'cz_21', 'cz_22', 'cz_23', 'cz_24', 'cz_25', 'cz_26', 'cz_27', 'cz_28', 'cz_29', 'cz_30', 'cz_31', 'cz_32', 'cz_33', 'cz_34', 'cz_35', 'cz_36', 'cz_37', 'cz_38', 'cz_39', 'cz_40', 'cz_41', 'cz_42', 'cz_43', 'cz_44', 'cz_45', 'cz_46', 'cz_47', 'cz_48', 'cz_49', 'cz_50', 'cz_51', 'cz_52']
IMPS = ['0x00cc7690', '0x00bde520', '0x00b2bba0', '0x005f85a0', '0x00d92db0', '0x00be4600', '0x007c4860', '0x00d94218', '0x007c4e48', '0x006a4b18', '0x007c3a6c', '0x007c3f18', '0x0086915c', '0x007c37dc', '0x0096a4e8', '0x00c37b58', '0x00a15a74', '0x00a12434', '0x00a15c54', '0x00a178f8', '0x007c4290', '0x009176f8', '0x007c3e00', '0x00a137e8', '0x0096ab6c', '0x005effb8', '0x0096aa6c', '0x0096ad40', '0x0096ac78', '0x00a7ffd0', '0x00a159c8', '0x00a143d8', '0x0096ae10', '0x009fdf50', '0x00663254', '0x00a19820', '0x00a30e68', '0x00a12bd8', '0x007c4554', '0x00a1311c', '0x00a12b04', '0x00a31284', '0x00a19604', '0x00a19748', '0x00a196dc', '0x006689d0', '0x00bb4798', '0x00a3124c', '0x00ce8dd8', '0x00a31b44', '0x00a1295c', '0x00a12a30', '0x00a116dc']
COUNTS = {'cz_00': (2, 1997, 1, 0, 8, 7), 'cz_01': (11, 2, 0, 0, 410, 928), 'cz_02': (8, 232, 3, 0, 14, 3), 'cz_03': (13, 2, 0, 0, 77, 258), 'cz_04': (0, 0, 0, 0, 30, 2), 'cz_05': (2, 0, 0, 0, 51, 90), 'cz_06': (0, 0, 0, 0, 9, 13), 'cz_07': (0, 0, 0, 0, 2, 2), 'cz_08': (0, 0, 0, 0, 3, 0), 'cz_09': (0, 32, 0, 0, 0, 34), 'cz_10': (0, 0, 0, 0, 5, 3), 'cz_11': (0, 0, 0, 0, 0, 2), 'cz_12': (0, 0, 0, 0, 2, 14), 'cz_13': (0, 0, 0, 0, 3, 8), 'cz_14': (0, 0, 0, 0, 1, 11), 'cz_15': (0, 0, 0, 0, 11, 0), 'cz_16': (0, 0, 0, 0, 0, 32), 'cz_17': (0, 0, 0, 0, 0, 17), 'cz_18': (0, 0, 0, 0, 0, 30), 'cz_19': (0, 0, 0, 0, 3, 10), 'cz_20': (0, 0, 0, 0, 3, 0), 'cz_21': (0, 1, 0, 0, 7, 1), 'cz_22': (0, 0, 0, 0, 2, 0), 'cz_23': (0, 0, 0, 0, 0, 9), 'cz_24': (0, 0, 0, 0, 1, 1), 'cz_25': (0, 0, 0, 0, 4, 2), 'cz_26': (0, 0, 0, 0, 1, 1), 'cz_27': (0, 0, 0, 0, 1, 1), 'cz_28': (0, 0, 0, 0, 1, 1), 'cz_29': (1, 3, 1, 0, 2, 2), 'cz_30': (0, 0, 0, 0, 0, 11), 'cz_31': (0, 0, 0, 0, 1, 2), 'cz_32': (0, 0, 0, 0, 2, 0), 'cz_33': (0, 0, 0, 0, 0, 0), 'cz_34': (0, 0, 0, 0, 0, 0), 'cz_35': (0, 0, 0, 0, 20, 19), 'cz_36': (0, 0, 0, 0, 4, 66), 'cz_37': (4, 1, 0, 0, 6, 17), 'cz_38': (0, 0, 0, 0, 4, 0), 'cz_39': (0, 0, 0, 0, 2, 4), 'cz_40': (2, 0, 0, 0, 3, 5), 'cz_41': (0, 0, 0, 0, 1, 0), 'cz_42': (0, 0, 0, 0, 1, 3), 'cz_43': (0, 0, 0, 0, 1, 3), 'cz_44': (0, 0, 0, 0, 1, 3), 'cz_45': (0, 0, 0, 0, 0, 0), 'cz_46': (0, 0, 0, 0, 1, 0), 'cz_47': (0, 0, 0, 0, 1, 0), 'cz_48': (0, 0, 0, 0, 0, 0), 'cz_49': (3, 1, 0, 0, 6, 12), 'cz_50': (2, 0, 0, 0, 3, 5), 'cz_51': (2, 0, 0, 0, 3, 5), 'cz_52': (0, 0, 0, 0, 0, 5)}
WORDS = [17646, 6200, 1818, 1361, 1305, 904, 378, 314, 252, 246, 228, 222, 178, 164, 159, 121, 120, 117, 117, 89, 83, 72, 70, 69, 67, 67, 64, 52, 50, 49, 43, 30, 26, 6, 6, 251, 249, 211, 143, 62, 53, 33, 27, 27, 27, 25, 14, 14, 5, 152, 53, 53, 48]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 34140
    for needle in ('34140', 'blockheadNamesInit', 'checkCanEnterTile', '999999',
                   'init_by_array', 'tileContainsUsableDoor', 'genrand_res53'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_czero():
    assert len(DATA['classes']) == 53
    s = BY['cz_01']['semantics']
    assert '999999' in s and 'checkCanEnterTile' in s
    s = BY['cz_24']['semantics']
    assert '0x9908b0df' in s
    s = BY['cz_49']['semantics']
    assert 'needPhysicalBlock' in s
    s = BY['cz_23']['semantics']
    assert '0x5d' in s
    s = BY['cz_52']['semantics']
    assert 'swim' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_czero()
    print('test_czero_evidence: OK')
