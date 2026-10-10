#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'HEATLINE.md').read_text()
DATA = json.loads((NATIVE / 'heatline.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['hl_00', 'hl_01', 'hl_02', 'hl_03', 'hl_04', 'hl_05', 'hl_06', 'hl_07', 'hl_08', 'hl_09', 'hl_10', 'hl_11', 'hl_12', 'hl_13', 'hl_14', 'hl_15', 'hl_16', 'hl_17', 'hl_18', 'hl_19', 'hl_20', 'hl_21', 'hl_22', 'hl_23', 'hl_24', 'hl_25', 'hl_26', 'hl_27', 'hl_28', 'hl_29', 'hl_30', 'hl_31', 'hl_32', 'hl_33', 'hl_34', 'hl_35', 'hl_36', 'hl_37', 'hl_38', 'hl_39', 'hl_40', 'hl_41', 'hl_42', 'hl_43', 'hl_44', 'hl_45', 'hl_46', 'hl_47', 'hl_48', 'hl_49']
IMPS = ['0x0067440c', '0x00674688', '0x006746a4', '0x00674704', '0x00674af4', '0x00674f00', '0x0067501c', '0x006753ec', '0x00675440', '0x00675560', '0x00675648', '0x00675730', '0x00675cd4', '0x00675d30', '0x00676800', '0x00679a48', '0x00679ab4', '0x00a8f22c', '0x00a92238', '0x00a93198', '0x00a93728', '0x00a93744', '0x00a93bbc', '0x00a93c64', '0x00a942d4', '0x00a947ac', '0x00a94898', '0x00a9519c', '0x00a95248', '0x00a958bc', '0x00ca8304', '0x00ca8318', '0x00ca8334', '0x00ca83d4', '0x00ca8920', '0x00ca8c78', '0x00ca8e64', '0x00ca8f4c', '0x00ca90bc', '0x00ca93ac', '0x00ca9500', '0x00ca955c', '0x00ca960c', '0x00a140ec', '0x00a14180', '0x00a14f28', '0x00a15404', '0x00a14ba0', '0x00a14d98', '0x00a14a48']
COUNTS = {'hl_00': (3, 7, 1, 4, 6, 0), 'hl_01': (0, 0, 0, 0, 0, 0), 'hl_02': (0, 0, 0, 0, 1, 0), 'hl_03': (5, 1, 2, 7, 11, 2), 'hl_04': (7, 8, 2, 7, 17, 2), 'hl_05': (2, 2, 1, 0, 2, 2), 'hl_06': (3, 8, 2, 3, 13, 1), 'hl_07': (1, 1, 0, 0, 1, 0), 'hl_08': (2, 1, 1, 0, 4, 2), 'hl_09': (2, 2, 1, 1, 2, 0), 'hl_10': (2, 2, 1, 1, 2, 1), 'hl_11': (12, 2, 1, 4, 18, 14), 'hl_12': (0, 0, 0, 1, 0, 2), 'hl_13': (5, 0, 0, 8, 33, 24), 'hl_14': (9, 2, 0, 9, 69, 25), 'hl_15': (1, 1, 0, 1, 1, 0), 'hl_16': (1, 1, 0, 1, 1, 0), 'hl_17': (3, 2, 0, 13, 76, 241), 'hl_18': (8, 0, 0, 11, 38, 78), 'hl_19': (3, 1, 0, 6, 8, 14), 'hl_20': (0, 0, 0, 0, 0, 0), 'hl_21': (4, 1, 1, 13, 7, 4), 'hl_22': (0, 0, 0, 3, 1, 0), 'hl_23': (7, 11, 1, 11, 24, 5), 'hl_24': (3, 10, 2, 7, 17, 0), 'hl_25': (2, 2, 1, 2, 4, 0), 'hl_26': (3, 1, 0, 7, 16, 25), 'hl_27': (2, 2, 1, 0, 2, 0), 'hl_28': (3, 1, 0, 5, 17, 12), 'hl_29': (0, 0, 0, 0, 0, 0), 'hl_30': (0, 0, 0, 0, 0, 0), 'hl_31': (0, 0, 0, 0, 0, 0), 'hl_32': (1, 0, 0, 1, 2, 2), 'hl_33': (5, 1, 2, 6, 6, 25), 'hl_34': (7, 4, 2, 6, 10, 3), 'hl_35': (3, 4, 2, 2, 5, 1), 'hl_36': (2, 2, 1, 1, 2, 0), 'hl_37': (3, 1, 1, 3, 5, 0), 'hl_38': (2, 1, 0, 4, 3, 7), 'hl_39': (3, 1, 1, 3, 4, 1), 'hl_40': (0, 0, 0, 1, 0, 2), 'hl_41': (0, 0, 0, 1, 3, 0), 'hl_42': (1, 1, 0, 1, 1, 0), 'hl_43': (0, 0, 0, 0, 0, 4), 'hl_44': (3, 1, 0, 0, 8, 11), 'hl_45': (1, 1, 0, 0, 5, 3), 'hl_46': (0, 0, 0, 0, 1, 0), 'hl_47': (1, 1, 0, 0, 5, 14), 'hl_48': (1, 1, 0, 0, 5, 12), 'hl_49': (1, 0, 0, 0, 5, 3)}
WORDS = [155, 7, 24, 252, 259, 71, 244, 21, 72, 58, 58, 361, 23, 692, 2268, 27, 29, 2753, 970, 356, 7, 286, 42, 412, 310, 59, 577, 43, 413, 6, 5, 7, 40, 339, 214, 123, 58, 92, 188, 85, 23, 44, 29, 37, 123, 170, 69, 126, 99, 86]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 12812
    for needle in ('12812', 'burnTimer', 'spreadTimers', 'placeFireAtPosition',
                   'tileIsBurnable', 'maxHeat', 'contributionGrid', '37.0', '45.0',
                   'artificialHeat', 'seasonForWorldX', '0xAA'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_heatline():
    s = BY['hl_47']['semantics']
    assert '37.0' in s and '45.0' in s
    s = BY['hl_46']['semantics']
    assert 'artificialHeat' in s and 'sunLight' in s
    s = BY['hl_43']['semantics']
    assert '0x15' in s
    s = BY['hl_13']['semantics']
    assert 'placeFireAtPosition' in s and 'burnTimer' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_FireObject.burnTimer' in symbols
    assert 'OBJC_IVAR_$_FireObject.spreadTimers' in symbols
    assert 'OBJC_IVAR_$_ArtificialLight.maxHeat' in symbols
    assert 'OBJC_IVAR_$_GlowBlock.tileType' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_heatline()
    print('test_heatline_evidence: OK')
