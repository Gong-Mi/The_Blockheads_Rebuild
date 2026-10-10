#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WATERLINE.md').read_text()
DATA = json.loads((NATIVE / 'waterline.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['aq_00', 'aq_01', 'aq_02', 'aq_03', 'aq_04', 'aq_05', 'aq_06', 'aq_07', 'aq_08', 'aq_09', 'aq_10', 'aq_11', 'aq_12', 'aq_13', 'aq_14', 'aq_15', 'aq_16', 'aq_17', 'aq_18', 'aq_19', 'aq_20', 'aq_21', 'aq_22', 'aq_23', 'aq_24', 'aq_25', 'aq_26', 'aq_27', 'aq_28', 'aq_29', 'aq_30', 'aq_31', 'aq_32', 'aq_33', 'aq_34', 'aq_35', 'aq_36', 'aq_37', 'aq_38', 'aq_39', 'aq_40', 'aq_41', 'aq_42']
IMPS = ['0x007e3a28', '0x007e4b6c', '0x007e5568', '0x007e5b10', '0x007e5eb0', '0x007e6a70', '0x007e6f48', '0x007e7990', '0x007e88a8', '0x007ea820', '0x007eb4e8', '0x007eb694', '0x007ebee0', '0x007ebf60', '0x007ebfa8', '0x007ebff4', '0x00582a50', '0x00582408', '0x00582488', '0x005d9ab0', '0x005d9b40', '0x00578430', '0x005c1ddc', '0x005da5c4', '0x0085c214', '0x008e0ad0', '0x00812184', '0x00812228', '0x008144a8', '0x0083b5f8', '0x008ee1f0', '0x00b8ca38', '0x00c8a540', '0x006ba1b4', '0x006d143c', '0x006ffc08', '0x00741978', '0x00770d2c', '0x009bc5f0', '0x00a65554', '0x00b50248', '0x00650a48', '0x00d85230']
COUNTS = {'aq_00': (18, 20, 7, 20, 63, 13), 'aq_01': (5, 16, 1, 8, 23, 10), 'aq_02': (11, 5, 4, 1, 27, 8), 'aq_03': (3, 2, 1, 13, 14, 1), 'aq_04': (0, 0, 0, 9, 6, 24), 'aq_05': (3, 1, 0, 5, 10, 16), 'aq_06': (4, 1, 0, 5, 21, 21), 'aq_07': (1, 1, 0, 6, 31, 37), 'aq_08': (18, 2, 0, 15, 93, 31), 'aq_09': (4, 1, 0, 4, 61, 11), 'aq_10': (1, 1, 0, 5, 4, 3), 'aq_11': (3, 1, 0, 5, 32, 17), 'aq_12': (0, 0, 0, 1, 1, 0), 'aq_13': (0, 0, 0, 1, 0, 0), 'aq_14': (0, 0, 0, 1, 0, 0), 'aq_15': (0, 0, 0, 0, 0, 0), 'aq_16': (1, 0, 0, 1, 1, 0), 'aq_17': (1, 0, 0, 0, 1, 0), 'aq_18': (2, 1, 0, 6, 8, 19), 'aq_19': (0, 0, 0, 1, 0, 0), 'aq_20': (0, 0, 0, 1, 0, 0), 'aq_21': (8, 1, 2, 3, 22, 23), 'aq_22': (2, 0, 1, 7, 31, 21), 'aq_23': (0, 0, 0, 1, 0, 0), 'aq_24': (1, 0, 0, 1, 9, 9), 'aq_25': (1, 1, 0, 4, 7, 32), 'aq_26': (1, 0, 0, 1, 1, 2), 'aq_27': (4, 0, 0, 6, 33, 31), 'aq_28': (3, 1, 0, 4, 11, 18), 'aq_29': (1, 1, 0, 0, 1, 0), 'aq_30': (5, 1, 1, 3, 6, 1), 'aq_31': (0, 0, 0, 1, 0, 0), 'aq_32': (0, 0, 0, 1, 0, 0), 'aq_33': (0, 0, 0, 0, 0, 0), 'aq_34': (0, 0, 0, 0, 0, 0), 'aq_35': (0, 0, 0, 0, 0, 0), 'aq_36': (0, 0, 0, 0, 0, 0), 'aq_37': (0, 0, 0, 0, 0, 0), 'aq_38': (0, 0, 0, 0, 0, 0), 'aq_39': (0, 0, 0, 0, 0, 0), 'aq_40': (0, 0, 0, 0, 0, 0), 'aq_41': (0, 0, 0, 0, 0, 0), 'aq_42': (0, 0, 0, 0, 0, 0)}
WORDS = [1101, 639, 362, 232, 752, 310, 658, 966, 1877, 818, 107, 531, 32, 18, 19, 6, 34, 32, 355, 18, 18, 380, 621, 15, 193, 560, 41, 691, 260, 21, 126, 16, 18, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 11897
    for needle in ('11897', 'getWeatherFractionForPos', 'sandFractionForPos',
                   'recursivelyFlowOutWaterFromTile', 'takeAnyWaterFromTileAtPos', 'waterChangedAtPos',
                   'windStrength', '0x1000', 'CaveTroll', 'snowChangedAtMacroPos'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_waterline():
    s = BY['aq_18']['semantics']
    assert 'sandFractionForPos' in s and 'noRainTimer' in s
    s = BY['aq_24']['semantics']
    assert 'byte2 == 1' in s and 'recursively' in BY['aq_24']['method']
    s = BY['aq_12']['semantics']
    assert '32' in s
    s = BY['aq_42']['semantics']
    assert 'CaveTroll' in s and 'false' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_Weather.windMovement' in symbols
    assert 'OBJC_IVAR_$_World.weatherFraction' in symbols
    assert 'OBJC_IVAR_$_DynamicWorld.waterChangedPositions' in symbols
    assert 'OBJC_IVAR_$_SurfaceBlock.removeNextFrameEmpty' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_waterline()
    print('test_waterline_evidence: OK')
