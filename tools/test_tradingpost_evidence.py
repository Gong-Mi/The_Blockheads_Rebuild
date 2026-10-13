#!/usr/bin/env python3
"""Contract test for TradingPost (E151)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TRADINGPOST.md').read_text()
DATA = json.loads((NATIVE / 'tradingpost.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['tp_00', 'tp_01', 'tp_02', 'tp_03', 'tp_04', 'tp_05', 'tp_06', 'tp_07', 'tp_08', 'tp_09', 'tp_10', 'tp_11', 'tp_12', 'tp_13', 'tp_14', 'tp_15', 'tp_16', 'tp_17', 'tp_18', 'tp_19', 'tp_20', 'tp_21', 'tp_22', 'tp_23', 'tp_24', 'tp_25', 'tp_26', 'tp_27', 'tp_28', 'tp_29', 'tp_30', 'tp_31', 'tp_32', 'tp_33', 'tp_34', 'tp_35', 'tp_36', 'tp_37', 'tp_38', 'tp_39', 'tp_40', 'tp_41', 'tp_42', 'tp_43', 'tp_44', 'tp_45']
IMPS = ['0x005edb38', '0x005f2224', '0x005eeb18', '0x005f0f9c', '0x005f0908', '0x005edc08', '0x005ee238', '0x005f2a10', '0x005ebbe4', '0x005e6938', '0x005ee188', '0x005e69ac', '0x005edaec', '0x005e7748', '0x005ed76c', '0x005ed788', '0x005ed720', '0x005ed704', '0x005e4ce0', '0x005e52bc', '0x005e5a94', '0x005e7024', '0x005f2834', '0x005f2994', '0x005ea85c', '0x005f29b0', '0x005f2850', '0x005ede48', '0x005edeb4', '0x005e7040', '0x005ed7a4', '0x005f25e8', '0x005edbec', '0x005f29cc', '0x005ee8b0', '0x005f2a4c', '0x005edef0', '0x005f20e0', '0x005ee9fc', '0x005f0cdc', '0x005f08e4', '0x005edb08', '0x005ebf70', '0x005e60c8', '0x005ece18', '0x005ed6ec']
COUNTS = {'tp_00': (2, 2, 1, 0, 2, 0), 'tp_01': (4, 1, 0, 3, 9, 4), 'tp_02': (9, 3, 2, 8, 32, 7), 'tp_03': (6, 1, 0, 6, 19, 11), 'tp_04': (0, 0, 0, 3, 8, 1), 'tp_05': (4, 2, 0, 2, 5, 10), 'tp_06': (15, 8, 1, 9, 21, 8), 'tp_07': (0, 0, 0, 1, 0, 0), 'tp_08': (3, 0, 0, 6, 10, 0), 'tp_09': (1, 1, 0, 1, 1, 0), 'tp_10': (1, 1, 0, 1, 1, 2), 'tp_11': (2, 2, 1, 3, 4, 0), 'tp_12': (0, 0, 0, 0, 0, 0), 'tp_13': (16, 2, 0, 8, 90, 34), 'tp_14': (0, 0, 0, 0, 0, 0), 'tp_15': (0, 0, 0, 0, 0, 0), 'tp_16': (1, 1, 0, 0, 1, 0), 'tp_17': (0, 0, 0, 0, 0, 0), 'tp_18': (8, 10, 1, 7, 19, 1), 'tp_19': (6, 5, 1, 4, 12, 5), 'tp_20': (12, 5, 1, 6, 20, 7), 'tp_21': (0, 0, 0, 0, 0, 0), 'tp_22': (0, 0, 0, 0, 0, 0), 'tp_23': (0, 0, 0, 0, 0, 0), 'tp_24': (21, 4, 1, 5, 75, 52), 'tp_25': (0, 0, 0, 0, 0, 0), 'tp_26': (3, 1, 0, 5, 3, 1), 'tp_27': (0, 0, 0, 1, 0, 0), 'tp_28': (0, 0, 0, 1, 0, 0), 'tp_29': (11, 6, 1, 12, 27, 5), 'tp_30': (6, 1, 0, 9, 6, 9), 'tp_31': (2, 1, 1, 2, 9, 0), 'tp_32': (0, 0, 0, 0, 0, 0), 'tp_33': (0, 0, 0, 1, 0, 0), 'tp_34': (2, 2, 1, 1, 3, 2), 'tp_35': (0, 0, 0, 1, 0, 0), 'tp_36': (3, 0, 0, 5, 10, 0), 'tp_37': (4, 1, 0, 1, 4, 4), 'tp_38': (3, 1, 0, 1, 4, 3), 'tp_39': (6, 1, 0, 4, 9, 7), 'tp_40': (0, 0, 0, 0, 0, 0), 'tp_41': (0, 1, 0, 0, 0, 0), 'tp_42': (7, 2, 2, 6, 15, 7), 'tp_43': (11, 5, 3, 7, 20, 14), 'tp_44': (2, 1, 0, 3, 25, 34), 'tp_45': (0, 0, 0, 0, 0, 0)}
WORDS = [45, 241, 1291, 514, 245, 144, 414, 15, 173, 29, 44, 87, 7, 2111, 7, 7, 19, 7, 375, 279, 388, 7, 7, 7, 1250, 7, 81, 27, 15, 450, 210, 147, 7, 17, 83, 17, 166, 81, 71, 156, 9, 12, 302, 449, 550, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 10576
    for needle in ('10576', 'TradingPost', 'priceTier', 'coinCount'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_tradingpost():
    assert len(DATA['classes']) == 46
    s = BY['tp_00']['semantics']
    assert '0x5edb38' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_tradingpost()
    print('test_tradingpost_evidence: OK')
