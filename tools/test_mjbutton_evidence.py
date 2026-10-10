#!/usr/bin/env python3
"""Contract test for MJButton (E138)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'MJBUTTON.md').read_text()
DATA = json.loads((NATIVE / 'mjbutton.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['mj_00', 'mj_01', 'mj_02', 'mj_03', 'mj_04', 'mj_05', 'mj_06', 'mj_07', 'mj_08', 'mj_09', 'mj_10', 'mj_11', 'mj_12', 'mj_13', 'mj_14', 'mj_15', 'mj_16', 'mj_17', 'mj_18', 'mj_19', 'mj_20', 'mj_21', 'mj_22', 'mj_23', 'mj_24', 'mj_25', 'mj_26', 'mj_27', 'mj_28', 'mj_29', 'mj_30', 'mj_31', 'mj_32', 'mj_33', 'mj_34', 'mj_35', 'mj_36', 'mj_37', 'mj_38', 'mj_39', 'mj_40', 'mj_41', 'mj_42', 'mj_43', 'mj_44', 'mj_45', 'mj_46', 'mj_47', 'mj_48', 'mj_49']
IMPS = ['0x00d17034', '0x00d16a7c', '0x00d169f4', '0x00d1696c', '0x00d168e4', '0x00d1611c', '0x00d10640', '0x00d1232c', '0x00d16e54', '0x00d16ed4', '0x00d16c94', '0x00d16d74', '0x00d16b04', '0x00d16b8c', '0x00d16c14', '0x00d11768', '0x00d11d7c', '0x00d12700', '0x00d16ab8', '0x00d16a30', '0x00d169a8', '0x00d16920', '0x00d1138c', '0x00d16e90', '0x00d10fc4', '0x00d15ae4', '0x00d16f34', '0x00d16cf4', '0x00d16dd4', '0x00d16b40', '0x00d15784', '0x00d16bc8', '0x00d15934', '0x00d12674', '0x00d15740', '0x00d16c50', '0x00d156fc', '0x00d16ff0', '0x00d1257c', '0x00d10c30', '0x00d10a08', '0x00d16748', '0x00d16498', '0x00d15f88', '0x00d16890', '0x00d16fb4', '0x00d10f88', '0x00d1670c', '0x00d15fdc', '0x00d1607c']
COUNTS = {'mj_00': (0, 0, 0, 0, 0, 0), 'mj_01': (0, 0, 0, 1, 0, 0), 'mj_02': (0, 0, 0, 1, 0, 0), 'mj_03': (0, 0, 0, 1, 0, 0), 'mj_04': (0, 0, 0, 1, 0, 0), 'mj_05': (3, 0, 2, 6, 4, 7), 'mj_06': (3, 0, 2, 6, 4, 7), 'mj_07': (2, 2, 1, 7, 8, 0), 'mj_08': (0, 0, 0, 1, 0, 0), 'mj_09': (0, 0, 0, 1, 1, 0), 'mj_10': (0, 0, 0, 1, 1, 0), 'mj_11': (0, 0, 0, 1, 1, 0), 'mj_12': (0, 0, 0, 1, 0, 0), 'mj_13': (0, 0, 0, 1, 0, 0), 'mj_14': (0, 0, 0, 1, 0, 0), 'mj_15': (6, 7, 2, 9, 9, 2), 'mj_16': (5, 7, 2, 8, 8, 2), 'mj_17': (15, 2, 2, 42, 68, 38), 'mj_18': (0, 0, 0, 1, 1, 0), 'mj_19': (0, 0, 0, 1, 1, 0), 'mj_20': (0, 0, 0, 1, 1, 0), 'mj_21': (0, 0, 0, 1, 1, 0), 'mj_22': (4, 1, 1, 6, 9, 5), 'mj_23': (0, 0, 0, 1, 0, 0), 'mj_24': (4, 2, 1, 4, 9, 8), 'mj_25': (1, 0, 1, 5, 7, 2), 'mj_26': (0, 0, 0, 1, 1, 0), 'mj_27': (0, 0, 0, 1, 1, 0), 'mj_28': (0, 0, 0, 1, 1, 0), 'mj_29': (0, 0, 0, 1, 1, 0), 'mj_30': (2, 1, 0, 6, 2, 0), 'mj_31': (0, 0, 0, 1, 1, 0), 'mj_32': (2, 1, 0, 6, 2, 0), 'mj_33': (1, 1, 1, 0, 1, 0), 'mj_34': (0, 0, 0, 1, 0, 0), 'mj_35': (0, 0, 0, 1, 0, 0), 'mj_36': (0, 0, 0, 1, 0, 0), 'mj_37': (0, 0, 0, 1, 0, 0), 'mj_38': (3, 1, 0, 2, 3, 0), 'mj_39': (4, 1, 0, 4, 8, 10), 'mj_40': (2, 1, 0, 4, 5, 4), 'mj_41': (2, 1, 0, 3, 3, 1), 'mj_42': (4, 1, 0, 2, 5, 7), 'mj_43': (0, 0, 0, 1, 0, 0), 'mj_44': (0, 0, 0, 1, 0, 0), 'mj_45': (0, 0, 0, 1, 0, 0), 'mj_46': (0, 0, 0, 1, 0, 0), 'mj_47': (0, 0, 0, 1, 0, 0), 'mj_48': (1, 0, 0, 1, 2, 2), 'mj_49': (1, 0, 0, 1, 2, 2)}
WORDS = [6, 15, 15, 15, 15, 223, 223, 148, 15, 24, 24, 24, 15, 15, 15, 389, 364, 2581, 19, 19, 19, 19, 247, 17, 242, 297, 32, 32, 32, 19, 108, 19, 108, 35, 17, 17, 17, 17, 62, 214, 119, 82, 157, 21, 21, 15, 15, 15, 40, 40]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 6259
    for needle in ('6259', 'render', 'E138'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_mjbutton():
    assert len(DATA['classes']) == 50
    s = BY['mj_00']['semantics']
    assert '0xd17034' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_mjbutton()
    print('test_mjbutton_evidence: OK')
