#!/usr/bin/env python3
"""Contract test for Shark (E140)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'SHARK.md').read_text()
DATA = json.loads((NATIVE / 'shark.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['sh_00', 'sh_01', 'sh_02', 'sh_03', 'sh_04', 'sh_05', 'sh_06', 'sh_07', 'sh_08', 'sh_09', 'sh_10', 'sh_11', 'sh_12', 'sh_13', 'sh_14', 'sh_15', 'sh_16', 'sh_17', 'sh_18', 'sh_19', 'sh_20', 'sh_21', 'sh_22', 'sh_23', 'sh_24', 'sh_25', 'sh_26', 'sh_27', 'sh_28', 'sh_29', 'sh_30', 'sh_31', 'sh_32', 'sh_33', 'sh_34', 'sh_35', 'sh_36', 'sh_37', 'sh_38', 'sh_39', 'sh_40', 'sh_41', 'sh_42', 'sh_43', 'sh_44', 'sh_45', 'sh_46']
IMPS = ['0x007ddac0', '0x007dd6d0', '0x007dd90c', '0x007dcee8', '0x007dd4dc', '0x007c72e8', '0x007c7404', '0x007c72cc', '0x007c72b0', '0x007dcd38', '0x007c90f0', '0x007c8e30', '0x007c91f8', '0x007d6154', '0x007c9d50', '0x007ca3e0', '0x007c7248', '0x007c7264', '0x007c7294', '0x007dca30', '0x007c83f8', '0x007c8a40', '0x007d62e4', '0x007dda6c', '0x007c76b0', '0x007c71b4', '0x007dc4a8', '0x007c71e4', '0x007dd8dc', '0x007dd320', '0x007c7198', '0x007dd088', '0x007dc93c', '0x007c946c', '0x007ca190', '0x007dd7d0', '0x007dccb4', '0x007dd5d8', '0x007dd540', '0x007ddaa4', '0x007dd398', '0x007dda88', '0x007dd584', '0x007c8cb0', '0x007c7218', '0x007dc4c4', '0x007c910c']
COUNTS = {'sh_00': (0, 0, 0, 2, 2, 0), 'sh_01': (1, 1, 1, 2, 2, 1), 'sh_02': (2, 1, 0, 3, 2, 3), 'sh_03': (2, 2, 1, 3, 3, 2), 'sh_04': (1, 0, 1, 0, 1, 0), 'sh_05': (2, 1, 0, 1, 2, 6), 'sh_06': (4, 4, 1, 1, 8, 8), 'sh_07': (0, 0, 0, 0, 0, 0), 'sh_08': (0, 0, 0, 0, 0, 0), 'sh_09': (2, 1, 0, 2, 5, 2), 'sh_10': (0, 0, 0, 0, 0, 0), 'sh_11': (5, 1, 1, 2, 8, 6), 'sh_12': (2, 2, 1, 9, 10, 0), 'sh_13': (4, 2, 2, 3, 4, 3), 'sh_14': (2, 1, 0, 10, 6, 8), 'sh_15': (17, 3, 1, 48, 241, 66), 'sh_16': (0, 0, 0, 0, 0, 0), 'sh_17': (0, 0, 0, 0, 0, 0), 'sh_18': (0, 0, 0, 0, 0, 0), 'sh_19': (2, 2, 1, 6, 3, 4), 'sh_20': (7, 1, 1, 3, 14, 13), 'sh_21': (3, 2, 1, 3, 3, 4), 'sh_22': (1, 1, 0, 2, 2, 4), 'sh_23': (0, 0, 0, 0, 0, 0), 'sh_24': (6, 17, 2, 27, 29, 5), 'sh_25': (0, 0, 0, 0, 0, 0), 'sh_26': (0, 0, 0, 0, 0, 0), 'sh_27': (0, 0, 0, 0, 0, 0), 'sh_28': (0, 0, 0, 0, 0, 0), 'sh_29': (0, 0, 0, 1, 2, 0), 'sh_30': (0, 0, 0, 0, 0, 0), 'sh_31': (4, 3, 2, 5, 8, 0), 'sh_32': (3, 1, 1, 2, 3, 1), 'sh_33': (13, 3, 2, 13, 19, 31), 'sh_34': (4, 2, 1, 4, 4, 5), 'sh_35': (1, 1, 1, 2, 2, 1), 'sh_36': (0, 0, 0, 2, 2, 0), 'sh_37': (0, 0, 0, 2, 2, 4), 'sh_38': (0, 0, 0, 1, 0, 0), 'sh_39': (0, 0, 0, 0, 0, 0), 'sh_40': (0, 0, 0, 2, 3, 2), 'sh_41': (0, 0, 0, 0, 0, 0), 'sh_42': (0, 0, 0, 1, 0, 0), 'sh_43': (1, 0, 0, 4, 2, 2), 'sh_44': (0, 1, 0, 0, 0, 0), 'sh_45': (1, 1, 0, 4, 18, 15), 'sh_46': (2, 1, 1, 0, 3, 2)}
WORDS = [31, 64, 88, 104, 25, 71, 171, 7, 7, 108, 7, 176, 157, 100, 272, 10618, 7, 12, 7, 161, 328, 125, 99, 7, 845, 12, 7, 13, 12, 30, 7, 166, 61, 569, 148, 67, 33, 62, 17, 7, 81, 7, 21, 96, 12, 286, 59]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 15370
    for needle in ('15370', 'Shark', 'update', 'render'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_shark():
    assert len(DATA['classes']) == 47
    s = BY['sh_00']['semantics']
    assert '0x7ddac0' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_shark()
    print('test_shark_evidence: OK')
