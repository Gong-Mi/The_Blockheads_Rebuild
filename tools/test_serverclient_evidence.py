#!/usr/bin/env python3
"""Contract test for ServerClient (E150)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'SERVERCLIENT.md').read_text()
DATA = json.loads((NATIVE / 'serverclient.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['svc_00', 'svc_01', 'svc_02', 'svc_03', 'svc_04', 'svc_05', 'svc_06', 'svc_07', 'svc_08', 'svc_09', 'svc_10', 'svc_11', 'svc_12', 'svc_13', 'svc_14', 'svc_15', 'svc_16', 'svc_17', 'svc_18', 'svc_19', 'svc_20', 'svc_21', 'svc_22', 'svc_23', 'svc_24', 'svc_25', 'svc_26', 'svc_27', 'svc_28', 'svc_29', 'svc_30', 'svc_31', 'svc_32', 'svc_33', 'svc_34', 'svc_35', 'svc_36', 'svc_37', 'svc_38', 'svc_39', 'svc_40', 'svc_41']
IMPS = ['0x00d0bc64', '0x00d0bbec', '0x00d090f8', '0x00d08c8c', '0x00d0af10', '0x00d093e4', '0x00d091fc', '0x00d0bba8', '0x00d08944', '0x00d088d4', '0x00d08ad8', '0x00d0b804', '0x00d07870', '0x00d0b704', '0x00d08a68', '0x00d07f5c', '0x00d08b44', '0x00d0bb64', '0x00d0afd0', '0x00d0b98c', '0x00d06a80', '0x00d0b848', '0x00d0baa0', '0x00d0b784', '0x00d089b4', '0x00d083ac', '0x00d0b740', '0x00d0b90c', '0x00d0b3bc', '0x00d09ec0', '0x00d0b654', '0x00d0b9c8', '0x00d0b884', '0x00d0b7c0', '0x00d0b948', '0x00d0ba54', '0x00d0bb20', '0x00d0ba0c', '0x00d08c20', '0x00d08bb4', '0x00d0b8c8', '0x00d0badc']
COUNTS = {'svc_00': (0, 0, 0, 1, 1, 0), 'svc_01': (0, 0, 0, 1, 2, 0), 'svc_02': (3, 1, 1, 1, 3, 0), 'svc_03': (9, 1, 2, 2, 14, 8), 'svc_04': (2, 1, 1, 1, 2, 0), 'svc_05': (9, 1, 2, 4, 36, 24), 'svc_06': (3, 1, 1, 2, 6, 2), 'svc_07': (0, 0, 0, 1, 0, 0), 'svc_08': (0, 0, 0, 1, 1, 0), 'svc_09': (1, 1, 0, 1, 1, 0), 'svc_10': (1, 1, 0, 1, 1, 0), 'svc_11': (0, 0, 0, 1, 0, 0), 'svc_12': (8, 2, 2, 13, 27, 2), 'svc_13': (0, 0, 0, 1, 0, 0), 'svc_14': (0, 0, 0, 1, 1, 0), 'svc_15': (2, 2, 1, 12, 17, 5), 'svc_16': (1, 1, 0, 1, 1, 0), 'svc_17': (0, 0, 0, 1, 0, 0), 'svc_18': (7, 1, 1, 1, 15, 10), 'svc_19': (0, 0, 0, 1, 0, 0), 'svc_20': (17, 5, 7, 18, 57, 6), 'svc_21': (0, 0, 0, 1, 0, 0), 'svc_22': (0, 0, 0, 1, 0, 0), 'svc_23': (0, 0, 0, 1, 0, 0), 'svc_24': (1, 1, 0, 2, 2, 0), 'svc_25': (1, 1, 0, 3, 4, 1), 'svc_26': (0, 0, 0, 1, 0, 0), 'svc_27': (0, 0, 0, 1, 0, 0), 'svc_28': (8, 3, 3, 3, 8, 0), 'svc_29': (10, 1, 3, 8, 55, 10), 'svc_30': (1, 1, 0, 1, 1, 1), 'svc_31': (0, 0, 0, 1, 0, 0), 'svc_32': (0, 0, 0, 1, 0, 0), 'svc_33': (0, 0, 0, 1, 0, 0), 'svc_34': (0, 0, 0, 1, 0, 0), 'svc_35': (0, 0, 0, 1, 0, 0), 'svc_36': (0, 0, 0, 1, 0, 0), 'svc_37': (0, 0, 0, 1, 0, 0), 'svc_38': (1, 1, 0, 1, 1, 0), 'svc_39': (1, 1, 0, 1, 1, 0), 'svc_40': (0, 0, 0, 1, 0, 0), 'svc_41': (0, 0, 0, 1, 0, 0)}
WORDS = [27, 30, 65, 283, 48, 695, 122, 17, 28, 28, 27, 17, 443, 15, 28, 252, 28, 17, 251, 15, 892, 15, 15, 15, 45, 90, 17, 15, 166, 953, 44, 17, 17, 17, 17, 19, 17, 18, 27, 27, 17, 17]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 4913
    for needle in ('4913', 'ServerClient', 'queue', 'gzip'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_serverclient():
    assert len(DATA['classes']) == 42
    s = BY['svc_00']['semantics']
    assert '0xd0bc64' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_serverclient()
    print('test_serverclient_evidence: OK')
