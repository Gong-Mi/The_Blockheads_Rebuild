#!/usr/bin/env python3
"""Contract test for the DynamicWorld load/session smalls (E31)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'LOAD_SESSION.md').read_text()
DATA = json.loads((NATIVE / 'load_session.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_stopallblockheadaction', 'wtl_newfoundlistrecievedfr', 'wtl_appenddebuglog_',
         'wtl_explorelightchangedatm', 'wtl_loadlocalinventorydata', 'wtl_ridableobjectwithid_',
         'wtl_loadstandarddynamicobj']

IMPS = ['0x008f8108', '0x008fad90', '0x00902b2c', '0x008e17ac', '0x008b8fc4', '0x008f8fcc', '0x008e6250']

COUNTS = {
    'wtl_stopallblockheadaction': (4, 1, 0, 2, 14, 14),
    'wtl_newfoundlistrecievedfr': (12, 3, 3, 2, 16, 1),
    'wtl_appenddebuglog_': (3, 6, 0, 4, 10, 4),
    'wtl_explorelightchangedatm': (1, 0, 0, 1, 2, 14),
    'wtl_loadlocalinventorydata': (7, 2, 2, 3, 12, 10),
    'wtl_ridableobjectwithid_': (1, 0, 0, 1, 15, 14),
    'wtl_loadstandarddynamicobj': (4, 1, 0, 4, 11, 9),
}

WORDS = [294, 246, 245, 239, 222, 216, 209]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1671
    for needle in ('1671', 'netBlockheads', 'serverClients', 'dynamicObjects',
                   '0x150', '0x2f4', '0x264', 'objectTypeHasStaticPosition',
                   'classForDynamicObjectType', 'NSStringFromClass'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_ridable_and_standard():
    s = BY['wtl_ridableobjectwithid_']['semantics']
    for needle in ('0x150', '0x2f4', '0x9c', '0x264', '0x1d4', '__count_unique', 'operator[]'):
        assert needle in s, needle
    s = BY['wtl_loadstandarddynamicobj']['semantics']
    for needle in ('objectTypeHasStaticPosition', 'classForDynamicObjectType', 'ffffe554', 'ffe234ac', 'ffffe550'):
        assert needle in s, needle


def test_session_and_log():
    s = BY['wtl_stopallblockheadaction']['semantics']
    for needle in ('ffffe4f4', 'ffe23444', 'ffe236ec'):
        assert needle in s, needle
    s = BY['wtl_appenddebuglog_']['semantics']
    for needle in ('0x41', '12-byte', 'NSStringFromClass', '0xfff34234'):
        assert needle in s, needle
    s = BY['wtl_explorelightchangedatm']['semantics']
    for needle in ('cmn r0, 1', 'ffffe56c', '0xc'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_ridable_and_standard()
    test_session_and_log()
    print('test_load_session_evidence: OK')
