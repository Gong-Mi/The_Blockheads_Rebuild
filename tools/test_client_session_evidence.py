#!/usr/bin/env python3
"""Contract test for the DynamicWorld client-request/session cluster (E28)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CLIENT_SESSION.md').read_text()
DATA = json.loads((NATIVE / 'client_session.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_initwithworld_worldtil', 'wtl_checkforharmabledynami', 'wtl_clientblockheadwithid_',
         'wtl_sendlightblockstoclien', 'wtl_clientpickuprequest_co', 'wtl_sendchestinventoryforc']

IMPS = ['0x008ac884', '0x008f1acc', '0x00905308', '0x008b1dd4', '0x008f6954', '0x00901b58']

COUNTS = {
    'wtl_initwithworld_worldtil': (10, 3, 7, 21, 25, 6),
    'wtl_checkforharmabledynami': (13, 1, 1, 3, 24, 36),
    'wtl_clientblockheadwithid_': (16, 1, 0, 3, 22, 32),
    'wtl_sendlightblockstoclien': (2, 1, 0, 4, 5, 22),
    'wtl_clientpickuprequest_co': (8, 2, 2, 2, 15, 17),
    'wtl_sendchestinventoryforc': (14, 1, 2, 2, 19, 16),
}

WORDS = [648, 586, 521, 478, 427, 387]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 3047
    for needle in ('3047', '512', 'ffffe530', '0x00E4AA1C', '0x00E18104', '0x20', '0x8ad2a4',
                   'ffe2349c', 'ffe23600', 'clientID'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_ctor_and_harmable():
    s = BY['wtl_initwithworld_worldtil']['semantics']
    for needle in ('0xe', 'NSSearchPathForDirectoriesInDomains', '0x200 (512)', 'ffffe530',
                   '0x8ad2a4', 'uint16'):
        assert needle in s, needle
    s = BY['wtl_checkforharmabledynami']['semantics']
    for needle in ('cmp r0, 8', '0x00E4AA1C', 'ffe23664', 'ffe23694', 'addObject:'):
        assert needle in s, needle


def test_session_bodies():
    s = BY['wtl_clientblockheadwithid_']['semantics']
    for needle in ('0x41 (65)', 'ffffe54c', 'ffffe550', 'uniqueID', 'ffe234ac'):
        assert needle in s, needle
    s = BY['wtl_sendlightblockstoclien']['semantics']
    for needle in ('0x20', 'ffffe56c', 'macroTileAtMacroPostion', 'ffffe570', 'ffffe574'):
        assert needle in s, needle
    s = BY['wtl_clientpickuprequest_co']['semantics']
    for needle in ('lsl 3', '8-byte', 'ffe2349c', '0x00E18104', '__count_unique', 'ffe23600'):
        assert needle in s, needle
    s = BY['wtl_sendchestinventoryforc']['semantics']
    for needle in ('ffffe4f4', 'uniqueID', 'ffe23444', 'ffe23390', '5'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_ctor_and_harmable()
    test_session_bodies()
    print('test_client_session_evidence: OK')
