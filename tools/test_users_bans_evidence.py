#!/usr/bin/env python3
"""Contract test for the DynamicWorld users/bans/session smalls (E33)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'USERS_BANS.md').read_text()
DATA = json.loads((NATIVE / 'users_bans.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_usermutechanged_', 'wtl_userbanchanged_isbanne', 'wtl_playerisbannedwithid_',
         'wtl_playerschanged', 'wtl_getownernameforobjecto', 'wtl_iscontrollingblockhead',
         'wtl_remotepickuprequestrep', 'wtl_blockheadwithuniqueid_', 'wtl_loaddebugchestatpos_ch']

IMPS = ['0x009023f4', '0x009025e4', '0x0090280c', '0x009028c8', '0x00902ac0', '0x008fdbf0',
        '0x008f722c', '0x008f7000', '0x009067e0']

COUNTS = {
    'wtl_usermutechanged_': (1, 1, 0, 1, 2, 2),
    'wtl_userbanchanged_isbanne': (1, 1, 0, 2, 2, 4),
    'wtl_playerisbannedwithid_': (1, 1, 0, 1, 1, 2),
    'wtl_playerschanged': (2, 1, 0, 1, 5, 5),
    'wtl_getownernameforobjecto': (1, 1, 0, 1, 1, 0),
    'wtl_iscontrollingblockhead': (4, 1, 0, 2, 7, 10),
    'wtl_remotepickuprequestrep': (5, 2, 0, 0, 7, 2),
    'wtl_blockheadwithuniqueid_': (2, 1, 0, 1, 5, 9),
    'wtl_loaddebugchestatpos_ch': (3, 1, 0, 3, 7, 0),
}

WORDS = [124, 138, 47, 126, 27, 175, 127, 139, 110]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1013
    for needle in ('1013', '0x270', 'ffffe51c', 'ffffe4f8', 'ffffe5ac', 'eor/orr',
                   'VLA', 'setPaused:'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_user_family():
    s = BY['wtl_usermutechanged_']['semantics']
    for needle in ('0x270', 'ffe237a8', '__tree_next'):
        assert needle in s, needle
    s = BY['wtl_userbanchanged_isbanne']['semantics']
    for needle in ('ffffe51c', 'ffe237ac', 'sxtb'):
        assert needle in s, needle
    s = BY['wtl_blockheadwithuniqueid_']['semantics']
    for needle in ('ffffe4f8', 'eor', 'orr', 'ffe2332c'):
        assert needle in s, needle


def test_pickup_and_chest():
    s = BY['wtl_remotepickuprequestrep']['semantics']
    for needle in ('0x10', 'bfc r0, 0, 3', 'mov sp, r0', 'ffe236e4'):
        assert needle in s, needle
    s = BY['wtl_loaddebugchestatpos_ch']['semantics']
    for needle in ('ffffe550', 'ffffe554', 'ffe232a0', 'worldIndexAtWorldPos'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_user_family()
    test_pickup_and_chest()
    print('test_users_bans_evidence: OK')
