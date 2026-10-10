#!/usr/bin/env python3
"""Contract test for the Window + SteamTrain smalls cluster (E71)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WINDOW_SMALLS.md').read_text()
DATA = json.loads((NATIVE / 'window_smalls.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['win_ctor_placed', 'win_ctor_net', 'win_creationdata', 'win_updatenet', 'win_draw',
         'win_setneedsremoved', 'win_dealloc', 'win_initsubderived', 'win_fbitemtype',
         'win_occupiesbg', 'st3_setwbchoice', 'st3_fuelcount', 'st3_fuelitemcount',
         'st3_fuelitems', 'st3_fueluipos', 'st3_needschoice', 'st3_setneedschoice',
         'st3_candismiss', 'st3_requiresfuel', 'st3_isengine', 'st3_maxriders',
         'st3_settargetvel']

IMPS = ['0x00c986a0', '0x00c98b70', '0x00c99094', '0x00c99040', '0x00c99568', '0x00c98538',
        '0x00c994a4', '0x00c984cc', '0x00c984fc', '0x00c99790', '0x00d2f8e4', '0x00d2fcd8',
        '0x00d2fda8', '0x00d2fdc4', '0x00d30504', '0x00d312f8', '0x00d31334', '0x00d304cc',
        '0x00d304e8', '0x00d3106c', '0x00d311dc', '0x00d2f8ac']

COUNTS = {
    'win_ctor_placed': (4, 2, 1, 2, 6, 6),
    'win_ctor_net': (8, 3, 1, 2, 10, 3),
    'win_creationdata': (6, 2, 2, 2, 9, 3),
    'win_updatenet': (1, 1, 0, 0, 1, 0),
    'win_draw': (0, 0, 0, 0, 0, 0),
    'win_setneedsremoved': (2, 1, 2, 2, 3, 1),
    'win_dealloc': (2, 2, 1, 1, 2, 0),
    'win_initsubderived': (0, 0, 0, 1, 0, 0),
    'win_fbitemtype': (0, 0, 0, 1, 0, 0),
    'win_occupiesbg': (0, 0, 0, 0, 0, 0),
    'st3_setwbchoice': (0, 0, 0, 8, 0, 4),
    'st3_fuelcount': (0, 0, 0, 1, 0, 4),
    'st3_fuelitemcount': (0, 0, 0, 0, 0, 0),
    'st3_fuelitems': (0, 0, 0, 0, 0, 0),
    'st3_fueluipos': (0, 0, 0, 1, 2, 0),
    'st3_needschoice': (0, 0, 0, 1, 0, 0),
    'st3_setneedschoice': (0, 0, 0, 1, 0, 0),
    'st3_candismiss': (0, 0, 0, 0, 0, 0),
    'st3_requiresfuel': (0, 0, 0, 0, 0, 0),
    'st3_isengine': (0, 0, 0, 0, 0, 0),
    'st3_maxriders': (0, 0, 0, 0, 0, 0),
    'st3_settargetvel': (0, 0, 0, 0, 0, 0),
}

WORDS = [169, 187, 169, 21, 138, 90, 49, 27, 15, 7, 125, 52, 19, 12, 31, 15, 17, 14, 7, 7, 7, 7]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1185
    for needle in ('1185', 'dmb ish', '0x20 (32)-byte', '16-byte frame alignment',
                   'tileAtWorldPositionLoaded', '4.0f', '31 = the window'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_window_facts():
    s = BY['win_initsubderived']['semantics']
    assert 'empty body' in s and '0x1f' in s
    s = BY['win_occupiesbg']['semantics']
    assert 'returns **1**' in s
    s = BY['win_creationdata']['semantics']
    assert '0x18 (24)-byte stret' in s and 'memcpy' in s
    s = BY['win_draw']['semantics']
    assert 'bic sp, sp, 0xf' in s and 'marshalling' in s


def test_train_facts():
    s = BY['st3_fuelitemcount']['semantics']
    assert '**4**' in s
    s = BY['st3_fueluipos']['semantics']
    assert '0x40800000' in s and '4.0f' in s
    s = BY['st3_setneedschoice']['semantics']
    assert 'dmb ish' in s
    s = BY['st3_settargetvel']['semantics']
    assert 'empty body' in s
    s = BY['st3_setwbchoice']['semantics']
    assert 'eor' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_window_facts()
    test_train_facts()
    print('test_winsmalls_evidence: OK')
