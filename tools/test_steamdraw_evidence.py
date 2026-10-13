#!/usr/bin/env python3
"""Contract test for the SteamTrain remainder (E74)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'STEAMTRAIN_CLOSE.md').read_text()
DATA = json.loads((NATIVE / 'steamtrain_close.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['st4_draw', 'st4_update', 'st4_ctor_save', 'st4_getsavedict', 'st4_title',
         'st4_actiontitle', 'st4_secondtitle', 'st4_itemtype', 'st4_objecttype',
         'st4_cxx_construct']

IMPS = ['0x00d20d20', '0x00d1bab8', '0x00d18834', '0x00d18e84', '0x00d2fca8', '0x00d2fad8',
        '0x00d2fbc0', '0x00d2f8c8', '0x00d17e7c', '0x00d31378']

COUNTS = {
    'st4_draw': (29, 5, 2, 34, 296, 63),
    'st4_update': (29, 4, 1, 54, 258, 187),
    'st4_ctor_save': (4, 6, 1, 4, 9, 2),
    'st4_getsavedict': (4, 6, 2, 4, 9, 0),
    'st4_title': (0, 1, 0, 0, 0, 0),
    'st4_actiontitle': (1, 3, 1, 1, 1, 2),
    'st4_secondtitle': (1, 3, 1, 1, 1, 2),
    'st4_itemtype': (0, 0, 0, 0, 0, 0),
    'st4_objecttype': (0, 0, 0, 0, 0, 0),
    'st4_cxx_construct': (0, 0, 0, 0, 0, 0),
}

WORDS = [13137, 4826, 180, 193, 12, 58, 58, 7, 7, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 18484
    for needle in ('18484', 'drawShaderQuad', 'fmodf', 'tileIsWater', '205', '42',
                   '8-point track probe'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_giants():
    s = BY['st4_draw']['semantics']
    for needle in ('13137', '20x glUniformMatrix4fv', 'drawShaderQuad', '95 objc_msgSend', 'atan2f'):
        assert needle in s, needle
    s = BY['st4_update']['semantics']
    for needle in ('Vector2', 'fmodf', 'tileIsWater', '1.8'):
        assert needle in s, needle


def test_pins():
    s = BY['st4_itemtype']['semantics']
    assert '0xcd (205)' in s and 'fuel' in s
    s = BY['st4_objecttype']['semantics']
    assert '0x2a (42)' in s
    s = BY['st4_actiontitle']['semantics']
    assert 'fffffce8' in s
    s = BY['st4_cxx_construct']['semantics']
    assert 'empty' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_giants()
    test_pins()
    print('test_steamdraw_evidence: OK')
