#!/usr/bin/env python3
"""Contract test for the World input router batch (E104)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_INPUT.md').read_text()
DATA = json.loads((NATIVE / 'world_input.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wi_00', 'wi_01', 'wi_02', 'wi_03', 'wi_04', 'wi_05', 'wi_06', 'wi_07', 'wi_08', 'wi_09', 'wi_10', 'wi_11', 'wi_12', 'wi_13', 'wi_14', 'wi_15', 'wi_16']
IMPS = ['0x005ac3a0', '0x00552e28', '0x00552ec0', '0x005531d0', '0x005536a4', '0x005b30c8', '0x005b3278', '0x005b3308', '0x005b33ac', '0x005b3430', '0x005b34b4', '0x005bf968', '0x005bf9f8', '0x005bf880', '0x005bfb5c', '0x005bfc14', '0x005b3540']
COUNTS = {'wi_00': (82, 13, 6, 26, 353, 363), 'wi_01': (0, 0, 0, 3, 0, 0), 'wi_02': (1, 0, 0, 5, 14, 2), 'wi_03': (2, 0, 1, 5, 18, 8), 'wi_04': (0, 0, 0, 1, 0, 0), 'wi_05': (2, 1, 0, 1, 2, 4), 'wi_06': (1, 0, 0, 1, 1, 0), 'wi_07': (1, 0, 0, 1, 1, 0), 'wi_08': (1, 0, 0, 0, 1, 0), 'wi_09': (1, 0, 0, 0, 1, 0), 'wi_10': (2, 1, 0, 1, 2, 0), 'wi_11': (2, 1, 0, 1, 2, 0), 'wi_12': (3, 1, 0, 1, 4, 2), 'wi_13': (2, 1, 0, 2, 2, 1), 'wi_14': (3, 1, 0, 1, 3, 0), 'wi_15': (3, 0, 0, 1, 3, 0), 'wi_16': (1, 1, 0, 2, 2, 2)}
WORDS = [6150, 38, 196, 309, 18, 60, 36, 41, 33, 33, 35, 36, 89, 58, 46, 39, 65]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 7282
    for needle in ('7282', '6150', 'makeIntpair', 'GLKMathUnproject', 'linearInterpolate',
                   '0x3ccdcccd', 'setListenerPosition', 'panBlockingUIDisplayed',
                   'fishingRod', 'touchStartTranslation'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_input():
    s = BY['wi_00']['semantics']
    assert 'objc_msgSend x99' in s
    s = BY['wi_03']['semantics']
    assert '__wrap_fmodf' in s
    s = BY['wi_05']['semantics']
    assert 'panBlockingUIDisplayed' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.touchStartTranslation' in symbols
    assert 'OBJC_IVAR_$_World.tapProjectionMatrix' in symbols
    sels = {v.get('selector') for e in DATA['classes'] for v in e['selectors'].values()}
    assert 'fishingRod' in sels


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_input()
    print('test_worldinput_evidence: OK')
