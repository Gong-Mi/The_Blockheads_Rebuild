#!/usr/bin/env python3
"""Contract test for the DynamicWorld draw & reload cluster (E25).

Pins the JSON artifact and the prose doc to the recovered semantics of the six
bodies: the packed in-front draw, the names pass, the three reload contracts and
the blockhead box draw.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DRAW_RELOAD.md').read_text()
DATA = json.loads((NATIVE / 'draw_reload.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_drawinfrontofblocksobj', 'wtl_drawnames_projectionma',
         'wtl_reloaddynamicobjectqua', 'dyn_reload_cylin', 'dyn_reload_gem',
         'wtl_drawblockheadboxes_pro']

IMPS = ['0x008d2db8', '0x008dc6b4', '0x008ff8bc', '0x008fec40', '0x008fe4a4', '0x008dc07c']

COUNTS = {
    'wtl_drawinfrontofblocksobj': (2, 0, 0, 2, 10, 10),
    'wtl_drawnames_projectionma': (3, 1, 0, 4, 19, 22),
    'wtl_reloaddynamicobjectqua': (7, 1, 0, 1, 34, 46),
    'dyn_reload_cylin': (6, 1, 0, 0, 23, 25),
    'dyn_reload_gem': (6, 1, 0, 0, 23, 25),
    'wtl_drawblockheadboxes_pro': (3, 1, 0, 2, 3, 1),
}

WORDS = [1642, 1393, 961, 487, 487, 398]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5368
    for needle in ('5368', '0x00E4AA1C', '0x00E18134', '__wrap_glEnable', '0xbe2',
                   '__wrap_free', '__wrap_malloc', '__wrap_exit', '0x60', '0x240',
                   'ffe23540', 'ffe23544'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_draw_bodies():
    s = BY['wtl_drawinfrontofblocksobj']['semantics']
    for needle in ('+0x2d0', '+0x240', '+0x234', '+0x168', '+0xc0', 'tree_next',
                   '0x78c870', '0x78ba80', 'objc_msgSend'):
        assert needle in s, needle
    s = BY['wtl_drawnames_projectionma']['semantics']
    for needle in ('__wrap_glEnable(0xbe2)', '0..8', '0x00E4AA1C', 'pinchScale',
                   'ffe23544', 'ffffe4f8', 'drawLocalNames'):
        assert needle in s, needle
    s = BY['wtl_drawblockheadboxes_pro']['semantics']
    for needle in ('ffffe55c', 'ffffe4f8', 'ffe231cc', 'ffe23540'):
        assert needle in s, needle


def test_reload_family():
    s = BY['wtl_reloaddynamicobjectqua']['semantics']
    for needle in ('+0x1a4', '+0x1b8', '__wrap_free', 'ffe23760', 'ffe23764', '0x00E18134',
                   '__wrap_malloc', '0x60', '__wrap_exit', 'ffe2376c'):
        assert needle in s, needle
    for name, slots in (('dyn_reload_cylin', ('+0x1dc', '+0x1e4', 'ffe2374c', 'ffe23748')),
                        ('dyn_reload_gem', ('+0x190', '+0x198', 'ffe2373c', 'ffe23738'))):
        s = BY[name]['semantics']
        for needle in slots:
            assert needle in s, needle
        for needle in ('__wrap_malloc', '0x240', '__wrap_exit'):
            assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_draw_bodies()
    test_reload_family()
    print('test_draw_reload_evidence: OK')
