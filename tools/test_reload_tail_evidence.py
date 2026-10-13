#!/usr/bin/env python3
"""Contract test for the DynamicWorld reload-tail & lifecycle smalls (E29)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'RELOAD_TAIL.md').read_text()
DATA = json.loads((NATIVE / 'reload_tail.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['dyn_reload_glow', 'dyn_reload_item', 'dyn_reload_egg', 'dyn_cxx_destruct',
         'wtl_addartificiallightcont', 'wtl_hasdynamicobjectstosav',
         'wtl_blockheadwillbeunloade', 'wtl_freeblocksatpos_']

IMPS = ['0x00900ca0', '0x009007c0', '0x008ff3dc', '0x00906ccc', '0x00903014', '0x008c98a0',
        '0x00901180', '0x008f16bc']

COUNTS = {
    'dyn_reload_glow': (4, 1, 0, 0, 14, 17),
    'dyn_reload_item': (4, 1, 0, 0, 14, 17),
    'dyn_reload_egg': (4, 1, 0, 0, 14, 17),
    'dyn_cxx_destruct': (0, 0, 0, 19, 23, 8),
    'wtl_addartificiallightcont': (1, 1, 0, 2, 5, 9),
    'wtl_hasdynamicobjectstosav': (0, 0, 0, 3, 0, 17),
    'wtl_blockheadwillbeunloade': (1, 1, 0, 2, 4, 7),
    'wtl_freeblocksatpos_': (4, 1, 1, 2, 9, 9),
}

WORDS = [312, 312, 312, 339, 259, 259, 248, 239]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2280
    for needle in ('2280', '0x1c4', '0x30c', '0x180', '0x514', 'ffe23784', 'ffe237c0',
                   'objectTypeMayHaveArtificalLight', 'worldIndexAtWorldPos', 'ffffe588'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_reload_trio():
    for name in ('dyn_reload_glow', 'dyn_reload_item', 'dyn_reload_egg'):
        s = BY[name]['semantics']
        for needle in ('+0x1c4', '__wrap_free', '__wrap_malloc', '0x60', '__wrap_exit', '0x178'):
            assert needle in s, needle


def test_destruct_and_helpers():
    s = BY['dyn_cxx_destruct']['semantics']
    for needle in ('~list', '~vector<intpair>', '0x30c', '0x180', '0x514', '~unordered_set'):
        assert needle in s, needle
    s = BY['wtl_freeblocksatpos_']['semantics']
    for needle in ('worldIndexAtWorldPos', '__count_unique', 'operator[]', 'ffe234ac', 'addObject:'):
        assert needle in s, needle
    s = BY['wtl_hasdynamicobjectstosav']['semantics']
    for needle in ('ffffe518', '0x41 (65)', 'movw r1, 0xc', 'ffffe570'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_reload_trio()
    test_destruct_and_helpers()
    print('test_reload_tail_evidence: OK')
