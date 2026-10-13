#!/usr/bin/env python3
"""Contract test for the Torch class (E72)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TORCH.md').read_text()
DATA = json.loads((NATIVE / 'torch.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['t_initsubderived', 't_getlightrgb', 't_ctor_placed', 't_objecttype', 't_fbitemtype',
         't_fbsavedict', 't_fbdataa', 't_fbdatab', 't_ctor_save', 't_ctor_net', 't_getsavedict',
         't_updatenet', 't_creationdata', 't_dealloc', 't_rmmacro', 't_draw', 't_remoteupdate',
         't_waterchanged', 't_worldcontents', 't_worldchanged', 't_setneedsremoved',
         't_renderimageidx', 't_staticquadcount', 't_adddrawquad', 't_lightpos',
         't_glowquadcount', 't_isdownlight', 't_isuplight', 't_occupiesfg',
         't_addartistlightcont', 't_dataa', 't_setdataa', 't_datab', 't_setdatab']

IMPS = ['0x004b4a20', '0x004b4e98', '0x004b5300', '0x004b5c1c', '0x004b5c38', '0x004b5c74',
        '0x004b5cc0', '0x004b5cfc', '0x004b5d38', '0x004b6230', '0x004b65b8', '0x004b69e0',
        '0x004b6a34', '0x004b6ed0', '0x004b6ff4', '0x004b71d8', '0x004b77d0', '0x004b78bc',
        '0x004b7bd4', '0x004b8b50', '0x004b8be8', '0x004b8cd0', '0x004b8fa8', '0x004b8fd0',
        '0x004be0d4', '0x004bed90', '0x004bedec', '0x004bee3c', '0x004bee90', '0x004beeac',
        '0x004bef20', '0x004bef5c', '0x004befa4', '0x004befe0']

COUNTS = {
    't_initsubderived': (1, 0, 0, 6, 4, 14),
    't_getlightrgb': (0, 0, 0, 1, 1, 39),
    't_ctor_placed': (7, 2, 2, 10, 14, 44),
    't_objecttype': (0, 0, 0, 1, 0, 0),
    't_fbitemtype': (0, 0, 0, 1, 0, 0),
    't_fbsavedict': (1, 1, 0, 0, 1, 0),
    't_fbdataa': (0, 0, 0, 2, 0, 0),
    't_fbdatab': (0, 0, 0, 1, 0, 0),
    't_ctor_save': (7, 8, 2, 9, 15, 3),
    't_ctor_net': (8, 3, 1, 5, 10, 3),
    't_getsavedict': (3, 8, 2, 6, 12, 2),
    't_updatenet': (1, 1, 0, 0, 1, 0),
    't_creationdata': (6, 2, 2, 5, 9, 3),
    't_dealloc': (2, 2, 1, 2, 3, 0),
    't_rmmacro': (3, 1, 1, 3, 7, 0),
    't_draw': (1, 1, 0, 6, 4, 11),
    't_remoteupdate': (2, 2, 1, 1, 2, 0),
    't_waterchanged': (4, 1, 0, 8, 6, 9),
    't_worldcontents': (7, 1, 0, 10, 36, 72),
    't_worldchanged': (2, 1, 0, 1, 2, 0),
    't_setneedsremoved': (2, 2, 1, 1, 2, 1),
    't_renderimageidx': (0, 0, 0, 3, 0, 52),
    't_staticquadcount': (0, 0, 0, 0, 0, 0),
    't_adddrawquad': (1, 1, 0, 15, 67, 78),
    't_lightpos': (0, 0, 0, 5, 64, 84),
    't_glowquadcount': (0, 0, 0, 1, 0, 2),
    't_isdownlight': (0, 0, 0, 2, 0, 0),
    't_isuplight': (0, 0, 0, 1, 0, 0),
    't_occupiesfg': (0, 0, 0, 0, 0, 0),
    't_addartistlightcont': (1, 1, 0, 1, 1, 0),
    't_dataa': (0, 0, 0, 1, 0, 0),
    't_setdataa': (0, 0, 0, 1, 0, 0),
    't_datab': (0, 0, 0, 1, 0, 0),
    't_setdatab': (0, 0, 0, 1, 0, 0),
}

WORDS = [286, 261, 578, 22, 15, 19, 30, 15, 318, 217, 266, 21, 204, 73, 121, 382, 59, 198,
         991, 38, 58, 182, 10, 4762, 803, 23, 48, 28, 7, 29, 15, 18, 15, 18]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 10130
    for needle in ('10130', 'reloadDrawBlockDynamicObjectQuadsForTile', 'fillQuadBuffer',
                   '0xfe', '0x102', '0x9d', 'dmb ish', '0x64'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_colors_and_codes():
    s = BY['t_getlightrgb']['semantics']
    for needle in ('0xb7 (183)', '(220, 100, 12)', '0x102 (258)'):
        assert needle in s, needle
    s = BY['t_worldcontents']['semantics']
    for needle in ('-2', '+0xb == 0x64', 'tileContainsDoor', 'place'):
        assert needle in s, needle
    s = BY['t_renderimageidx']['semantics']
    for needle in ('0x91', '12-word', '0x9d'):
        assert needle in s, needle


def test_emitter_and_atomics():
    s = BY['t_adddrawquad']['semantics']
    for needle in ('23', 'memcpy', 'fillQuadBuffer', '0xbfb4f4ab'):
        assert needle in s, needle
    s = BY['t_setdataa']['semantics']
    assert 'dmb ish' in s
    s = BY['t_setdatab']['semantics']
    assert 'dmb ish' in s
    s = BY['t_rmmacro']['semantics']
    assert 'reloadDrawBlockDynamicObjectQuadsForTile' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_colors_and_codes()
    test_emitter_and_atomics()
    print('test_torch_evidence: OK')
