#!/usr/bin/env python3
"""Contract test for VinePlant (E92)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'VINE_PLANT.md').read_text()
DATA = json.loads((NATIVE / 'vine_plant.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['v_objecttype', 'v_initsubderived', 'v_ctor', 'v_ctornet', 'v_remoteupdate', 'v_dealloc', 'v_creationdata', 'v_compost', 'v_update', 'v_dieofoldage', 'v_kindself', 'v_planttype', 'v_soiltype', 'v_gatherprogress', 'v_harvested', 'v_setgather', 'v_tilesbelow', 'v_setneedsremoved', 'v_droppeditem', 'v_fgquadcount', 'v_addfgquad', 'v_rmmacro', 'v_availfood', 'v_setavailfood']
IMPS = ['0x004f58ec', '0x004f5908', '0x004f5cb4', '0x004f7344', '0x004f7744', '0x004f7b20', '0x004f7b8c', '0x004f7c18', '0x004f7cf0', '0x004f86a8', '0x004f8a6c', '0x004f8aa0', '0x004f8abc', '0x004f8b58', '0x004f8c64', '0x004f956c', '0x004f96c0', '0x004f96fc', '0x004f9788', '0x004f97a4', '0x004f9a78', '0x004fa3d4', '0x004fa570', '0x004fa5b8']
COUNTS = {'v_objecttype': (0, 0, 0, 0, 0, 0), 'v_initsubderived': (3, 1, 0, 7, 9, 6), 'v_ctor': (12, 1, 1, 9, 29, 27), 'v_ctornet': (3, 2, 1, 1, 3, 2), 'v_remoteupdate': (4, 2, 1, 4, 10, 11), 'v_dealloc': (1, 1, 1, 0, 1, 0), 'v_creationdata': (1, 0, 1, 3, 2, 6), 'v_compost': (0, 0, 0, 2, 1, 6), 'v_update': (7, 2, 1, 13, 22, 25), 'v_dieofoldage': (6, 1, 0, 7, 9, 7), 'v_kindself': (0, 0, 0, 0, 0, 0), 'v_planttype': (0, 0, 0, 0, 0, 0), 'v_soiltype': (0, 0, 0, 0, 0, 5), 'v_gatherprogress': (0, 0, 0, 3, 0, 3), 'v_harvested': (9, 1, 0, 6, 23, 23), 'v_setgather': (0, 0, 0, 4, 0, 4), 'v_tilesbelow': (0, 0, 0, 1, 0, 0), 'v_setneedsremoved': (1, 1, 1, 0, 1, 0), 'v_droppeditem': (0, 0, 0, 0, 0, 0), 'v_fgquadcount': (0, 0, 0, 3, 2, 15), 'v_addfgquad': (0, 0, 0, 4, 14, 24), 'v_rmmacro': (2, 1, 1, 3, 6, 0), 'v_availfood': (0, 0, 0, 2, 0, 0), 'v_setavailfood': (0, 0, 0, 1, 0, 0)}
WORDS = [7, 235, 758, 96, 247, 27, 89, 54, 622, 241, 13, 7, 39, 67, 578, 85, 15, 35, 7, 181, 540, 103, 37, 19]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 4102
    for needle in ('4102', 'currentTemperatureForTileAt', 'tileIsWater', 'fillArbitraryQuadBuffer',
                   'macroPosForWorldPos', '0xbf00'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_vine():
    s = BY['v_ctor']['semantics']
    assert 'currentTemperatureForTileAt' in s
    s = BY['v_update']['semantics']
    assert 'tileIsWater' in s and 'reloadDrawBlockDynamicObjectQuad' in s
    s = BY['v_addfgquad']['semantics']
    assert 'fillArbitraryQuadBuffer' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_vine()
    print('test_vineplant_evidence: OK')
