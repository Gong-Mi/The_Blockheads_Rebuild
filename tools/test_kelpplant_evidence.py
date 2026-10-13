#!/usr/bin/env python3
"""Contract test for KelpPlant (E93)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'KELP_PLANT.md').read_text()
DATA = json.loads((NATIVE / 'kelp_plant.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['k_objecttype', 'k_initsubderived', 'k_ctor', 'k_ctornet', 'k_creationdata', 'k_dealloc', 'k_remoteupdate', 'k_update', 'k_dieofoldage', 'k_draw', 'k_kindself', 'k_planttype', 'k_soiltype', 'k_gatherprogress', 'k_harvested', 'k_setgather', 'k_tilesabove', 'k_droppeditem', 'k_staticquadcount', 'k_adddrawquad', 'k_rmmacro', 'k_availfood', 'k_setavailfood']
IMPS = ['0x00814a54', '0x00814a70', '0x00814f54', '0x00816560', '0x00816960', '0x008169ec', '0x00816a58', '0x00816e34', '0x00817c8c', '0x00818150', '0x00818d9c', '0x00818dd0', '0x00818dec', '0x00818e74', '0x00818f7c', '0x00819858', '0x008199ac', '0x008199e8', '0x00819a04', '0x00819cd8', '0x0081a6f0', '0x0081a890', '0x0081a8d8']
COUNTS = {'k_objecttype': (0, 0, 0, 0, 0, 0), 'k_initsubderived': (3, 1, 0, 9, 11, 8), 'k_ctor': (12, 1, 1, 9, 33, 28), 'k_ctornet': (3, 2, 1, 1, 3, 2), 'k_creationdata': (1, 0, 1, 1, 1, 0), 'k_dealloc': (1, 1, 1, 0, 1, 0), 'k_remoteupdate': (4, 2, 1, 4, 10, 11), 'k_update': (8, 2, 1, 15, 34, 43), 'k_dieofoldage': (7, 1, 0, 7, 14, 7), 'k_draw': (1, 1, 0, 9, 13, 22), 'k_kindself': (0, 0, 0, 0, 0, 0), 'k_planttype': (0, 0, 0, 0, 0, 0), 'k_soiltype': (0, 0, 0, 0, 0, 4), 'k_gatherprogress': (0, 0, 0, 3, 0, 3), 'k_harvested': (9, 1, 0, 6, 22, 22), 'k_setgather': (0, 0, 0, 4, 0, 4), 'k_tilesabove': (0, 0, 0, 1, 0, 0), 'k_droppeditem': (0, 0, 0, 0, 0, 0), 'k_staticquadcount': (0, 0, 0, 3, 2, 15), 'k_adddrawquad': (0, 0, 0, 7, 15, 22), 'k_rmmacro': (2, 1, 1, 3, 6, 0), 'k_availfood': (0, 0, 0, 2, 0, 0), 'k_setavailfood': (0, 0, 0, 1, 0, 0)}
WORDS = [7, 309, 805, 96, 35, 27, 247, 918, 305, 743, 13, 7, 34, 66, 567, 85, 22, 7, 181, 646, 104, 37, 19]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5280
    for needle in ('5280', 'sinf', 'updateArbitraryQuadV', 'macroTileAtMacroPostion',
                   'currentTemperatureForTileAt', 'tileIsWater'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_kelp():
    s = BY['k_draw']['semantics']
    assert 'sinf' in s and 'updateArbitraryQuadV' in s
    s = BY['k_ctor']['semantics']
    assert 'currentTemperatureForTileAt' in s and 'tileIsWater' in s
    s = BY['k_update']['semantics']
    assert '0x708' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_kelp()
    print('test_kelpplant_evidence: OK')
