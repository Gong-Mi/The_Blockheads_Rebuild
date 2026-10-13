#!/usr/bin/env python3
"""Contract test for NormalPlant (E90)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'NORMAL_PLANT.md').read_text()
DATA = json.loads((NATIVE / 'normal_plant.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['np_objecttype', 'np_maxagebase', 'np_contentstype', 'np_flowercontents', 'np_mintemp', 'np_seeditem', 'np_folliageitem', 'np_renderimage', 'np_foodremove', 'np_floweringseason', 'np_candie', 'np_npcspawn', 'np_emitslight', 'np_lightfactor', 'np_lightcolor', 'np_initsubderived', 'np_ctor', 'np_ctorsave', 'np_ctornet', 'np_dealloc', 'np_setneedsremoved', 'np_setflowering', 'np_remoteupdate', 'np_glowquadcount', 'np_addglowquad', 'np_update', 'np_kindself', 'np_harvested', 'np_tilesabove', 'np_droppeditem', 'np_staticquadcount', 'np_adddrawquad', 'np_rmmacro', 'np_addartistlight', 'np_availfood', 'np_setavailfood']
IMPS = ['0x00a6532c', '0x00a65348', '0x00a65378', '0x00a654f4', '0x00a65554', '0x00a65570', '0x00a6558c', '0x00a655a8', '0x00a655c4', '0x00a655f4', '0x00a65614', '0x00a65634', '0x00a65650', '0x00a6566c', '0x00a65698', '0x00a656e4', '0x00a659a0', '0x00a66614', '0x00a66a78', '0x00a66b94', '0x00a66c7c', '0x00a67034', '0x00a672d0', '0x00a67414', '0x00a674cc', '0x00a675a0', '0x00a690c0', '0x00a691a0', '0x00a69888', '0x00a698e0', '0x00a699d8', '0x00a69a00', '0x00a69f60', '0x00a6a180', '0x00a6a1f4', '0x00a6a23c']
COUNTS = {'np_objecttype': (0, 0, 0, 0, 0, 0), 'np_maxagebase': (0, 0, 0, 0, 0, 0), 'np_contentstype': (1, 1, 0, 0, 2, 0), 'np_flowercontents': (1, 1, 0, 0, 2, 0), 'np_mintemp': (0, 0, 0, 0, 0, 0), 'np_seeditem': (0, 0, 0, 0, 0, 0), 'np_folliageitem': (0, 0, 0, 0, 0, 0), 'np_renderimage': (0, 0, 0, 0, 0, 0), 'np_foodremove': (0, 0, 0, 0, 0, 0), 'np_floweringseason': (0, 0, 0, 0, 0, 0), 'np_candie': (0, 0, 0, 0, 0, 0), 'np_npcspawn': (0, 0, 0, 0, 0, 0), 'np_emitslight': (0, 0, 0, 0, 0, 0), 'np_lightfactor': (0, 0, 0, 0, 0, 0), 'np_lightcolor': (4, 0, 0, 4, 9, 5), 'np_initsubderived': (4, 0, 0, 4, 8, 5), 'np_ctor': (16, 1, 2, 11, 33, 17), 'np_ctorsave': (9, 4, 2, 7, 12, 7), 'np_ctornet': (2, 2, 1, 0, 2, 2), 'np_dealloc': (2, 2, 1, 1, 2, 0), 'np_setneedsremoved': (4, 2, 1, 3, 5, 2), 'np_setflowering': (2, 1, 0, 3, 7, 9), 'np_remoteupdate': (3, 2, 1, 2, 4, 1), 'np_glowquadcount': (2, 1, 0, 1, 2, 2), 'np_addglowquad': (2, 1, 0, 1, 2, 2), 'np_update': (35, 3, 2, 23, 79, 51), 'np_kindself': (2, 1, 0, 0, 2, 1), 'np_harvested': (8, 1, 0, 7, 16, 18), 'np_tilesabove': (0, 0, 0, 1, 0, 0), 'np_droppeditem': (2, 1, 0, 1, 3, 3), 'np_staticquadcount': (0, 0, 0, 0, 0, 0), 'np_adddrawquad': (2, 1, 0, 4, 8, 3), 'np_rmmacro': (4, 2, 1, 3, 8, 1), 'np_addartistlight': (1, 1, 0, 1, 1, 0), 'np_availfood': (0, 0, 0, 2, 0, 0), 'np_setavailfood': (0, 0, 0, 1, 0, 0)}
WORDS = [7, 12, 24, 24, 28, 21, 14, 7, 12, 16, 8, 14, 7, 11, 194, 175, 793, 281, 71, 58, 102, 167, 81, 46, 53, 1736, 56, 442, 22, 62, 10, 315, 136, 29, 37, 19]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5090
    for needle in ('5090', 'growthVigorForPlantTypeAtPos', 'reloadDrawBlockDynamicObjectQuad',
                   'emitsLight', '0x384', 'flowering'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_subclass():
    s = BY['np_initsubderived']['semantics']
    assert 'growthVigorForPlantTypeAtPos' in s and 'reloadDrawBlockDynamicObjectQuad' in s
    s = BY['np_setflowering']['semantics']
    assert 'reloadDrawBlockDynamicObjectQuad' in s
    s = BY['np_harvested']['semantics']
    assert '0x384' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_subclass()
    print('test_normalplant_evidence: OK')
