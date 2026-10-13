#!/usr/bin/env python3
"""Contract test for TulipPlant (E94)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TULIP_PLANT.md').read_text()
DATA = json.loads((NATIVE / 'tulip_plant.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['tl_objecttype', 'tl_initsubderived', 'tl_ctor', 'tl_ctorsave', 'tl_ctornet', 'tl_creationdata', 'tl_setflowering', 'tl_update', 'tl_draw', 'tl_kindself', 'tl_planttype', 'tl_soiltype', 'tl_harvested', 'tl_tilesabove', 'tl_droppeditem', 'tl_staticquadcount', 'tl_adddrawquad', 'tl_rmmacro', 'tl_canbreed', 'tl_mixgenes', 'tl_colorgenevar', 'tl_availfood', 'tl_setavailfood', 'tl_colorgene', 'tl_setcolorgene', 'tl_cxxconstruct']
IMPS = ['0x0099f950', '0x0099f96c', '0x009a09f8', '0x009a1368', '0x009a1684', '0x009a1b58', '0x009a1c24', '0x009a1d20', '0x009a2b00', '0x009a498c', '0x009a49c0', '0x009a49dc', '0x009a4a78', '0x009a4f1c', '0x009a4f74', '0x009a4f90', '0x009a4fb8', '0x009a53c8', '0x009a54d0', '0x009a557c', '0x009a5770', '0x009a5d24', '0x009a5d6c', '0x009a5db8', '0x009a5df4', '0x009a5e3c']
COUNTS = {'tl_objecttype': (0, 0, 0, 0, 0, 0), 'tl_initsubderived': (4, 10, 1, 11, 48, 13), 'tl_ctor': (9, 1, 1, 9, 19, 14), 'tl_ctorsave': (5, 6, 1, 4, 10, 2), 'tl_ctornet': (3, 2, 1, 3, 3, 2), 'tl_creationdata': (2, 0, 1, 6, 3, 1), 'tl_setflowering': (1, 0, 0, 3, 2, 1), 'tl_update': (11, 2, 1, 15, 29, 30), 'tl_draw': (9, 1, 0, 10, 76, 29), 'tl_kindself': (0, 0, 0, 0, 0, 0), 'tl_planttype': (0, 0, 0, 0, 0, 0), 'tl_soiltype': (0, 0, 0, 0, 0, 5), 'tl_harvested': (4, 1, 0, 6, 8, 19), 'tl_tilesabove': (0, 0, 0, 1, 0, 0), 'tl_droppeditem': (0, 0, 0, 0, 0, 0), 'tl_staticquadcount': (0, 0, 0, 0, 0, 0), 'tl_adddrawquad': (0, 0, 0, 3, 4, 1), 'tl_rmmacro': (2, 1, 1, 2, 3, 0), 'tl_canbreed': (0, 0, 0, 2, 0, 1), 'tl_mixgenes': (0, 0, 0, 1, 2, 14), 'tl_colorgenevar': (0, 0, 0, 2, 15, 38), 'tl_availfood': (0, 0, 0, 2, 0, 0), 'tl_setavailfood': (0, 0, 0, 1, 0, 0), 'tl_colorgene': (0, 0, 0, 1, 0, 0), 'tl_setcolorgene': (0, 0, 0, 1, 0, 0), 'tl_cxxconstruct': (0, 0, 0, 2, 6, 0)}
WORDS = [7, 873, 604, 199, 116, 114, 63, 888, 1465, 13, 7, 39, 297, 29, 7, 10, 231, 66, 43, 125, 312, 37, 19, 15, 18, 94]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5691
    for needle in ('5691', '0xffff', 'glUniform4f', 'clamp_float', '0x64', '0x1c2'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_color():
    s = BY['tl_mixgenes']['semantics']
    assert '0xffff' in s
    s = BY['tl_draw']['semantics']
    assert 'glUniform4f' in s
    s = BY['tl_cxxconstruct']['semantics']
    assert 'clamp_float' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_color()
    print('test_tulipplant_evidence: OK')
