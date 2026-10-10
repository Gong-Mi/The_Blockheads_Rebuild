#!/usr/bin/env python3
"""Contract test for the Plant base class (E88)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'PLANT_BASE.md').read_text()
DATA = json.loads((NATIVE / 'plant_base.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['p_rmmacro', 'p_ctor', 'p_ctornet', 'p_dealloc', 'p_updatenet', 'p_creationdata', 'p_creationdata2', 'p_remoteupdate', 'p_setflowering', 'p_worldchanged', 'p_compost', 'p_update', 'p_soiltype', 'p_planttype', 'p_gatherprogress', 'p_harvested', 'p_setgather', 'p_removeplant', 'p_maxagegene', 'p_growthgene', 'p_isflowering', 'p_droppeditem', 'p_kindself', 'p_cleartiles', 'p_setneedsremoved', 'p_canbreed', 'p_occupiesfg', 'p_tilesabove', 'p_tilesbelow']
IMPS = ['0x00954f40', '0x00954fec', '0x00955b98', '0x00955d10', '0x0095649c', '0x009564f0', '0x00956608', '0x009566e8', '0x00956808', '0x0095684c', '0x00956e1c', '0x00956ef8', '0x00957304', '0x009573a0', '0x009573bc', '0x00957404', '0x00957474', '0x009574c8', '0x009575cc', '0x0095768c', '0x0095773c', '0x00957778', '0x00957794', '0x009577b4', '0x00957af4', '0x00957be4', '0x00957c00', '0x00957c1c', '0x00957c38']
COUNTS = {'p_rmmacro': (2, 2, 1, 0, 2, 0), 'p_ctor': (7, 1, 1, 8, 11, 10), 'p_ctornet': (2, 2, 1, 2, 2, 2), 'p_dealloc': (1, 1, 1, 0, 1, 0), 'p_updatenet': (1, 1, 0, 0, 1, 0), 'p_creationdata': (1, 0, 0, 2, 2, 2), 'p_creationdata2': (2, 1, 1, 0, 3, 2), 'p_remoteupdate': (3, 2, 1, 1, 3, 0), 'p_setflowering': (0, 0, 0, 1, 0, 0), 'p_worldchanged': (5, 1, 0, 3, 12, 21), 'p_compost': (0, 0, 0, 2, 1, 6), 'p_update': (4, 1, 0, 9, 5, 11), 'p_soiltype': (0, 0, 0, 0, 0, 5), 'p_planttype': (0, 0, 0, 0, 0, 0), 'p_gatherprogress': (0, 0, 0, 1, 0, 0), 'p_harvested': (1, 1, 0, 0, 1, 0), 'p_setgather': (0, 0, 0, 1, 0, 0), 'p_removeplant': (3, 0, 0, 5, 8, 0), 'p_maxagegene': (0, 0, 0, 2, 5, 0), 'p_growthgene': (0, 0, 0, 1, 2, 0), 'p_isflowering': (0, 0, 0, 1, 0, 0), 'p_droppeditem': (0, 0, 0, 0, 0, 0), 'p_kindself': (0, 0, 0, 0, 0, 0), 'p_cleartiles': (4, 1, 0, 3, 10, 7), 'p_setneedsremoved': (2, 2, 1, 1, 2, 2), 'p_canbreed': (0, 0, 0, 0, 0, 0), 'p_occupiesfg': (0, 0, 0, 0, 0, 0), 'p_tilesabove': (0, 0, 0, 0, 0, 0), 'p_tilesbelow': (0, 0, 0, 0, 0, 0)}
WORDS = [43, 301, 94, 27, 21, 70, 56, 72, 17, 372, 55, 259, 39, 7, 18, 28, 21, 157, 92, 44, 22, 7, 8, 208, 60, 28, 21, 14, 7]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2168
    for needle in ('2168', 'tileIsPlant', 'lrand48', '0xb occupancy', 'ffffcad4',
                   'tileIsAirWaterOrSnow'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_engine():
    s = BY['p_ctor']['semantics']
    assert 'tileIsPlant' in s and '0xb' in s
    s = BY['p_removeplant']['semantics']
    assert 'lrand48' in s and 'clampi' in s
    s = BY['p_soiltype']['semantics']
    assert '0x1b, 0x1c' in s
    s = BY['p_worldchanged']['semantics']
    assert 'tileIsAirWaterOrSnow' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_engine()
    print('test_plantbase_evidence: OK')
