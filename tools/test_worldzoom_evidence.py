#!/usr/bin/env python3
"""Contract test for the World camera/zoom/motion line (E107)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_ZOOM.md').read_text()
DATA = json.loads((NATIVE / 'world_zoom.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wz_00', 'wz_01', 'wz_02', 'wz_03', 'wz_04', 'wz_05', 'wz_06', 'wz_07', 'wz_08']
IMPS = ['0x005c4c28', '0x005c55f4', '0x005c8e98', '0x005c5c0c', '0x005c60ac', '0x005be998', '0x005bf528', '0x005bf738', '0x005be378']
COUNTS = {'wz_00': (21, 3, 4, 5, 33, 25), 'wz_01': (11, 1, 1, 2, 23, 19), 'wz_02': (11, 1, 0, 2, 18, 5), 'wz_03': (1, 0, 0, 1, 1, 2), 'wz_04': (2, 1, 0, 2, 3, 5), 'wz_05': (5, 1, 1, 10, 34, 19), 'wz_06': (3, 1, 0, 1, 9, 6), 'wz_07': (3, 1, 0, 1, 5, 2), 'wz_08': (0, 0, 0, 4, 17, 2)}
WORDS = [627, 390, 313, 53, 74, 583, 132, 82, 249]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2503
    for needle in ('2503', '627', '583', 'zoomToPos:pinchZoom:', 'tileIsLitForClient',
                   'calibrationMatrix', 'longTermAveragedAcceleration', 'motionManager',
                   'clientZoomRequestSent', 'zoomPlayerCycleCounts'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_zoom():
    s = BY['wz_00']['semantics']
    assert 'sendDataToServer' in s
    assert '0x55468c' in s
    s = BY['wz_05']['semantics']
    assert 'calibrationMatrix' in s
    s = BY['wz_08']['semantics']
    assert 'cross' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.calibrationMatrix' in symbols
    sels = {v.get('selector') for e in DATA['classes'] for v in e['selectors'].values()}
    assert 'zoomToPos:pinchZoom:' in sels


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_zoom()
    print('test_worldzoom_evidence: OK')
