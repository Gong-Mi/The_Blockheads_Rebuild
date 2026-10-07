#!/usr/bin/env python3
"""Contract test for the SteamTrain core cluster (E69)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'STEAMTRAIN_CORE.md').read_text()
DATA = json.loads((NATIVE / 'steamtrain_core.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['st_loadderived', 'st_ctor_pos', 'st_ctor_net', 'st_creationnetdata', 'st_dealloc',
         'st_remoteupdate', 'st_searchstations']

IMPS = ['0x00d170b0', '0x00d17e98', '0x00d18b04', '0x00d19188', '0x00d19898', '0x00d19b84',
        '0x00d1a510']

COUNTS = {
    'st_loadderived': (4, 2, 2, 17, 23, 2),
    'st_ctor_pos': (11, 3, 1, 9, 29, 34),
    'st_ctor_net': (7, 3, 1, 5, 9, 3),
    'st_creationnetdata': (6, 4, 2, 12, 11, 8),
    'st_dealloc': (3, 2, 1, 11, 12, 0),
    'st_remoteupdate': (15, 5, 2, 15, 23, 28),
    'st_searchstations': (9, 2, 0, 18, 54, 67),
}

WORDS = [883, 615, 215, 361, 187, 611, 1371]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 4243
    for needle in ('4243', 'texCoordsForImageIndex', '0x243', '0x68', '0x62', 'fffffc8c',
                   'makeIntpair', 'tileAtWorldPositionLoaded'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_geometry_and_records():
    s = BY['st_loadderived']['semantics']
    for needle in ('texCoordsForImageIndex', '0x243', '1.2f'):
        assert needle in s, needle
    s = BY['st_creationnetdata']['semantics']
    for needle in ('0x68', 'memcpy', 'vmul'):
        assert needle in s, needle
    s = BY['st_dealloc']['semantics']
    assert 'fffffc8c..fca8' in s


def test_net_and_search():
    s = BY['st_remoteupdate']['semantics']
    for needle in ('vdiv.f32', 'vcmpe', 'ffe28ac8'):
        assert needle in s, needle
    s = BY['st_searchstations']['semantics']
    for needle in ('0x62', '8 probe steps', 'tileAtWorldPositionLoaded'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_geometry_and_records()
    test_net_and_search()
    print('test_steamtrain_core_evidence: OK')
