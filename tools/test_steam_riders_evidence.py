#!/usr/bin/env python3
"""Contract test for the SteamTrain riders/fuel cluster (E70)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'STEAM_RIDERS.md').read_text()
DATA = json.loads((NATIVE / 'steam_riders.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['st2_riderbody', 'st2_tapradius', 'st2_riderpos', 'st2_addfuelitem', 'st2_renderpos',
         'st2_updatehasfuel', 'st2_removerider', 'st2_setneedsremoved', 'st2_setpaused',
         'st2_railname', 'st2_camerapos']

IMPS = ['0x00d2efd0', '0x00d307cc', '0x00d2eac8', '0x00d30030', '0x00d2e5b4', '0x00d2fdf4',
        '0x00d31088', '0x00d30580', '0x00d306d0', '0x00d311f8', '0x00d2ea38']

COUNTS = {
    'st2_riderbody': (1, 0, 0, 5, 23, 4),
    'st2_tapradius': (1, 0, 0, 4, 36, 9),
    'st2_riderpos': (0, 0, 0, 4, 13, 0),
    'st2_addfuelitem': (9, 4, 1, 7, 12, 11),
    'st2_renderpos': (0, 0, 0, 3, 11, 0),
    'st2_updatehasfuel': (2, 0, 0, 5, 4, 6),
    'st2_removerider': (1, 1, 1, 6, 1, 1),
    'st2_setneedsremoved': (2, 2, 1, 2, 3, 0),
    'st2_setpaused': (1, 1, 0, 2, 2, 1),
    'st2_railname': (0, 0, 0, 6, 0, 1),
    'st2_camerapos': (1, 0, 0, 0, 2, 2),
}

WORDS = [567, 552, 322, 295, 289, 143, 85, 84, 63, 64, 36]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2500
    for needle in ('2500', 'atan2f', '0xcd', 'fffffcc0', 'ffffcacc', 'Vector2::Vector2(0,',
                   '0.5f'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_matrix_and_fuel():
    s = BY['st2_riderbody']['semantics']
    for needle in ('0x3f000000', 'atan2f', '0xd20620', 'lsl r0, r0, 5'):
        assert needle in s, needle
    s = BY['st2_addfuelitem']['semantics']
    for needle in ('0xcd (205)', 'ffe28ad8', 'strb'):
        assert needle in s, needle
    s = BY['st2_updatehasfuel']['semantics']
    for needle in ('fffffcc0', 'bpl', 'fffffcc4'):
        assert needle in s, needle


def test_flags():
    s = BY['st2_railname']['semantics']
    assert 'ffffcacc' in s and 'strb' in s
    s = BY['st2_removerider']['semantics']
    assert 'ffffcacc' in s
    s = BY['st2_setpaused']['semantics']
    assert 'fffffcec' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_matrix_and_fuel()
    test_flags()
    print('test_steam_riders_evidence: OK')
