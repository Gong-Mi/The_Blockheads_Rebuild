#!/usr/bin/env python3
"""Contract test for the DynamicWorld change-propagation cluster (E23).

Pins the JSON artifact and the prose doc to the recovered semantics of the seven
bodies: the light/water change producers, the tree/plant sowing scans with their
switch jump tables, the tree-life fraction field, the ownership-pole restorer and
the elevator-motor lookup.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_UPDATE.md').read_text()
DATA = json.loads((NATIVE / 'world_update.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_lightchangedatmacropos', 'wtl_waterchangedatpos_full', 'wtl_sowtreenearparent_adul',
         'wtl_sowplantnearparent_', 'wtl_gettreelifefractionfor', 'wtl_checkandrestorepoleite',
         'wtl_elevatormotorforshafta']

IMPS = ['0x008e1f18', '0x008e0ad0', '0x008e2dc8', '0x008e3edc', '0x008f9b70', '0x009039e8', '0x008ebf40']

COUNTS = {
    'wtl_lightchangedatmacropos': (0, 0, 0, 3, 4, 47),
    'wtl_waterchangedatpos_full': (1, 1, 0, 4, 7, 32),
    'wtl_sowtreenearparent_adul': (6, 1, 0, 3, 26, 53),
    'wtl_sowplantnearparent_': (7, 1, 0, 3, 31, 59),
    'wtl_gettreelifefractionfor': (9, 2, 1, 5, 68, 52),
    'wtl_checkandrestorepoleite': (27, 6, 5, 9, 58, 75),
    'wtl_elevatormotorforshafta': (6, 1, 0, 3, 47, 68),
}


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == [805, 560, 638, 699, 1160, 1292, 899]
    assert sum(BY[n]['verified_words'] for n in NAMES) == 6053
    for needle in ('6053', '0x00E49A64', '0x00E4AA3C', '0x00E4AA60', 'reloadDrawBlockWaterForTile',
                   'tileIsAirWaterOrSnow', '2^31', '0x8e / 0x8c /', '0x8f / 0x8d', '36000.0',
                   '0x67 / 0x68', 'std::__tree_next'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_light_and_water():
    s = BY['wtl_lightchangedatmacropos']['semantics']
    for needle in ('ffffe570', 'ffffe574', 'ffffe57c', '__aeabi_memmove', 'sendReliably', 'sendAtAll'):
        assert needle in s, needle
    s = BY['wtl_waterchangedatpos_full']['semantics']
    for needle in ('fullBlock', 'ffffe5c0', 'reloadDrawBlockWaterForTile', '0x20', 'makeIntpair',
                   'ffffe570', 'ffffe574'):
        assert needle in s, needle


def test_sowing():
    s = BY['wtl_sowtreenearparent_adul']['semantics']
    for needle in ('0x8ad2a4', '0x00E49A64', 'ffffe54c', 'tileAtWorldPositionLoaded',
                   'tileIsAirWaterOrSnow', '0x10', 'makeIntpair', 'adult float'):
        assert needle in s, needle
    s = BY['wtl_sowplantnearparent_']['semantics']
    for needle in ('0x00E4AA3C', '0xa (10)', 'ffffe550', 'cmp r0, 7', 'kelp', '3/2'):
        assert needle in s, needle


def test_lifefrac():
    s = BY['wtl_gettreelifefractionfor']['semantics']
    for needle in ('5.0', '2.0 -> 10.0 -> 50.0', '2147483648.0', 'ffffe5d0',
                   'v.x = v.x*5.0 + frac*5.0', '0x00E4AA60', '1 - |x_tree - x|/32.0',
                   'ffe236fc', 'Vector::Vector(float, float, float, float)'):
        assert needle in s, needle


def test_poles_and_elevator():
    s = BY['wtl_checkandrestorepoleite']['semantics']
    for needle in ('ffffe5d4', 'ffffe5d8', '0x8e', '0x8c', '0x8f', '0x8d', '512',
                   'stringWithFormat', 'worldTime', '36000.0', 'ffe23410'):
        assert needle in s, needle
    s = BY['wtl_elevatormotorforshafta']['semantics']
    for needle in ('+0x294', 'ffffe54c', 'ffffe550', 'tileAtWorldPositionLoaded', '0x67', '0x68',
                   'ffe23640'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_light_and_water()
    test_sowing()
    test_lifefrac()
    test_poles_and_elevator()
    print('test_world_update_evidence: OK')
