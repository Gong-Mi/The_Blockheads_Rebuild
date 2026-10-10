#!/usr/bin/env python3
"""Contract test for the Workbench electricity sub-cluster (E75)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_ELECTRICITY.md').read_text()
DATA = json.loads((NATIVE / 'workbench_electricity.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wb_avaiablelec', 'wb_conductelec', 'wb_subtractelec', 'wb_genelectric',
         'wb_useselectric', 'wb_energyfrac', 'wb_solarlight_full', 'wb_solarlight',
         'wb_getlightrgb', 'wb_portallight', 'wb_storagedev', 'wb_conductelec']

IMPS = ['0x00b01284', '0x00b012c0', '0x00b0137c', '0x00b01c24', '0x00b01cac', '0x00b01ec0',
        '0x00aee208', '0x00aee508', '0x00ae3c6c', '0x00ae3f64', '0x00b01bd4', '0x00b012c0']

COUNTS = {
    'wb_avaiablelec': (0, 0, 0, 1, 0, 0),
    'wb_conductelec': (2, 1, 0, 0, 2, 1),
    'wb_subtractelec': (3, 1, 0, 7, 5, 10),
    'wb_genelectric': (0, 0, 0, 2, 0, 11),
    'wb_useselectric': (0, 0, 0, 1, 0, 10),
    'wb_energyfrac': (1, 1, 0, 2, 1, 7),
    'wb_solarlight_full': (1, 1, 0, 2, 6, 10),
    'wb_solarlight': (4, 1, 0, 2, 9, 13),
    'wb_getlightrgb': (0, 0, 0, 3, 2, 23),
    'wb_portallight': (7, 1, 1, 5, 13, 2),
    'wb_storagedev': (0, 0, 0, 1, 0, 0),
}

WORDS = {0: 15, 1: 47, 2: 245, 3: 167, 4: 133, 5: 104, 6: 192, 7: 324, 8: 190, 9: 215, 10: 20, 11: 47}


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [m['verified_words'] for m in DATA['classes']] == [WORDS[i] for i in range(12)]
    assert sum(m['verified_words'] for m in DATA['classes']) == 1699
    for needle in ('1699', '8192', '0x2000', 'tileIsAirOrSnow', 'powf', '(48, 130, 220)',
                   'fffff150'):
        assert needle in DOC, needle


def test_anchor_counts():
    for i, n in enumerate(NAMES):
        m = DATA['classes'][i]
        assert kinds(m) == COUNTS[n], (i, n, kinds(m))


def test_electricity():
    s = BY['wb_avaiablelec']['semantics']
    assert 'ldrh' in s and 'u16' in s
    s = BY['wb_subtractelec']['semantics']
    for needle in ('strh', 'sub r0, r2, r0', '0xb013f4'):
        assert needle in s, needle
    s = BY['wb_energyfrac']['semantics']
    assert '8192' in s and 'vdiv.f32' in s
    s = BY['wb_storagedev']['semantics']
    assert '0x15 (21)' in s
    s = BY['wb_genelectric']['semantics']
    assert '0xf (15)' in s and '0x14 (20)' in s


def test_solar_and_light():
    s = BY['wb_solarlight_full']['semantics']
    for needle in ('tileIsAirOrSnow', '__wrap_powf', '0x2e'):
        assert needle in s, needle
    s = BY['wb_getlightrgb']['semantics']
    assert '(48, 130, 220)' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_electricity()
    test_solar_and_light()
    print('test_wbelectric_evidence: OK')
