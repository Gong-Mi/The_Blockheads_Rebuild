#!/usr/bin/env python3
"""Contract test for the Workbench fuel/craft-status cluster (E76)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_FUEL.md').read_text()
DATA = json.loads((NATIVE / 'workbench_fuel.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wf_updatehasfuel', 'wf_hurry', 'wf_addfuel', 'wf_addfuelitem', 'wf_startfuel',
         'wf_totalleft', 'wf_fuelitems', 'wf_crafttype', 'wf_fuelitemcount', 'wf_hasreqfuel',
         'wf_fuelcount', 'wf_doubleheight', 'wf_frac', 'wf_reqhuman', 'wf_candismiss',
         'wf_iobjtype']

IMPS = ['0x00aedb58', '0x00aed558', '0x00afdf94', '0x00b019c0', '0x00afc87c', '0x00aed318',
        '0x00b01894', '0x00aed44c', '0x00b0179c', '0x00afe31c', '0x00afdec4', '0x00afe40c',
        '0x00afe63c', '0x00afcafc', '0x00b02134', '0x00ae9b5c']

COUNTS = {
    'wf_updatehasfuel': (7, 1, 1, 11, 16, 10),
    'wf_hurry': (6, 2, 2, 7, 19, 4),
    'wf_addfuel': (6, 1, 1, 7, 7, 11),
    'wf_addfuelitem': (1, 1, 0, 2, 2, 0),
    'wf_startfuel': (6, 1, 0, 5, 6, 3),
    'wf_totalleft': (2, 0, 0, 7, 4, 10),
    'wf_fuelitems': (0, 0, 0, 2, 1, 0),
    'wf_crafttype': (1, 0, 0, 3, 2, 5),
    'wf_fuelitemcount': (0, 0, 0, 2, 1, 0),
    'wf_hasreqfuel': (0, 0, 0, 4, 0, 3),
    'wf_fuelcount': (0, 0, 0, 1, 0, 4),
    'wf_doubleheight': (0, 0, 0, 1, 1, 0),
    'wf_frac': (0, 0, 0, 1, 0, 0),
    'wf_reqhuman': (0, 0, 0, 1, 0, 0),
    'wf_candismiss': (0, 0, 0, 0, 0, 0),
    'wf_iobjtype': (0, 0, 0, 0, 0, 0),
}

WORDS = [428, 384, 226, 49, 160, 144, 25, 67, 25, 60, 52, 19, 16, 15, 7, 7]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1684
    for needle in ('1684', '0x64', '100', '124', 'fffff1a0', 'fffff160'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_fuel():
    s = BY['wf_addfuel']['semantics']
    for needle in ('0x64', 'strh', 'vmul.f32', '0xf (15)'):
        assert needle in s, needle
    s = BY['wf_hasreqfuel']['semantics']
    assert 'eor r0, r0, 1' in s
    s = BY['wf_startfuel']['semantics']
    assert 'fffff190' in s
    s = BY['wf_candismiss']['semantics']
    assert 'returns **1**' in s


def test_status():
    s = BY['wf_updatehasfuel']['semantics']
    assert 'fffff14c' in s and 'cmp r0, 3' in s
    s = BY['wf_crafttype']['semantics']
    assert '0x7c' in s
    s = BY['wf_frac']['semantics']
    assert 'fffff1a0' in s
    s = BY['wf_hurry']['semantics']
    assert 'fffff168' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_fuel()
    test_status()
    print('test_wbfuel_evidence: OK')
