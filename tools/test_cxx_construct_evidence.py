#!/usr/bin/env python3
"""Contract test for the DynamicWorld .cxx_construct member chain (E66)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CXX_CONSTRUCT.md').read_text()
DATA = json.loads((NATIVE / 'cxx_construct.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_cxx_construct']
IMPS = ['0x00907218']
WORDS = [866]
COUNTS = {'wtl_cxx_construct': (0, 0, 0, 20, 5, 8)}


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 866
    for needle in ('866', '0x30c', 'ffffe54c', 'ffffe554', 'ffffe588', 'Vector::Vector()',
                   'ffffe578', '262/262', 'LISTING-TEXT'):
        assert needle in DOC, needle


def test_inventory_claims():
    s = BY['wtl_cxx_construct']['semantics']
    for needle in ('0x30c (65-segment)', 'ffffe550', 'ffffe554', 'ffffe588',
                   'Vector::Vector()', 'ffffe5c8', '1.0f'):
        assert needle in s, needle


def test_collision_note():
    assert 'disasm_dynamicworld_cxx_construct.txt' in DOC
    assert 'disasm_worldtileloader_cxx_construct.txt' in DOC


if __name__ == '__main__':
    test_bodies()
    test_inventory_claims()
    test_collision_note()
    print('test_cxx_construct_evidence: OK')
