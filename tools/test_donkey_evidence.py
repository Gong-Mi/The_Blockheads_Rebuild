#!/usr/bin/env python3
"""Contract test for the Donkey class (E96)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DONKEY.md').read_text()
DATA = json.loads((NATIVE / 'donkey.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['d_npctype', 'd_maxage', 'd_minfullness', 'd_foodplanttype', 'd_speciesname', 'd_fooditemtype', 'd_captureditemtype', 'd_capturerequireditemtype', 'd_getnamesarray', 'd_getnamesarraycount', 'd_creationdatastructsize', 'd_loadderivedstuff', 'd_dealloc', 'd_maxhealth', 'd_flies', 'd_canjumpmultipletileswhilefly', 'd_galloping', 'd_maxvelocity', 'd_setupmatrices_dt_', 'd_drawsubclassstuff_projection', 'd_createitemdropsfordeath', 'd_generatebreedforchild', 'd_breedstring', 'd_blockheadcanride_usingitem_', 'd_cxx_construct']
IMPS = ['0x006ba498', '0x006ba4b4', '0x006ba4e4', '0x006ba518', '0x006ba570', '0x006ba5e0', '0x006ba638', '0x006ba690', '0x006ba6ac', '0x006ba71c', '0x006ba774', '0x006ba790', '0x006bc680', '0x006bc8f4', '0x006bc910', '0x006bc960', '0x006bc9b0', '0x006bca88', '0x006bcad8', '0x006c4ba4', '0x006ca8a0', '0x006cad1c', '0x006caedc', '0x006cb018', '0x006cb1f4']
COUNTS = {'d_npctype': (0, 0, 0, 0, 0, 0), 'd_maxage': (0, 0, 0, 0, 0, 0), 'd_minfullness': (0, 0, 0, 0, 0, 0), 'd_foodplanttype': (0, 0, 0, 1, 0, 0), 'd_speciesname': (0, 2, 0, 1, 0, 0), 'd_fooditemtype': (0, 0, 0, 2, 0, 0), 'd_captureditemtype': (0, 0, 0, 1, 0, 0), 'd_capturerequireditemtype': (0, 0, 0, 0, 0, 0), 'd_getnamesarray': (0, 0, 0, 1, 0, 0), 'd_getnamesarraycount': (0, 0, 0, 1, 0, 0), 'd_creationdatastructsize': (0, 0, 0, 0, 0, 0), 'd_loadderivedstuff': (8, 40, 4, 25, 74, 15), 'd_dealloc': (2, 2, 1, 9, 10, 0), 'd_maxhealth': (0, 0, 0, 2, 0, 0), 'd_flies': (0, 0, 0, 2, 0, 0), 'd_canjumpmultipletileswhilefly': (0, 0, 0, 1, 0, 0), 'd_galloping': (0, 0, 0, 3, 0, 2), 'd_maxvelocity': (0, 0, 0, 1, 0, 0), 'd_setupmatrices_dt_': (2, 1, 1, 40, 77, 20), 'd_drawsubclassstuff_projection': (21, 4, 1, 27, 115, 14), 'd_createitemdropsfordeath': (2, 1, 0, 9, 17, 30), 'd_generatebreedforchild': (0, 0, 0, 4, 5, 12), 'd_breedstring': (0, 0, 0, 1, 1, 0), 'd_blockheadcanride_usingitem_': (2, 1, 0, 5, 2, 7), 'd_cxx_construct': (0, 0, 0, 0, 0, 0)}
WORDS = [7, 25, 13, 22, 28, 51, 29, 7, 28, 29, 7, 1799, 157, 47, 40, 20, 54, 20, 7321, 5391, 417, 130, 18, 119, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 15785
    for needle in ('15785', 'sinf', 'glUniformMatrix4fv', 'nameForDonkeyBreed', '0xde1', '0x384'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_donkey():
    s = BY['d_setupmatrices_dt_']['semantics']
    assert 'sinf' in s
    s = BY['d_drawsubclassstuff_projection']['semantics']
    assert 'glUniformMatrix4fv' in s
    s = BY['d_createitemdropsfordeath']['semantics']
    assert 'nameForDonkeyBreed' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_donkey()
    print('test_donkey_evidence: OK')
