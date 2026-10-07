#!/usr/bin/env python3
"""Contract test for the WorldTileLoader compressBlocks stub (E65)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'COMPRESS_STUB.md').read_text()
DATA = json.loads((NATIVE / 'compress_stub.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_compressblocks']
IMPS = ['0x0085475c']
WORDS = [5]
COUNTS = {'wtl_compressblocks': (0, 0, 0, 0, 0, 0)}


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    for needle in ('5', 'empty stub', '0x0085475c', '52/52', '209/210'):
        assert needle in DOC, needle


def test_empty_body():
    entry = BY['wtl_compressblocks']
    assert len(entry['selectors']) == 0
    assert len(entry['ivars']) == 0
    assert len(entry['calls']) == 0
    assert len(entry['branches']) == 0
    s = entry['semantics']
    assert 'EMPTY STUB' in s
    assert 'epilogue' in s


if __name__ == '__main__':
    test_bodies()
    test_empty_body()
    print('test_compress_stub_evidence: OK')
