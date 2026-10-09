#!/usr/bin/env python3
"""Contract test for the NPC core (E117)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'NPC_CORE.md').read_text()
DATA = json.loads((NATIVE / 'npc_core.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['np_00', 'np_01', 'np_02', 'np_03', 'np_04', 'np_05', 'np_06', 'np_07', 'np_08', 'np_09', 'np_10', 'np_11', 'np_12', 'np_13', 'np_14', 'np_15', 'np_16', 'np_17', 'np_18', 'np_19', 'np_20', 'np_21', 'np_22', 'np_23', 'np_24', 'np_25', 'np_26', 'np_27', 'np_28', 'np_29']
IMPS = ['0x006513e4', '0x0064bf30', '0x00647cf8', '0x006468d0', '0x00645aac', '0x0064b398', '0x00650b10', '0x00650218', '0x00644e94', '0x0064ad80', '0x00649894', '0x00644718', '0x0064fd60', '0x0064f124', '0x0064a9f8', '0x0064f6c8', '0x0064e8d8', '0x0064f444', '0x0064f9a0', '0x0064eb64', '0x0064567c', '0x00649fec', '0x0064e604', '0x00649670', '0x0064ef20', '0x00644ca0', '0x0064a2f0', '0x00646738', '0x0064448c', '0x0064589c']
COUNTS = {'np_00': (0, 0, 0, 1, 0, 0), 'np_01': (20, 7, 3, 15, 67, 42), 'np_02': (35, 4, 2, 13, 63, 91), 'np_03': (19, 2, 0, 29, 37, 55), 'np_04': (9, 18, 2, 17, 37, 14), 'np_05': (19, 2, 2, 13, 27, 25), 'np_06': (4, 1, 1, 7, 24, 29), 'np_07': (13, 1, 0, 6, 20, 21), 'np_08': (3, 1, 0, 19, 5, 27), 'np_09': (5, 2, 2, 3, 22, 6), 'np_10': (15, 2, 2, 9, 15, 10), 'np_11': (9, 2, 1, 4, 10, 10), 'np_12': (9, 1, 0, 4, 9, 6), 'np_13': (6, 1, 0, 8, 8, 3), 'np_14': (6, 2, 0, 4, 9, 6), 'np_15': (8, 1, 0, 5, 8, 3), 'np_16': (3, 2, 0, 3, 5, 7), 'np_17': (6, 1, 0, 6, 6, 4), 'np_18': (5, 1, 0, 5, 5, 3), 'np_19': (3, 2, 0, 4, 4, 8), 'np_20': (5, 2, 3, 1, 5, 3), 'np_21': (2, 1, 0, 5, 2, 4), 'np_22': (5, 1, 0, 5, 7, 2), 'np_23': (5, 1, 0, 6, 5, 2), 'np_24': (3, 1, 0, 6, 4, 4), 'np_25': (2, 2, 1, 5, 2, 2), 'np_26': (2, 1, 0, 3, 2, 5), 'np_27': (0, 0, 0, 0, 5, 0), 'np_28': (1, 1, 0, 3, 5, 0), 'np_29': (3, 1, 1, 0, 4, 2)}
WORDS = [18, 1832, 1432, 1261, 803, 695, 513, 469, 464, 390, 355, 259, 216, 200, 192, 182, 163, 161, 148, 142, 136, 135, 134, 132, 129, 125, 107, 102, 87, 73]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 11055
    for needle in ('11055', '1832', '1432', '1261', 'tameCountRequirementForNPCType',
                   'drawShaderQuadNoTexture', 'tileContainsTrapDoor', 'MJSoundManager',
                   '0x6445d8', 'getNamesArray'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_npc():
    s = BY['np_05']['semantics']
    assert 'tameCountRequirementForNPCType' in s
    s = BY['np_06']['semantics']
    assert 'tileContainsTrapDoor' in s
    s = BY['np_17']['semantics']
    assert 'createFreeBlockAtPosition' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_NPC.tamedClientID' in symbols
    assert 'OBJC_IVAR_$_NPC.fullness' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_npc()
    print('test_npccore_evidence: OK')
