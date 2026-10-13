#!/usr/bin/env python3
"""Contract test for the World PVP/projectile/tips line (E112)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_PVP.md').read_text()
DATA = json.loads((NATIVE / 'world_pvp.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wp_00', 'wp_01', 'wp_02', 'wp_03', 'wp_04', 'wp_05', 'wp_06', 'wp_07', 'wp_08', 'wp_09', 'wp_10']
IMPS = ['0x005c9b54', '0x005cb08c', '0x005cb550', '0x005c97dc', '0x005c937c', '0x005cba90', '0x005cb930', '0x005c96f0', '0x005c19b4', '0x005c1b58', '0x005cf334']
COUNTS = {'wp_00': (10, 2, 0, 3, 14, 15), 'wp_01': (9, 4, 3, 2, 12, 7), 'wp_02': (7, 3, 2, 3, 8, 9), 'wp_03': (7, 1, 2, 2, 7, 7), 'wp_04': (5, 1, 1, 3, 9, 5), 'wp_05': (7, 0, 2, 0, 9, 0), 'wp_06': (2, 3, 0, 2, 2, 4), 'wp_07': (2, 0, 0, 1, 4, 0), 'wp_08': (4, 2, 1, 2, 4, 6), 'wp_09': (3, 1, 1, 0, 6, 4), 'wp_10': (0, 0, 0, 1, 0, 0)}
WORDS = [321, 305, 248, 222, 221, 104, 88, 59, 105, 94, 15]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1782
    for needle in ('1782', '321', '305', 'sufferDamage:isSimulation:recoil:', 'TipManager',
                   'sendChatMessage', 'projectileManager',
                   'playerNameForPlayerWithIDIncludingOldPlayers', '0x2a', '0x29'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_pvp():
    s = BY['wp_00']['semantics']
    assert 'sufferDamage:isSimulation:recoil:' in s
    s = BY['wp_04']['semantics']
    assert 'projectileManager' in s
    s = BY['wp_06']['semantics']
    assert 'sendChatMessage' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.projectileManager' in symbols
    assert 'OBJC_IVAR_$_World.pvpEnabled' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_pvp()
    print('test_worldpvp_evidence: OK')
