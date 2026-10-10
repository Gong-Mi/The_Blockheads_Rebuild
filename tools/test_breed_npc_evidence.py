#!/usr/bin/env python3
"""Contract test for the DynamicWorld breeding/NPC/service cluster (E27)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BREED_NPC.md').read_text()
DATA = json.loads((NATIVE / 'breed_npc.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_npccloseenoughtobreedw', 'wtl_findbreedingplantnearp', 'wtl_getplantatpos_',
         'wtl_toomanynpcstospawnmore', 'wtl_setpaused_', 'wtl_saveblockheadinventory',
         'wtl_teleportblockhead_towo']

IMPS = ['0x008f3288', '0x008e37c0', '0x008ef6f8', '0x008f2bb4', '0x008f9580', '0x008b8634', '0x008f5658']

COUNTS = {
    'wtl_npccloseenoughtobreedw': (4, 1, 0, 2, 35, 37),
    'wtl_findbreedingplantnearp': (8, 1, 1, 2, 26, 22),
    'wtl_getplantatpos_': (3, 1, 0, 2, 18, 29),
    'wtl_toomanynpcstospawnmore': (2, 0, 0, 2, 22, 30),
    'wtl_setpaused_': (2, 1, 0, 2, 9, 15),
    'wtl_saveblockheadinventory': (12, 5, 4, 2, 17, 7),
    'wtl_teleportblockhead_towo': (6, 2, 2, 0, 20, 6),
}

WORDS = [574, 440, 465, 437, 380, 339, 326]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2961
    for needle in ('2961', '0x00E4AA3C', '0x00E4AA1C', '0x00E4AA0C', '0x00E4AA90',
                   'cylindrical wrap-distance', "0x21 ('!')", '0xfff34184', '256-iteration',
                   'ffe236f8'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_wrap_family():
    for name in ('wtl_npccloseenoughtobreedw', 'wtl_findbreedingplantnearp',
                 'wtl_toomanynpcstospawnmore'):
        s = BY[name]['semantics']
        for needle in ('worldWidthMacro', '5'):
            assert needle in s, needle


def test_lookup_and_pause():
    s = BY['wtl_getplantatpos_']['semantics']
    for needle in ('0xa', '0x00E4AA3C', 'ffe23670', 'ffe23674', 'ffffe550'):
        assert needle in s, needle
    s = BY['wtl_setpaused_']['semantics']
    for needle in ('ffffe4f8', '0x00E4AA0C', '0x00E4AA90', 'ffe236f8', 'paused byte'):
        assert needle in s, needle


def test_services():
    s = BY['wtl_saveblockheadinventory']['semantics']
    for needle in ('0x21', 'NSKeyedArchiver', 'ffffe518', '0xfff33e44', 'ffffe50c'):
        assert needle in s, needle
    s = BY['wtl_teleportblockhead_towo']['semantics']
    for needle in ('ffe236c0', '0xfff34184', '0x100 (256)', 'Vector4', '0x3f000000', 'ffe2afa0'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_wrap_family()
    test_lookup_and_pause()
    test_services()
    print('test_breed_npc_evidence: OK')
