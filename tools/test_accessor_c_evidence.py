#!/usr/bin/env python3
"""Contract test for the DynamicWorld door/boat/train accessor family C (E38)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'ACCESSOR_C.md').read_text()
DATA = json.loads((NATIVE / 'accessor_c.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_windowatpos_', 'wtl_addwindowatpos_oftype_', 'wtl_removewindowatpos_',
         'wtl_adddooratpos_oftype_sa', 'wtl_dooratpos_', 'wtl_doorcanbeusedbypathuse',
         'wtl_doorisopenatpos_', 'wtl_setdooratpos_toopen_di', 'wtl_posofdoorsotherblockat',
         'wtl_placeboatinwateratpos_', 'wtl_checkforboatundertap_', 'wtl_boatwithid_',
         'wtl_checkfortraincarundert', 'wtl_traincarwithid_']

IMPS = ['0x008ed3a4', '0x008ed414', '0x008ed4b8', '0x008ed56c', '0x008ed7c0', '0x008ed950',
        '0x008edb58', '0x008ef3c8', '0x008ef488', '0x008ee1f0', '0x008ee3e8', '0x008ee5e4',
        '0x008eef50', '0x008ef18c']

COUNTS = {
    'wtl_windowatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_addwindowatpos_oftype_': (1, 0, 0, 0, 1, 0),
    'wtl_removewindowatpos_': (2, 1, 0, 0, 2, 0),
    'wtl_adddooratpos_oftype_sa': (3, 0, 0, 1, 6, 9),
    'wtl_dooratpos_': (2, 1, 0, 0, 4, 7),
    'wtl_doorcanbeusedbypathuse': (6, 1, 1, 1, 7, 4),
    'wtl_doorisopenatpos_': (2, 1, 0, 0, 2, 3),
    'wtl_setdooratpos_toopen_di': (2, 1, 0, 0, 2, 0),
    'wtl_posofdoorsotherblockat': (1, 0, 0, 0, 8, 6),
    'wtl_placeboatinwateratpos_': (5, 1, 1, 3, 6, 1),
    'wtl_checkforboatundertap_': (1, 0, 0, 1, 2, 5),
    'wtl_boatwithid_': (0, 0, 0, 2, 4, 4),
    'wtl_checkfortraincarundert': (1, 0, 0, 1, 2, 8),
    'wtl_traincarwithid_': (0, 0, 0, 2, 4, 7),
}

WORDS = [28, 41, 45, 149, 100, 130, 56, 48, 100, 126, 127, 71, 143, 143]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1307
    for needle in ('1307', '0x1f (31)', '0x14 (20)', '0x180', '0x00E4AA0C', '0x46',
                   'ffe23664', 'ffe2af8c'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_door_family():
    s = BY['wtl_adddooratpos_oftype_sa']['semantics']
    for needle in ('0x14', 'tileAtWorldPositionLoaded', '0x46', 'strb r2, [r3, 0xc]'):
        assert needle in s, needle
    s = BY['wtl_dooratpos_']['semantics']
    for needle in ('sub ip, ip, 1', 'makeIntpair', 'ffe235f0'):
        assert needle in s, needle
    s = BY['wtl_posofdoorsotherblockat']['semantics']
    for needle in ('makeIntpair', 'mvn r0, 0'):
        assert needle in s, needle


def test_boat_train():
    s = BY['wtl_boatwithid_']['semantics']
    for needle in ('0x180', '__count_unique', 'ffffe54c', 'ffffe550'):
        assert needle in s, needle
    s = BY['wtl_checkfortraincarundert']['semantics']
    for needle in ('0x00E4AA0C', 'ffe23664'):
        assert needle in s, needle
    s = BY['wtl_trainincarwithid_' if False else 'wtl_traincarwithid_']['semantics']
    for needle in ('0x00E4AA0C', '__count_unique'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_door_family()
    test_boat_train()
    print('test_accessor_c_evidence: OK')
