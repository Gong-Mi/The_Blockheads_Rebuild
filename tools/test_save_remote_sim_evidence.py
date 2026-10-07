#!/usr/bin/env python3
"""Contract test for the DynamicWorld save/remote/simulate cluster (E40)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'SAVE_REMOTE_SIM.md').read_text()
DATA = json.loads((NATIVE / 'save_remote_sim.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_savedynamicobjects', 'wtl_remotecreate_forobject', 'wtl_loadclientowneddynamic',
         'wtl_finishsimulating', 'wtl_removesavedinventoryfo', 'wtl_saferemovefromdynamico',
         'wtl_mainthreadremovedirfro', 'wtl_removeportalfromlistat', 'wtl_simulate_',
         'wtl_update_accuratedt_', 'wtl_setserver_serverclient']

IMPS = ['0x008b254c', '0x008c3c08', '0x008bd6bc', '0x008cbc8c', '0x008b8dc0', '0x008b8c58',
        '0x008ae490', '0x008b8b80', '0x008c9740', '0x008c9810', '0x008ad2b4']

COUNTS = {
    'wtl_savedynamicobjects': (2, 1, 0, 3, 4, 14),
    'wtl_remotecreate_forobject': (7, 1, 2, 1, 7, 5),
    'wtl_loadclientowneddynamic': (5, 2, 1, 2, 7, 12),
    'wtl_finishsimulating': (4, 1, 0, 1, 7, 7),
    'wtl_removesavedinventoryfo': (4, 2, 1, 0, 9, 4),
    'wtl_saferemovefromdynamico': (4, 1, 1, 2, 4, 0),
    'wtl_mainthreadremovedirfro': (3, 1, 0, 1, 3, 1),
    'wtl_removeportalfromlistat': (1, 1, 0, 2, 2, 0),
    'wtl_simulate_': (2, 2, 0, 0, 2, 2),
    'wtl_update_accuratedt_': (1, 1, 0, 0, 1, 0),
    'wtl_setserver_serverclient': (0, 0, 0, 2, 0, 0),
}

WORDS = [284, 151, 191, 173, 129, 90, 74, 54, 88, 36, 27]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1297
    for needle in ('1297', '0x2e (46)', '0x18 (24)', '0xe (14', 'objectTypeCanBeLoadedOnlyWhenClientOwnerOnline',
                   '0xfff33f84', '0xfff33ef4', '8.0', 'ffffe51c', 'ffffe514'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_save_and_remote():
    s = BY['wtl_savedynamicobjects']['semantics']
    for needle in ('ffffe578', '0x2e (46)', '0x18 (24)', 'ffffe518'):
        assert needle in s, needle
    s = BY['wtl_remotecreate_forobject']['semantics']
    for needle in ('0xe (14', 'ffffe53c', 'ffe2aeb4'):
        assert needle in s, needle
    s = BY['wtl_loadclientowneddynamic']['semantics']
    for needle in ('objectTypeCanBeLoadedOnlyWhenClientOwnerOnline', '0xfff33f84'):
        assert needle in s, needle


def test_sim_and_removals():
    s = BY['wtl_simulate_']['semantics']
    for needle in ('8.0', 'ffe234e8', '0..8'):
        assert needle in s, needle
    s = BY['wtl_removeportalfromlistat']['semantics']
    for needle in ('ffffe4e8', 'ffe2336c'):
        assert needle in s, needle
    s = BY['wtl_setserver_serverclient']['semantics']
    for needle in ('ffffe51c', 'ffffe514'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_save_and_remote()
    test_sim_and_removals()
    print('test_save_remote_sim_evidence: OK')
