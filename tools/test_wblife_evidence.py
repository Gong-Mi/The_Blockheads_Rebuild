#!/usr/bin/env python3
"""Contract test for the Workbench save/net/lifecycle cluster (E77)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_LIFECYCLE.md').read_text()
DATA = json.loads((NATIVE / 'workbench_lifecycle.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wl_getsavedict', 'wl_worldchanged', 'wl_remove', 'wl_ctor_save', 'wl_ctor_net',
         'wl_remoteupdate', 'wl_bhloaded', 'wl_updatenet', 'wl_dealloc', 'wl_upgrade',
         'wl_setneedsremoved', 'wl_setpaused', 'wl_remotebhremoved', 'wl_setlevel']

IMPS = ['0x00ae81d0', '0x00afcb38', '0x00afd874', '0x00ae4ed8', '0x00ae6490', '0x00aff768',
        '0x00ae6ed8', '0x00ae9510', '0x00ae6c3c', '0x00afeae0', '0x00afe4c4', '0x00b02060',
        '0x00b01180', '0x00afe968']

COUNTS = {
    'wl_getsavedict': (18, 24, 5, 24, 57, 27),
    'wl_worldchanged': (3, 1, 0, 5, 27, 39),
    'wl_remove': (7, 1, 0, 13, 11, 17),
    'wl_ctor_save': (26, 28, 8, 31, 80, 32),
    'wl_ctor_net': (13, 4, 1, 12, 21, 8),
    'wl_remoteupdate': (33, 6, 3, 27, 62, 72),
    'wl_bhloaded': (7, 2, 1, 6, 8, 7),
    'wl_updatenet': (7, 3, 2, 10, 10, 10),
    'wl_dealloc': (3, 2, 1, 6, 7, 2),
    'wl_upgrade': (13, 7, 2, 8, 37, 19),
    'wl_setneedsremoved': (3, 1, 1, 4, 4, 3),
    'wl_setpaused': (1, 1, 0, 2, 1, 1),
    'wl_remotebhremoved': (1, 0, 1, 2, 1, 2),
    'wl_setlevel': (4, 0, 0, 5, 4, 0),
}

WORDS = [1232, 605, 404, 1390, 482, 1670, 220, 312, 167, 802, 94, 53, 65, 94]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 7590
    for needle in ('7590', 'reloadDrawBlockLightGlowQuadsForTile',
                   'reloadDrawBlockDynamicObjectStaticGeometryForTile', 'cmn r0, 1',
                   '__wrap_free', '0x28'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_render_and_save():
    s = BY['wl_ctor_save']['semantics']
    assert 'reloadDrawBlockLightGlowQuadsForTile' in s
    s = BY['wl_remoteupdate']['semantics']
    assert 'reloadDrawBlockDynamicObjectStaticGeometryForTile' in s
    s = BY['wl_getsavedict']['semantics']
    assert 'objc_enumerationMutation' in s and 'fff3bf94' in s


def test_lifecycle():
    s = BY['wl_bhloaded']['semantics']
    assert 'cmn r0, 1' in s
    for n in ('wl_remove', 'wl_setneedsremoved'):
        assert 'type == 1 exits' in BY[n]['semantics'], n
    s = BY['wl_dealloc']['semantics']
    assert '__wrap_free' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_render_and_save()
    test_lifecycle()
    print('test_wblife_evidence: OK')
