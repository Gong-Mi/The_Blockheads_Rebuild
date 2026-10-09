#!/usr/bin/env python3
"""Contract test for the World admin/moderation line (E109)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_ADMIN.md').read_text()
DATA = json.loads((NATIVE / 'world_admin.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wa_00', 'wa_01', 'wa_02', 'wa_03', 'wa_04', 'wa_05', 'wa_06', 'wa_07', 'wa_08']
IMPS = ['0x005d70b4', '0x005d5b10', '0x005d5710', '0x005d0410', '0x005cfea4', '0x005cfa88', '0x005d0e54', '0x005d218c', '0x005d1aa4']
COUNTS = {'wa_00': (3, 2, 0, 2, 6, 53), 'wa_01': (6, 3, 1, 3, 14, 9), 'wa_02': (8, 2, 3, 5, 11, 5), 'wa_03': (10, 8, 2, 1, 11, 1), 'wa_04': (7, 2, 0, 3, 6, 3), 'wa_05': (7, 3, 3, 3, 10, 7), 'wa_06': (11, 10, 3, 2, 16, 14), 'wa_07': (10, 6, 1, 2, 8, 1), 'wa_08': (11, 5, 2, 3, 12, 4)}
WORDS = [440, 284, 256, 303, 162, 222, 353, 239, 316]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2575
    for needle in ('2575', '440', '353', 'customRulesChanged', 'gzipDeflate',
                   'sendDataToServer:reliable:', 'BlockAlertView', 'mutedPlayers',
                   'reportedPlayerName', '0x55468c'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_admin():
    s = BY['wa_02']['semantics']
    assert 'dataWithPropertyList' in s
    s = BY['wa_06']['semantics']
    assert 'stringByReplacingOccurrencesOfString' in s
    s = BY['wa_05']['semantics']
    assert 'NSSearchPathForDirectoriesInDomains' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.mutedPlayers' in symbols
    assert 'OBJC_IVAR_$_World.kickbanAlertView' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_admin()
    print('test_worldadmin_evidence: OK')
