#!/usr/bin/env python3
"""Contract test for NetPlayerButton (E156)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'NETPLAYERBUTTON.md').read_text()
DATA = json.loads((NATIVE / 'netplayerbutton.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ["npb_00", "npb_01", "npb_02", "npb_03", "npb_04", "npb_05", "npb_06", "npb_07", "npb_08", "npb_09", "npb_10", "npb_11", "npb_12", "npb_13", "npb_14", "npb_15", "npb_16", "npb_17", "npb_18", "npb_19", "npb_20", "npb_21", "npb_22", "npb_23", "npb_24", "npb_25", "npb_26", "npb_27", "npb_28", "npb_29", "npb_30", "npb_31", "npb_32", "npb_33", "npb_34", "npb_35"]
IMPS = ["0x00788798", "0x00788188", "0x00788cf4", "0x00788af4", "0x007853f4", "0x00787fb0", "0x00784e1c", "0x00788bf4", "0x00788c74", "0x00788b74", "0x00788818", "0x007889f4", "0x00787df4", "0x00788630", "0x00788d74", "0x0078896c", "0x007889b0", "0x00788918", "0x00785864", "0x0078602c", "0x00788898", "0x00788d30", "0x00788b30", "0x00786298", "0x00785598", "0x00788c30", "0x00788cb0", "0x00788bb0", "0x00788a30", "0x00788db0", "0x00788ab0", "0x00787d04", "0x00788a74", "0x007884b8", "0x00787c14", "0x007864f8"]
COUNTS = {"npb_00": [1, 1, 0, 2, 1, 0], "npb_01": [7, 1, 1, 6, 7, 4], "npb_02": [0, 0, 0, 1, 0, 0], "npb_03": [0, 0, 0, 1, 0, 0], "npb_04": [2, 2, 1, 5, 6, 0], "npb_05": [3, 1, 1, 1, 4, 3], "npb_06": [11, 10, 4, 11, 13, 2], "npb_07": [0, 0, 0, 1, 0, 0], "npb_08": [0, 0, 0, 1, 0, 0], "npb_09": [0, 0, 0, 1, 0, 0], "npb_10": [1, 1, 0, 2, 1, 0], "npb_11": [0, 0, 0, 1, 0, 0], "npb_12": [3, 1, 1, 1, 4, 2], "npb_13": [2, 1, 0, 5, 2, 0], "npb_14": [0, 0, 0, 1, 0, 0], "npb_15": [0, 0, 0, 1, 0, 0], "npb_16": [0, 0, 0, 1, 0, 0], "npb_17": [0, 0, 0, 1, 0, 0], "npb_18": [4, 1, 2, 7, 7, 7], "npb_19": [1, 0, 0, 1, 1, 0], "npb_20": [1, 1, 0, 2, 1, 0], "npb_21": [0, 0, 0, 1, 0, 0], "npb_22": [0, 0, 0, 1, 0, 0], "npb_23": [2, 1, 1, 5, 5, 0], "npb_24": [2, 1, 1, 6, 5, 0], "npb_25": [0, 0, 0, 1, 0, 0], "npb_26": [0, 0, 0, 1, 0, 0], "npb_27": [0, 0, 0, 1, 0, 0], "npb_28": [0, 0, 0, 1, 0, 0], "npb_29": [0, 0, 0, 1, 0, 0], "npb_30": [0, 0, 0, 1, 0, 0], "npb_31": [1, 0, 1, 1, 2, 2], "npb_32": [0, 0, 0, 1, 0, 0], "npb_33": [3, 2, 1, 2, 3, 0], "npb_34": [1, 0, 1, 1, 2, 2], "npb_35": [26, 19, 3, 21, 62, 50]}
WORDS = [32, 204, 15, 15, 105, 118, 355, 15, 15, 15, 32, 15, 111, 90, 15, 17, 17, 21, 498, 155, 32, 17, 17, 152, 179, 17, 17, 17, 17, 17, 17, 60, 15, 94, 60, 1460]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 4048
    for needle in ('4048', 'playerID', 'playerName', 'updatedPlayerIfNeeded'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == tuple(COUNTS[n]), (n, kinds(BY[n]))


def test_netplayerbutton():
    assert len(DATA['classes']) == 36
    s = BY['npb_00']['semantics']
    assert '0x00788798' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_netplayerbutton()
    print('test_netplayerbutton_evidence: OK')
