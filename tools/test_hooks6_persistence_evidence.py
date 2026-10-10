#!/usr/bin/env python3
"""Dual-mode evidence guard for batch b3n (the six persistence hooks —
PERSISTENCE CORE CLOSED).

Host mode (pinned ELF present): re-runs the recovery tool `--check` and
its mutation `--self-test`.

CI mode (no ELF): static assertions over the checked-in evidence.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
TOOL = ROOT / 'tools/recover_hooks6_persistence.py'
JSON_PATH = (ROOT / 'reconstruction/reverse-v3/native/'
             'hooks6_persistence_closeout.json')

EXPECT = {
    ('Tree', 'growInTimeSinceSaved:'): (0x004C2568, 546, 0),
    ('TradingPost', 'initSlotsWithSaveDict:'): (0x005E4914, 243, 1),
    ('NPC', 'loadValuesFromSaveDict:'): (0x00643B20, 603, 15),
    ('DynamicObject', 'initDerivedStuff:loadPhysicalBlockIfNeeded:'):
        (0x00839508, 242, 0),
    ('FreightCar',
     'initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:'):
        (0x00A403E8, 134, 0),
    ('TradePortal', 'loadPriceOffsets:'): (0x00D37A78, 197, 0),
}

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    data = json.loads(JSON_PATH.read_text())
    check(data['batch'] == 'b3n', 'batch must be b3n')
    check(data['elf_sha256'] == SHA, 'elf sha drift')
    check(len(data['classes']) == 6, 'must cover six methods')
    seen = {(c['class'], c['selector']) for c in data['classes']}
    check(seen == set(EXPECT), f'method set drift: {sorted(seen)}')
    for c in data['classes']:
        imp, words, keys = EXPECT[(c['class'], c['selector'])]
        check(int(c['imp'], 16) == imp, f"{c['class']}: imp drift")
        check(c['code_words'] == words, f"{c['class']}: word count drift")
        check(len(c['own_keys']) == keys,
              f"{c['class']}: key count drift {len(c['own_keys'])}")
    npc = next(c for c in data['classes'] if c['class'] == 'NPC')
    check(npc['own_keys'] == sorted([
        'age', 'breed', 'currentBlockheadIndex', 'damage', 'fullness',
        'hasBeenFedByBlockheadOrChest', 'hasBred', 'layCooldownTimer',
        'layTimer', 'mateBreed', 'mateCooldownTimer', 'name',
        'tameCooldownTimer', 'tameCountsByClientID', 'tamedClientID']),
        'NPC key set drift')
    fc = next(c for c in data['classes'] if c['class'] == 'FreightCar')
    check(fc['runtime_superclass'] == 'TrainCar', 'FreightCar super drift')
    census = data['census']
    check(census['covered_after_b3n'] == 149, 'census covered drift')
    check(census['remaining_methods'] == 0, 'core must be closed')

    if ELF.exists() and os.environ.get('BLOCKHEADS_SKIP_HOST') != '1':
        import hashlib
        check(hashlib.sha256(ELF.read_bytes()).hexdigest() == SHA,
              'ELF sha mismatch')
        r = subprocess.run([sys.executable, str(TOOL), str(ELF), '--check'],
                           capture_output=True, text=True)
        check(r.returncode == 0, f'--check failed: {r.stdout} {r.stderr[-400:]}')
        r2 = subprocess.run([sys.executable, str(TOOL), str(ELF),
                             '--self-test'], capture_output=True, text=True)
        check(r2.returncode == 0 and '8/8' in r2.stdout,
              f'self-test failed: {r2.stdout[-400:]} {r2.stderr[-400:]}')
    else:
        print('b3n evidence: static contract only '
              '(no pinned ELF or no Unicorn on this host)')

    if failures:
        print('b3n evidence: FAIL')
        for f in failures:
            print(f'  - {f}')
        raise SystemExit(1)
    print('b3n evidence: PASS')


if __name__ == '__main__':
    main()
