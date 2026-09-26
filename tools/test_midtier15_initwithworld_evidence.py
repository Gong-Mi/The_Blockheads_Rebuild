#!/usr/bin/env python3
"""Dual-mode evidence guard for batch b3k (fifteen mid-tier initWithWorld
loaders, forward-then-read).

Host mode (pinned ELF present): re-runs the recovery tool `--check` and its
mutation `--self-test`.

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
TOOL = ROOT / 'tools/recover_midtier15_initwithworld.py'
JSON_PATH = (ROOT / 'reconstruction/reverse-v3/native/'
             'midtier15_initwithworld.json')

EXPECT = {
    'Window': (0x00C98944, 139, 'DynamicObject', ['itemType', 'ownerID']),
    'Bed': (0x00D407EC, 144, 'InteractionObject', ['beddingColor', 'itemType']),
    'Tree': (0x004C39A0, 146, 'DynamicObject', ['saveTime']),
    'PineTree': (0x00B64F48, 157, 'Tree', ['availableFood', 'saveTime']),
    'Rail': (0x0077AB90, 164, 'DynamicObject',
             ['configuration', 'itemType', 'ownedByStation']),
    'Sign': (0x005FA604, 166, 'InteractionObject',
             ['connectionType', 'offsetType', 'text']),
    'Boat': (0x0096B818, 168, 'DynamicObject',
             ['currentBlockheadIndex', 'ownerID']),
    'Ladder': (0x00AADCD4, 168, 'DynamicObject',
               ['itemType', 'ownerID', 'paintColor']),
    'Egg': (0x00D4E30C, 178, 'DynamicObject',
            ['breed', 'genesDict', 'hatchTimer']),
    'SteamTrain': (0x00D18834, 180, 'TrainCar',
                   ['fuelFraction', 'goingRight', 'hasFuel', 'stopped']),
    'Column': (0x00834A30, 193, 'DynamicObject',
               ['configuration', 'itemType', 'ownerID', 'paintColor']),
    'Stairs': (0x006CC734, 193, 'DynamicObject',
               ['configuration', 'itemType', 'ownerID', 'paintColor']),
    'Door': (0x007694FC, 198, 'DynamicObject',
             ['blocked', 'ironPlaceClientID', 'itemType', 'ownerID']),
    'TulipPlant': (0x009A1368, 199, 'Plant',
                   ['availableFood', 'colorGenes', 'mateColorGenes',
                    'mixGenes']),
    'Wire': (0x0095002C, 200, 'DynamicObject',
             ['configuration', 'itemType', 'ownerID', 'solidConfiguration']),
}

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    data = json.loads(JSON_PATH.read_text())
    check(data['batch'] == 'b3k', 'batch must be b3k')
    check(data['elf_sha256'] == SHA, 'elf sha drift')
    check(len(data['classes']) == 15, 'must cover fifteen classes')
    seen = {c['class'] for c in data['classes']}
    check(seen == set(EXPECT), f'class set drift: {sorted(seen)}')
    total_keys = 0
    for c in data['classes']:
        imp, words, sup, keys = EXPECT[c['class']]
        check(int(c['imp'], 16) == imp, f"{c['class']}: imp drift")
        check(c['code_words'] == words, f"{c['class']}: word count drift")
        check(c['runtime_superclass'] == sup,
              f"{c['class']}: runtime super drift")
        check(c['own_keys'] == keys, f"{c['class']}: own key set drift")
        total_keys += len(keys)
    check(total_keys == 45, f'total key reads must be 45, got {total_keys}')
    census = data['census']
    check(census['front_methods'] == 60, 'census front methods drift')
    check(census['front_words'] == 13820, 'census front words drift')
    check(census['covered_after_b3k'] == 40, 'census covered drift')
    check(census['remaining_methods'] == 20, 'census remaining drift')
    check(census['remaining_words'] == 9299, 'census remaining words drift')

    if ELF.exists() and os.environ.get('BLOCKHEADS_SKIP_HOST') != '1':
        import hashlib
        check(hashlib.sha256(ELF.read_bytes()).hexdigest() == SHA,
              'ELF sha mismatch')
        r = subprocess.run([sys.executable, str(TOOL), str(ELF), '--check'],
                           capture_output=True, text=True)
        check(r.returncode == 0, f'--check failed: {r.stdout} {r.stderr[-400:]}')
        r2 = subprocess.run([sys.executable, str(TOOL), str(ELF),
                             '--self-test'], capture_output=True, text=True)
        check(r2.returncode == 0 and '5/5' in r2.stdout,
              f'self-test failed: {r2.stdout[-400:]} {r2.stderr[-400:]}')
    else:
        print('b3k evidence: static contract only '
              '(no pinned ELF or no Unicorn on this host)')

    if failures:
        print('b3k evidence: FAIL')
        for f in failures:
            print(f'  - {f}')
        raise SystemExit(1)
    print('b3k evidence: PASS')


if __name__ == '__main__':
    main()
