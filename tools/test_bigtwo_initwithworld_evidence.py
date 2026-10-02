#!/usr/bin/env python3
"""Dual-mode evidence guard for batch b3m-3 (FreeBlock/Workbench — the
FINAL closeout of the initWithWorld front).

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
TOOL = ROOT / 'tools/recover_bigtwo_initwithworld.py'
JSON_PATH = (ROOT / 'reconstruction/reverse-v3/native/'
             'bigtwo_initwithworld.json')

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    data = json.loads(JSON_PATH.read_text())
    check(data['batch'] == 'b3m3', 'batch must be b3m3')
    check(data['elf_sha256'] == SHA, 'elf sha drift')
    check(len(data['classes']) == 2, 'must cover two classes')
    by_class = {c['class']: c for c in data['classes']}
    check(set(by_class) == {'FreeBlock', 'Workbench'}, 'class set drift')

    fb = by_class['FreeBlock']
    check(int(fb['imp'], 16) == 0x00626A68, 'FreeBlock imp drift')
    check(fb['code_words'] == 1347, 'FreeBlock word count drift')
    check(fb['runtime_superclass'] == 'DynamicObject', 'FreeBlock super drift')
    check(len(fb['own_keys']) == 12, f'FreeBlock key count drift {len(fb["own_keys"])}')
    check('priorityBlockheadUinqueID' in fb['own_keys'],
          'FreeBlock must preserve the original typo key')
    check(fb['hooks'] == ['initSubDerivedObjects'],
          f'FreeBlock hook drift {fb.get("hooks")}')

    wb = by_class['Workbench']
    check(int(wb['imp'], 16) == 0x00AE4ED8, 'Workbench imp drift')
    check(wb['code_words'] == 1390, 'Workbench word count drift')
    check(wb['runtime_superclass'] == 'InteractionObject', 'Workbench super drift')
    # 25 key READS over 24 distinct keys: currentBlockheadIndexFuel appears
    # TWICE in the pool (two read sites), which the set-based pool scan
    # collapses to one entry.
    check(len(wb['own_keys']) == 24, f'Workbench key count drift {len(wb["own_keys"])}')
    check('craftingItemData' in wb['own_keys'] and
          'craftingItemDatav2' in wb['own_keys'],
          'Workbench v1->v2 migration pair missing')
    check(sorted(wb['child_classrefs']) == [
        'ArtificialLight', 'BlockheadCraftableItemObject',
        'CraftableItemObject', 'InventoryItem', 'NSMutableArray',
        'NSString', 'PaintingCraftableItemObject'],
        f'Workbench child classrefs drift {wb["child_classrefs"]}')

    census = data['census']
    check(census['covered_after_b3m3'] == 60, 'census covered drift')
    check(census['covered_words_after_b3m3'] == 13820,
          'census covered words drift')
    check(census['remaining_methods'] == 0, 'front must be closed')
    check(census['remaining_words'] == 0, 'front words must be zero')

    if ELF.exists() and os.environ.get('BLOCKHEADS_SKIP_HOST') != '1':
        import hashlib
        check(hashlib.sha256(ELF.read_bytes()).hexdigest() == SHA,
              'ELF sha mismatch')
        r = subprocess.run([sys.executable, str(TOOL), str(ELF), '--check'],
                           capture_output=True, text=True)
        check(r.returncode == 0, f'--check failed: {r.stdout} {r.stderr[-400:]}')
        r2 = subprocess.run([sys.executable, str(TOOL), str(ELF),
                             '--self-test'], capture_output=True, text=True)
        check(r2.returncode == 0 and '4/4' in r2.stdout,
              f'self-test failed: {r2.stdout[-400:]} {r2.stderr[-400:]}')
    else:
        print('b3m3 evidence: static contract only '
              '(no pinned ELF or no Unicorn on this host)')

    if failures:
        print('b3m3 evidence: FAIL')
        for f in failures:
            print(f'  - {f}')
        raise SystemExit(1)
    print('b3m3 evidence: PASS')


if __name__ == '__main__':
    main()
