#!/usr/bin/env python3
"""Evidence guard for the Tree fruit-record slice (batch b4e stage 2).

Static mode (always, CI included): the decoded record facts must be present in
the recovered module, the C++ contract and the ARM harness must share the same
fruit-case table, and CMake/workflow must register both.

Host mode (only when the pinned ELF is present): runs
tools/test_tree_loadsave_arm_stage2.py and asserts its JSON report.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
HEADER = ROOT / 'reconstruction/recovered/tree_load_records.h'
IMPL = ROOT / 'reconstruction/recovered/tree_load_records.cpp'
CONTRACT = ROOT / 'tools/test_tree_load_records.cpp'
HARNESS = ROOT / 'tools/test_tree_loadsave_arm_stage2.py'
CMAKE = ROOT / 'reconstruction/recovered/CMakeLists.txt'
WORKFLOW = ROOT / '.github/workflows/method-save.yml'

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def main():
    for path in (HEADER, IMPL, CONTRACT, HARNESS):
        check(path.exists(), f'missing {path.relative_to(ROOT)}')
    if failures:
        report()

    header = HEADER.read_text()
    impl = IMPL.read_text()
    harness = HARNESS.read_text()
    contract = CONTRACT.read_text()

    # Decoded record geometry (b3a static decode, b4e executed).
    check('stride 0xc' in header, 'header must state the 0xc record stride')
    check('+0  pos.x word' in header and '+4  pos.y word' in header,
          'header must pin pos.x@+0 and pos.y@+4')
    check('hasCreatedFreeBlockThisSeason byte' in header,
          'header must pin the +8 flag byte')
    check('treeFruits@124' in header and 'fruitCount@128' in header,
          'header must pin the treeFruits@124 buffer and fruitCount@128')
    check('tileIsKindOfSelf:' in header and 'uniqueID@40' in header,
          'header must state the identity gate')
    check('++result.fruit_count' in impl,
          'impl must advance fruitCount per written record')
    check('if (!fruit.identity_matches)' in impl,
          'impl must model the identity gate skip')

    # Harness must execute the original entry and use the real veneer slots.
    lowered = harness.lower()
    check('0x004c2df0' in lowered, 'harness must target the original entry')
    check('0x0105fb18' in lowered and '0x0105b7a0' in lowered,
          'harness must stub both msgSend slots (method + world accessor veneer)')
    check('0x0105fb70' in lowered, 'harness must route the memset veneer')
    check('worldWidthMacro' in harness and 'macroTiles' in harness,
          'harness must answer the world accessor queries')
    check('0x4c3218' in lowered, 'harness must fit the identity at 0x4c3218')

    # Shared fruit-case table (harness FRUIT_CASES vs contract cases).
    harness_cases = re.search(r'FRUIT_CASES = \[(.*?)\n\]', harness, re.S)
    check(harness_cases is not None, 'harness must define FRUIT_CASES')
    if harness_cases:
        rows = re.findall(r'\[(.*?)\]', harness_cases.group(1), re.S)
        tuples = [row for row in rows if row.strip() and '(' in row]
        check(len(tuples) >= 4, f'expected >=4 non-empty fruit rows, got {len(tuples)}')
        check('(5, 6, 1)' in harness_cases.group(1),
              'harness fruit table must contain the (5,6,1) row')
        for row in ('{{5, 6, 1}}', '{{1, 2, 0}, {3, 4, 1}}'):
            check(row in contract,
                  f'contract must match the harness fruit table row {row}')
    check('negative_control' in harness,
          'harness must carry the identity-skip negative control')

    # Registration.
    cmake = CMAKE.read_text()
    check('blockheads_recovered_tree_records' in cmake,
          'CMakeLists must build the records library')
    check('recovered_tree_load_records' in cmake,
          'CMakeLists must register the records contract test')
    workflow = WORKFLOW.read_text()
    check('test_tree_load_records_arm_evidence.py' in workflow,
          'workflow must run this guard')

    # The stage-1 guard must remain registered (no regression).
    check((ROOT / 'tools/test_tree_loadsave_arm_evidence.py').exists(),
          'stage-1 guard must still exist')

    if os.environ.get('BLOCKHEADS_SKIP_HOST') != '1' and ELF.exists():
        import hashlib
        digest = hashlib.sha256(ELF.read_bytes()).hexdigest()
        check(digest == SHA, 'ELF SHA mismatch')
        out = ROOT / 'scratch/tree-records-arm'
        out.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run([sys.executable, str(HARNESS), str(ELF),
                               '--output-dir', str(out)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            failures.append(f'stage-2 harness failed: {proc.stdout[-800:]}'
                            f'{proc.stderr[-800:]}')
        else:
            report_json = json.loads(
                (out / 'tree-records-arm-result.json').read_text())
            check(report_json['stage'] == 2, 'report must be stage 2')
            check(report_json['match'] is True, 'report must record a match')
            check(report_json['cases'] >= 5, 'report must cover >=5 cases')
            check(any(row.get('negative_control') for row in report_json['rows']),
                  'report must include the identity-skip negative control row')
            for row in report_json['rows']:
                if 'cpp' in row:
                    check(row['cpp']['fruit_count'] == row['arm_fruit_count'],
                          'C++ fruit_count must equal the ARM one')
    report()


def report():
    if failures:
        print('tree records arm evidence: FAIL')
        for item in failures:
            print(f'  - {item}')
        raise SystemExit(1)
    print('tree records arm evidence: PASS')


if __name__ == '__main__':
    main()
