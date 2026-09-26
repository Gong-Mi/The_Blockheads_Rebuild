#!/usr/bin/env python3
"""CI-safe evidence guard for the b3j forward-then-read loaders (batch ownkey5).

Five mid-size `initWithWorld:` loaders (AppleTree 102w long, TrainStation 105w,
Plant 114w long, GatherBlock 128w, Yak 134w) now carry executed differential
evidence: ONE shared recovered engine + five thin descriptor tables, executed
against the original ARM32 bodies under Unicorn.

This guard pins the structure, the registrations, and the two EXECUTED
CORRECTIONS of the b3j static decode; when the pinned ELF and Unicorn are both
present (host) it re-runs the differential and asserts its report.

CI has no pinned ELF, so there it degrades to static content assertions.

    python3 tools/test_ownkey5_init_arm_evidence.py
    HOME=<empty dir> python3 tools/test_ownkey5_init_arm_evidence.py   # CI mode
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
ELF_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
GUARD = 'test_ownkey5_init_arm_evidence.py'
CLASSES = {'AppleTree', 'TrainStation', 'Plant', 'GatherBlock', 'Yak'}
WORD_COUNTS = {'appletree': 102, 'trainstation': 105, 'plant': 114,
               'gatherblock': 128, 'yak': 134}
IMP = {'appletree': '0x009bd3b0', 'trainstation': '0x00b38f88',
       'plant': '0x009559d0', 'gatherblock': '0x008695a0',
       'yak': '0x0095dae4'}


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    engine_h = (RECOVERED / 'ownkey_loader.h').read_text()
    engine_cpp = (RECOVERED / 'ownkey_loader.cpp').read_text()
    tables = (RECOVERED / 'ownkey5_init.cpp').read_text()
    harness = (ROOT / 'tools/test_ownkey5_arm.py').read_text()
    contract = (ROOT / 'tools/test_ownkey5_init.cpp').read_text()
    module = (ROOT / 'tools/arm_harness/ownkey.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()

    # --- ONE shared engine + five thin tables (modularity is the point) -----
    assert 'OwnKeyProgram' in engine_h and 'OwnKeyStep' in engine_h
    assert 'ownkey_run' in engine_cpp
    for cls in CLASSES:
        assert f'k{cls}' in tables or f'"{cls}"' in tables, cls
    assert 'kPrograms[]' in tables and 'ownkey_program_apple_tree' in tables
    assert 'ownkey_programs()' in tables
    # the harness stays thin: Unicorn shape lives in the shared module
    assert 'class OwnKeyRunner' in module
    assert 'from arm_harness.ownkey import OwnKeyRunner' in harness

    # --- the two executed corrections of the b3j decode --------------------
    # GatherBlock: timer -> floatValue + vcvt round trip -> @56 FIRST, then
    # lastKnownGatherValue -> intValue -> @60.
    assert 'FloatValueThroughUint32, "timer", 56' in tables
    assert 'IntValue, "lastKnownGatherValue", 60' in tables
    assert 'executed selector sequence' in tables
    # Yak: milk -> floatValue -> @1136 FIRST, then hair -> floatValue -> @1140.
    assert 'FloatValue, "milk", 1136' in tables
    assert 'FloatValue, "hair", 1140' in tables
    assert tables.index('"milk", 1136') < tables.index('"hair", 1140')
    # both corrections are mirrored in the harness expectation tables
    assert 'executed correction' in harness
    assert harness.count('executed correction') >= 2

    # --- harness discipline (paid for in blood this batch) ------------------
    # fresh session per method: shared-hook and TB-cache contamination
    assert 'A FRESH session per method' in harness
    # failure domains are separate: one method must not abort the batch
    assert 'FAILURE DOMAINS ARE SEPARATE' in harness
    assert 'per_method_status' in harness
    # the store hook derives the effective address from the instruction form
    assert 'register-offset form' in module.lower() or \
        'Rn = bits 19-16' in module
    # the incoming frame always carries all four stacked args for long methods
    assert 'INCOMING frame always carries' in module

    # --- listings: the pinned IMP appears and the header names the selector --
    for name, words in WORD_COUNTS.items():
        listing = NATIVE / f'disasm_{name}_ownkey5.txt'
        assert listing.exists(), listing.name
        text = listing.read_text()
        assert 'initWithWorld:dynamicWorld:saveDict:cache:' in text, name
        assert f'# implementation: {IMP[name]}' in text, name
        assert listing.read_text().count('\n') >= words, name

    # --- registrations -----------------------------------------------------
    assert 'blockheads_recovered_ownkey5' in cmake
    assert 'recovered_ownkey5_init' in cmake
    assert 'test_ownkey5_init.cpp' in cmake
    assert GUARD in workflow, 'evidence guard not registered in the workflow'

    if ELF.exists() and have_unicorn():
        if __import__('hashlib').sha256(ELF.read_bytes()).hexdigest() != ELF_SHA:
            raise SystemExit('pinned ELF SHA mismatch')
        out = ROOT / 'scratch/ownkey5-arm-differential'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/test_ownkey5_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        report_path = out / 'ownkey5-arm-result.json'
        if not report_path.exists():
            print(r.stdout + r.stderr)
            raise SystemExit('ownkey5: differential produced no report')
        report = json.loads(report_path.read_text())
        if r.returncode != 0 or report['match'] is not True:
            print(r.stdout + r.stderr)
            print(json.dumps(report.get('per_method_failures', {}), indent=2))
            raise SystemExit('ownkey5: ARM differential did not match')
        status = report['per_method_status']
        assert set(status) == CLASSES, sorted(status)
        assert all(v == 'MATCHED' for v in status.values()), status
        print(f"ownkey5 ARM differential: {report['cases']} cases over "
              f"{len(status)} methods matched "
              f"({', '.join(sorted(status))})")
    else:
        print('ownkey5 evidence: static contract only (no pinned ELF or no '
              'Unicorn on this host)')

    print('ownkey5 evidence: PASS')


if __name__ == '__main__':
    main()
