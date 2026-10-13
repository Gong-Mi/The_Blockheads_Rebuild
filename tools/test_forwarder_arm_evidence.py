#!/usr/bin/env python3
"""CI-safe evidence guard for the forwarder ARM differential (batch b4c).

Host, when both the pinned ELF and Unicorn are present: runs the differential
over all five entries and asserts it matched with identical traces. Without
them (CI): asserts the recovered C++ contract, its CTest registration, the
CMake/workflow registrations, and that the b3f decode (shared skeleton hash,
five classes, runtime superclass NPC) is still the frozen one.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
SKELETON_SHA = ('bbd0bc16ac1ca4e3776bafe9153a6067'
                '2ca15a66b68d4efffad33581d804f1c8')
ENTRIES = {'ClownFish', 'Shark', 'Scorpion', 'Dodo', 'DonkeyLike'}


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'object_forwarder_init.h').read_text()
    source = (RECOVERED / 'object_forwarder_init.cpp').read_text()
    contract = (ROOT / 'tools/test_object_forwarder_init.cpp').read_text()
    harness = (ROOT / 'tools/test_forwarder_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    decode = json.loads((NATIVE / 'forwarder5_initwithworld.json').read_text())

    assert 'initWithWorld:dynamicWorld:saveDict:cache:' in header
    assert 'loadDerivedStuff' in header and 'b4c' in header
    assert 'ForwarderCall::SuperInit' in source
    assert 'ForwarderCall::PostInitHook' in source
    assert 'nil super → returns nil' in contract
    assert 'loadDerivedStuff' in harness
    for cls in ENTRIES:
        assert cls in harness, cls
        assert decode['classes'] and cls in {c['class'] for c in decode['classes']}
    assert 'object_forwarder_init.cpp' in cmake
    assert 'recovered_object_forwarder_init' in cmake
    assert 'test_forwarder_arm_evidence.py' in workflow

    # The b3f decode this contract describes must still be the frozen one.
    assert decode['shared_skeleton_sha256'] == SKELETON_SHA
    assert decode['shared_skeleton_words'] == 69
    assert {c['class'] for c in decode['classes']} == ENTRIES
    for c in decode['classes']:
        assert c['runtime_superclass'] == 'NPC', c['class']
        assert c['code_words'] == 74, c['class']
        assert c['own_keys'] == [] and c['own_ivars'] == [], c['class']
        assert c['skeleton_sha256'] == SKELETON_SHA, c['class']

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/forwarder-arm-differential'
        r = subprocess.run([sys.executable, str(ROOT / 'tools/test_forwarder_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('forwarder ARM differential failed')
        report = json.loads((out / 'forwarder-arm-result.json').read_text())
        assert report['match'] is True
        assert report['identical_traces_across_entries'] is True
        assert report['entries'] == 5 and report['cases'] == 10
        print(f"b4c ARM differential: {report['entries']} entries / "
              f"{report['cases']} cases matched, identical traces")
    else:
        print('b4c evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4c evidence: PASS')


if __name__ == '__main__':
    main()
