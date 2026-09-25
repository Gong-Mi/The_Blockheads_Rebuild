#!/usr/bin/env python3
"""CI-safe evidence guard for the client assembly app skeleton (batch b5a).

Static mode (always): the generated 1..64 type table matches the decoded
`classForDynamicObjectType` matrix, the app sources live in app/src/main/cpp and
are compiled by BOTH the production Android target and the host CI target, the
registry still defaults every type to Stub, and the loader reports instead of
guessing every unidentified/out-of-range/opaque/malformed record.

Host mode (when a built CLI is present): runs the skeleton over a synthetic
snapshot and asserts the report counters.
"""
import glob
import json
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'app/src/main/cpp'
MATRIX = ROOT / 'reconstruction/reverse-v3/native/dynamicobject_type_matrix.json'
TABLE = APP / 'dynamic_object_type_table.inc'
WORKFLOW = ROOT / '.github/workflows/method-save.yml'


def static_checks():
    # 1. Single source of truth for the type table.
    check = subprocess.run([sys.executable,
                            str(ROOT / 'tools/gen_dynamic_object_type_table.py'),
                            '--check'], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr

    sys.path.insert(0, str(ROOT / 'tools'))
    import gen_dynamic_object_type_table as gen
    expected = gen.render()
    assert TABLE.read_text() == expected
    matrix = json.loads(MATRIX.read_text())
    assert matrix['total_types'] == 64
    rows = [line for line in TABLE.read_text().splitlines() if line.startswith('    {')]
    assert len(rows) == 64, len(rows)
    for line, entry in zip(rows, matrix['types']):
        assert f'{{{entry["type_id"]}, "{entry["class_name"]}"' in line, line

    # 2. Sources in the production app directory, compiled by both targets.
    for name in ('original_save_dict', 'dynamic_object_registry', 'original_client_app'):
        assert (APP / f'{name}.h').exists(), name
        assert (APP / f'{name}.cpp').exists(), name
    host_cmake = (ROOT / 'reconstruction/recovered/CMakeLists.txt').read_text()
    android_cmake = (APP / 'CMakeLists.txt').read_text()
    for name in ('original_save_dict.cpp', 'dynamic_object_registry.cpp',
                 'original_client_app.cpp'):
        assert name in host_cmake, f'{name} missing from the host CMake target'
        assert name in android_cmake, f'{name} missing from the Android native-lib'

    # 3. The registry still starts every type as a stub, and the plug-in path is
    #    the only way to a non-stub status.
    registry = (APP / 'dynamic_object_registry.cpp').read_text()
    assert 'static_assert(kTypeCount == 64' in registry
    assert 'slots_(kTypeCount)' in registry
    assert 'slots_[i].status = ObjectLoadStatus::Stub;' in registry
    assert 'stub: per-type loader not recovered' in registry
    assert 'outside the decoded 1..64 matrix' in registry
    assert 'is outside the decoded 1..64 matrix' in registry
    header = (APP / 'dynamic_object_registry.h').read_text()
    assert 'enum class ObjectLoadStatus { Stub, Recovered, Verified };' in header

    # 4. The app reports instead of guessing.
    app = (APP / 'original_client_app.cpp').read_text()
    for marker in ('unidentified_objects++', 'out_of_range_objects++',
                   'opaque_records++', 'malformed_records++',
                   'unsafe payload path', 'invalid dynamic/index.tsv header'):
        assert marker in app, marker
    assert 'objectType' in app and 'dynamicObjectType' in app
    assert 'type_key_used' in app

    # 5. Registration + documentation.
    workflow = WORKFLOW.read_text()
    assert 'tools/test_client_app_skeleton_evidence.py' in workflow
    assert 'tools/gen_dynamic_object_type_table.py --check' in workflow
    doc = (ROOT / 'reconstruction/reverse-v3/CLIENT_APP_SKELETON.md').read_text()
    assert 'stub' in doc.lower() and 'b5a' in doc
    print('b5a evidence: static checks PASS')


def host_checks():
    binaries = sorted(glob.glob(str(ROOT / 'build-*/client_app_skeleton_cli')))
    if not binaries:
        print('b5a evidence: CLI not built on this host; static checks only')
        return
    binary = binaries[-1]
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / 'snapshot'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/make_client_app_fixture.py'),
                            str(snapshot)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        r = subprocess.run([binary, str(snapshot), '--json'],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        report = json.loads(r.stdout)
    assert report['blocks'] == 3, report
    assert report['dynamic_records'] == 4, report
    # 6 entries: one without a type key, one out-of-range, four constructed
    assert report['dynamic_objects'] == 4, report
    assert report['stub_objects'] == 4, report
    assert report['verified_objects'] == 0 and report['recovered_objects'] == 0
    assert report['unidentified_objects'] == 1, report
    assert report['out_of_range_objects'] == 1, report
    assert report['opaque_records'] == 2, report
    assert report['malformed_records'] == 0, report
    assert report['shared_object_type_objects'] == 1, report
    assert report['per_type'] == {'1': 1, '13': 1, '14': 1, '24': 1}, report
    assert report['type_key_used'] == {'objectType': 4, 'dynamicObjectType': 1}, report
    statuses = {obj['status'] for obj in report['objects']}
    assert statuses == {'stub'}, statuses
    print(f'b5a evidence: CLI report over the synthetic snapshot PASS '
          f'({report["dynamic_objects"]} objects, all stubs)')


def main():
    static_checks()
    host_checks()
    print('b5a evidence: PASS')


if __name__ == '__main__':
    main()
