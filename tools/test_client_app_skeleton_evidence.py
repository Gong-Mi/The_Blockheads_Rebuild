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
import os
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
    for name in ('original_save_dict', 'dynamic_object_registry', 'original_client_app',
                 'original_dynamic_import'):
        assert (APP / f'{name}.h').exists(), name
        assert (APP / f'{name}.cpp').exists(), name
    host_cmake = (ROOT / 'reconstruction/recovered/CMakeLists.txt').read_text()
    android_cmake = (APP / 'CMakeLists.txt').read_text()
    for name in ('original_save_dict.cpp', 'dynamic_object_registry.cpp',
                 'original_client_app.cpp', 'original_dynamic_import.cpp'):
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
    # Newest binary wins: several build-* trees can coexist on a dev host, and
    # taking the alphabetically last one silently tested a stale CLI.
    binaries = sorted(glob.glob(str(ROOT / 'build-*/client_app_skeleton_cli')),
                      key=lambda p: os.path.getmtime(p))
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
    assert report['dynamic_records'] == 5, report
    # b5b: six objects resolve through the record key (type 1), two through the
    # per-object fallback on the type-less-key record (24, 13); one entry
    # without any type stays unidentified, one objectType 65 stays out of
    # range; opaque = the not-dynamic plist + the binary payload.
    # Re-pinned to the registered families: type 1 (tree) and 13 (npc) run
    # recovered chains, so the fixture now yields 1 stub (type 24 Blockhead,
    # out-of-domain by evidence) and 7 recovered. When a family registers,
    # this count moves with it — that drift is the point of this check.
    assert report['dynamic_objects'] == 8, report
    assert report['stub_objects'] == 1, report
    assert report['verified_objects'] == 0 and report['recovered_objects'] == 7
    # layer 3 (materialization): the dynamic domain becomes markers with the
    # decoded identity and position. Three fixture objects carry no position
    # at all and are counted, never clamped; every marker that does exist
    # lands inside an imported block (so out-of-world is 0 here).
    assert report['materialized_objects'] == 5, report
    assert report['materialized_from_float_pos'] == 1, report
    assert report['materialized_from_integer_pos'] == 4, report
    assert report['materialized_recovered'] == 4, report
    assert report['materialized_stub'] == 1, report
    assert report['materialized_without_position'] == 3, report
    assert report['materialized_out_of_world'] == 0, report
    # layer 4 (world-level state): worldv2 / dynamicWorldv2 / blockheads are
    # decoded by name. randomSeed has NO consumer in the replacement
    # generator today, and that is reported rather than papered over; the
    # save carries no player records, which is a fact about this save.
    ws = report['world_state']
    assert ws['worldv2_present'] and ws['dynamic_worldv2_present'], ws
    assert ws['blockheads_present'], ws
    assert ws['random_seed'] == 1788626619, ws
    assert ws['seed_has_consumer'] is False, ws
    assert ws['portal_level'] == 0 and ws['expert_mode'] is False, ws
    assert ws['max_players'] == '1' and ws['host_port'] == '15159', ws
    assert ws['remote_game'] is False and ws['run_at_launch'] is True, ws
    assert ws['no_rain_timer'] == 0.0 and ws['migration_complete'] is True, ws
    assert ws['active_blockhead_index'] == 0, ws
    assert ws['dynamic_object_id_count'] == 155, ws
    assert ws['save_version'] == 8, ws
    assert ws['workbench_has_been_crafted'] is False, ws
    assert ws['player_records'] == 0, ws
    assert ws['opaque_data_blobs'] == 4, ws
    assert ws['unread_keys'] == {'fixtureUnknownKey': 1}, ws
    # every recovered object must OWN its decoded state with the exact family
    # of the module that produced it; stubs own none
    for obj in report['objects']:
        family = obj.get('state_family')
        if obj['status'] == 'stub':
            assert family is None, obj
            continue
        assert family in {'TreeFullState', 'NpcFullState'}, obj
        if obj['type_id'] == 1:
            assert family == 'TreeFullState', obj
        if obj['type_id'] == 13:
            assert family == 'NpcFullState', obj
    assert report['unidentified_objects'] == 1, report
    assert report['out_of_range_objects'] == 1, report
    assert report['opaque_records'] == 2, report
    assert report['malformed_records'] == 0, report
    assert report['shared_object_type_objects'] == 1, report
    assert report['per_type'] == {'1': 6, '13': 1, '24': 1}, report
    # record keys carry 6 typed rows (4 per-object metadata values disagree
    # with their record key and LOSE, per the strict rule); the one
    # metadata-only record resolves 2 objects through the fallback keys and
    # leaves one unidentified (an out-of-range objectType never counts).
    assert report['type_key_used'] == {'record_key': 6, 'type_disagreement': 4,
                                       'objectType': 1,
                                       'dynamicObjectType': 1}, report
    by_id = {obj['unique_id']: obj for obj in report['objects']}
    assert set(by_id) == {42, 77, 78, 5, 6, 7, 10, 11}, sorted(by_id)
    assert all(by_id[uid]['type_id'] == 1 for uid in (42, 77, 78, 5, 6, 7))
    assert by_id[10]['type_id'] == 24 and by_id[11]['type_id'] == 13
    statuses = {obj['status'] for obj in report['objects']}
    assert statuses == {'stub', 'recovered'}, statuses
    print(f'b5a evidence: CLI report over the synthetic snapshot PASS '
          f'({report["dynamic_objects"]} objects, '
          f'{report["recovered_objects"]} stateful recovered)')


def main():
    static_checks()
    host_checks()
    print('b5a evidence: PASS')


if __name__ == '__main__':
    main()
