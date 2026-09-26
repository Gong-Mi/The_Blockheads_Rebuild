#!/usr/bin/env python3
"""CI-safe evidence guard for the Workbench loader ARM differential (b4q).

Host (pinned ELF + Unicorn present): runs the differential and asserts every
case matches bit-exactly against -O0 and -O2.
CI: asserts the recovered contract, CTest/CMake/workflow registrations, the
trace-code single source of truth and the frozen executed facts.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
IMP = '0x00ae4ed8'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'workbench_init.h').read_text()
    source = (RECOVERED / 'workbench_init.cpp').read_text()
    contract = (ROOT / 'tools/test_workbench_init.cpp').read_text()
    harness = (ROOT / 'tools/test_workbench_init_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    workflow_android = (ROOT / '.github/workflows/android.yml').read_text()
    listing = (NATIVE / 'disasm_workbench_big_initwithworld.txt').read_text()
    doc = (NATIVE / 'WORKBENCH_INIT_ARM.md').read_text()

    assert IMP in header.lower() and 'b4q' in header
    assert 'initWithWorld:dynamicWorld:saveDict:cache:' in header
    assert 'kWorkbenchImageSize = 324' in header
    # executed facts
    assert 'kWorkbenchCraftableBlobSize = 124' in header
    assert 'kWorkbenchStretSlotCountOffset = 0x48' in header
    assert 'kWorkbenchSkippedSlotType = 11' in header
    assert 'objectForKey TWICE' in header
    assert 'unsignedIntValue' in doc or 'UNSIGNEDINTVALUE' in doc
    assert 'gated by isInUse ALONE' in doc

    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('WorkbenchInitCall', 'MsgSendSuper',
                    'ObjectForKeyWorkbenchType', 'IntValueWorkbenchType',
                    'ObjectForKeyHurrying', 'ObjectForKeyHasFuel',
                    'ObjectForKeyAvailableElectricity',
                    'ObjectForKeyBlockheadIndexFuel',
                    'ObjectForKeyCraftingItemDatav2',
                    'ObjectForKeyCraftingItemData',
                    'CraftableAlloc', 'CraftableInitWithSaveDict',
                    'CraftableInitWithCraftableItem', 'BytesCopy',
                    'CraftableItemStret', 'ReleaseSlot',
                    'StringWithFormatSourceItems',
                    'CountByEnumeratingSource', 'InventoryAlloc',
                    'InventoryInitWithSaveData', 'SlotAddObject',
                    'SetInteractionWorkbenchCraft',
                    'SetInteractionWorkbenchFuel',
                    'ObjectForKeyLightDict', 'ArtificialLightAlloc',
                    'LightInitWithWorld', 'MacroTiles',
                    'InitSubDerivedItems'):
        assert snippet in generated, snippet
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'WORKBENCH_INIT_CODES' in harness

    for marker in ('super_nil', 'plain_keys', 'index_fuel_reread',
                   'v2_type1', 'v2_type2', 'v2_type_other', 'v1_migration',
                   'in_use_no_data', 'source_items_walk',
                   'fuel_blockhead_wire', 'light_dict_restore'):
        assert marker in harness, marker
    assert 'super2 own class' in harness
    assert 'msgSend_stret' in harness or 'GOT_STRET' in harness
    assert '0x105FB6C' in harness          # objc_msgSend_stret GOT
    assert '0x105FB40' in harness          # memcpy GOT
    assert 'recovered_workbench_init' in cmake
    assert 'test_workbench_init_arm_evidence.py' in workflow
    assert 'implemented | 54' in workflow_android
    assert 'semantics | 54' in workflow_android
    assert 'boundary: 0x00ae6490' in listing
    for anchor in (IMP, '0x00e8be80', '0x00ae5b7c'):
        assert anchor in listing, anchor

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/workbench-arm-differential'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/test_workbench_init_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('Workbench ARM differential failed')
        report = json.loads((out / 'workbench_init_arm_result.json').read_text())
        assert report['match'] is True
        assert report['cases'] >= 11
        walk = next(r for r in report['rows']
                    if r['case'] == 'source_items_walk')
        assert walk['trace_len'] >= 70, walk
        print(f"b4q ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4q evidence: static contract only (no pinned ELF or no Unicorn)')

    print('b4q evidence: PASS')


if __name__ == '__main__':
    main()
