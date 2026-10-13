#!/usr/bin/env python3
"""CI-safe evidence guard for the Chest loader ARM differential (batch b4m).

Host, when both the pinned ELF and Unicorn are present: runs the differential
and asserts every case matches bit-exactly against -O0 and -O2.
Without them (CI): asserts the recovered C++ contract, the CTest registration,
the CMake/workflow registrations, the trace-code single source of truth, the
frozen b3m-2 static decode and the instance-size cross-check.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
IMP = '0x00cb627c'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'chest_init_with_world.h').read_text()
    source = (RECOVERED / 'chest_init_with_world.cpp').read_text()
    contract = (ROOT / 'tools/test_chest_init_with_world.cpp').read_text()
    harness = (ROOT / 'tools/test_chest_init_with_world_arm.py').read_text()
    bridge = (ROOT / 'tools/chest_init_with_world_arm_bridge.cpp').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    listing = (NATIVE / 'disasm_chest_big_initwithworld.txt').read_text()
    b3m2 = json.loads((NATIVE / 'chest_big_initwithworld.json').read_text())

    # Contract header documents IMP, batch and the decoded shape.
    assert IMP in header.lower() and 'b4m' in header
    assert 'initWithWorld:dynamicWorld:saveDict:cache:' in header
    assert 'generated/trace_codes.h' in header
    assert '0x00CB623C' in header

    # Trace codes single source of truth.
    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('ChestInitCall', 'MsgSendSuper', 'CustomRulesStret',
                    'CustomRulesMemset', 'ObjectForKeySaveItemSlots',
                    'InitWithCapacity', 'ObjectAtIndex',
                    'StateMemset', 'FastEnumeration', 'EnumerationMutation',
                    'AllocInventoryItem', 'InitWithSaveData', 'ItemType',
                    'AddObjectItem', 'StringWithFormatShelfRenderItems',
                    'ObjectForKeyShelfItemDataBs', 'InitSubDerivedItems'):
        assert snippet in generated, snippet
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'CHEST_INIT_CODES' in harness
    assert 'trace_codes_gen' in harness

    # Contract semantics: the capacity rule, the RE-READ after the rules gate,
    # the per-slot offsets and the 16-bit shelf truncation.
    assert 'return (chest_type == 2 || chest_type == 5) ? 4 : 16;' in source
    assert 'chestType is RE-READ here' in source
    assert 'load_word(result.image, kChestOffsetChestType)' in source
    assert 'kChestOffsetShelfRenderItems + 4 * m' in source
    assert 'kChestOffsetShelfItemDataBs + 2 * m' in source
    assert 'static_cast<std::uint16_t>(data_value)' in source
    assert 'e.item_type != 11' in source
    assert 'kChestImageSize = 140' in header
    assert 'kChestOffsetShelfItemDataBs = 132' in header
    assert 'store_half' in source

    # The bridge keeps the fixed-size fixture tables honest.
    assert 'kMaxSlots = 64' in bridge and 'kMaxItems = 512' in bridge
    assert '0xFFFFFFFFu' in bridge

    # Hand-written contract test asserts both directions of the gate and the
    # pad path (independent of the ARM pair).
    for marker in ('saw_capacity_16', 'pad path', '0x2345u',
                   'ChestInitCall::CustomRulesMemset',
                   'EnumerationMutation'):
        assert marker in contract, marker
    assert 'recovered_chest_init_with_world' in cmake
    assert 'test_chest_init_with_world_arm_evidence.py' in workflow
    assert 'tools/gen_trace_codes.py --check' in workflow

    # Harness cases and stub assertions.
    for case_name in ('super_nil', 'chest_type_2_full', 'chest_type_0_sixteen',
                      'count_less_than_capacity', 'slots_key_missing',
                      'chest_type_4_rules_zero', 'chest_type_4_rules_gate',
                      'chest_type_4_world_nil', 'owner_id_present',
                      'mixed_item_types', 'chest_type_key_missing',
                      'chunked_slot_items', 'mutation_during_enumeration'):
        assert case_name in harness, case_name
    assert 'super2 class word (own class)' in harness
    assert 'customRules receiver (self->world ivar)' in harness
    assert 'dynamicWorld ivar identity' in harness
    assert 'capacity helper drift' in harness
    assert '__stack_chk_guard' in harness and 'GUARD_ADDR' in harness
    assert 'VENEER_MSGSEND_SLOT' in harness
    assert 'objc_enumerationMutation' in harness
    assert 'objc_msgSend_stret' in harness

    # The frozen b3m-2 static decode must still match.
    entry = next((c for c in b3m2['classes'] if c['class'] == 'Chest'), None)
    assert entry is not None, 'Chest missing from chest_big_initwithworld.json'
    assert entry['imp'] == IMP
    assert entry['code_words'] == 760
    assert entry['runtime_superclass'] == 'InteractionObject'
    assert entry['capacity_helper']['rule'] == (
        'numberOfSlots = (chestType == 2 || chestType == 5) ? 4 : 16')
    assert entry['capacity_helper']['imp'] == '0x00cb623c'
    assert sorted(entry['own_keys']) == ['chestType', 'safeClientID',
                                         'saveItemSlots', 'shelfItemDataBs_%d',
                                         'shelfRenderItems_%d']
    assert entry['literal_cells']['stack_chk_guard_got'] == '0x0105b7e0'
    assert entry['literal_cells']['superref_slot'] == '0x00e8bef0'

    # Listing anchors: prologue, the canary GOT load, the capacity helper call,
    # the rules stret and the epilogue.
    for anchor in (IMP, '0xcb623c', '0x1c2918', '0x0105b7e0', '0x00cb6e5c',
                   "shelfItemDataBs_%d", "shelfRenderItems_%d"):
        assert anchor in listing, anchor

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/chest-init-arm-differential'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/test_chest_init_with_world_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('Chest ARM differential failed')
        report = json.loads((out / 'chest_init_with_world_arm_result.json').read_text())
        assert report['match'] is True
        assert report['cases'] >= 13
        print(f"b4m ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4m evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4m evidence: PASS')


if __name__ == '__main__':
    main()
