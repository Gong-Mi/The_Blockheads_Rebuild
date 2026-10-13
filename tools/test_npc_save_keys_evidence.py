#!/usr/bin/env python3
"""Regression contract for NPC getSaveDict key/value-source pairings."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'


def main():
    report = json.loads((NATIVE / 'npc_save_keys.json').read_text())
    assert report['method'] == 'NPC -[getSaveDict]'
    assert report['imp'] == '0x00645aac'
    assert report['code_end'] == '0x0064667c'
    assert report['bounded_end'] == '0x00646738'
    assert report['pic_base'] == '0x0105faf4'
    assert report['super_route']['selector'] == 'getSaveDict'
    assert report['super_route']['dispatch'] == 'objc_msgSendSuper2'
    assert report['super_route']['site'] == '0x00645b00'
    rows = report['pairings']
    assert len(rows) == 16
    by_key = {r['key']: r for r in rows}
    scalar = {
        'damage': ('numberWithInt:', 'OBJC_IVAR_$_NPC.damage', 54),
        'breed': ('numberWithInt:', 'OBJC_IVAR_$_NPC.breed', 96),
        'fullness': ('numberWithFloat:', 'OBJC_IVAR_$_NPC.fullness', 68),
        'layTimer': ('numberWithFloat:', 'OBJC_IVAR_$_NPC.layTimer', 80),
        'mateBreed': ('numberWithInt:', 'OBJC_IVAR_$_NPC.mateBreed', 98),
        'tameCooldownTimer': ('numberWithFloat:', 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72),
        'layCooldownTimer': ('numberWithFloat:', 'OBJC_IVAR_$_NPC.layCooldownTimer', 84),
        'mateCooldownTimer': ('numberWithFloat:', 'OBJC_IVAR_$_NPC.mateCooldownTimer', 76),
        'age': ('numberWithFloat:', 'OBJC_IVAR_$_NPC.age', 88),
        'hasBred': ('numberWithBool:', 'OBJC_IVAR_$_NPC.hasBred', 100),
        'hasBeenFedByBlockheadOrChest': ('numberWithBool:', 'OBJC_IVAR_$_NPC.hasBeenFedByBlockheadOrChest', 101),
        'currentBlockheadIndex': ('numberWithInt:', 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
    }
    for key, (conv, ivar, offset) in scalar.items():
        row = by_key[key]
        assert row['conversion_selector'] == conv, key
        assert row['value_source']['ivar'] == ivar, key
        assert row['value_source']['ivar_offset'] == offset, key
        assert row['boxed_value_spill'] and row['boxed_value_reload'], key
    for key in ('name', 'tameCountsByClientID', 'tamedClientID'):
        assert by_key[key]['pairing_kind'] == 'direct_object', key
    assert by_key['saveTime']['pairing_kind'] == 'world_time'
    assert by_key['saveTime']['value_source']['ivar'] == 'OBJC_IVAR_$_DynamicObject.world'
    assert by_key['currentBlockheadIndex']['pairing_kind'] == 'rider_index_loop'
    assert 'needsRemoved' in by_key['currentBlockheadIndex']['value_path']
    # every key must carry its own constant-string object identity
    objs = {row['constant_string_object'] for row in rows}
    assert len(objs) == 16
    print('npc-save-keys-evidence: PASS')


if __name__ == '__main__':
    main()
