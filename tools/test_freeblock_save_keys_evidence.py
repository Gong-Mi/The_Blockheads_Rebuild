#!/usr/bin/env python3
"""Regression contract for FreeBlock getSaveDict key/value-source pairings."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'


def main():
    report = json.loads((NATIVE / 'freeblock_save_keys.json').read_text())
    assert report['method'] == 'FreeBlock -[getSaveDict]'
    assert report['imp'] == '0x00629804'
    assert report['code_end'] == '0x0062a410'
    assert report['bounded_end'] == '0x0062a4bc'
    assert report['pic_base'] == '0x0105faf4'
    assert report['super_route']['selector'] == 'getSaveDict'
    assert report['super_route']['dispatch'] == 'objc_msgSendSuper2'
    assert report['super_route']['site'] == '0x00629858'
    assert report['uniqueid_send']['selector'] == 'uniqueID'
    rows = report['pairings']
    assert len(rows) == 12
    by_key = {r['key']: r for r in rows}
    assert set(by_key) == {
        'bounceTimer', 'fallSpeed', 'floatPos[VX]', 'floatPos[VY]',
        'itemType', 'dataA', 'dataB', 'creationTime', 'hovers',
        'subItems', 'dynamicObjectSaveDict', 'priorityBlockheadUinqueID',
    }
    # scalar conversions must be fully bounded
    scalar = {
        'bounceTimer': ('numberWithFloat:', 'OBJC_IVAR_$_FreeBlock.bounceTimer', 68),
        'fallSpeed': ('numberWithFloat:', 'OBJC_IVAR_$_FreeBlock.fallSpeed', 72),
        'itemType': ('numberWithInt:', 'OBJC_IVAR_$_FreeBlock.itemType', 56),
        'dataA': ('numberWithInt:', 'OBJC_IVAR_$_FreeBlock.dataA', 60),
        'dataB': ('numberWithInt:', 'OBJC_IVAR_$_FreeBlock.dataB', 62),
        'creationTime': ('numberWithDouble:', 'OBJC_IVAR_$_FreeBlock.creationTime', 80),
        'hovers': ('numberWithBool:', 'OBJC_IVAR_$_FreeBlock.hovers', 64),
    }
    for key, (conv, ivar, offset) in scalar.items():
        row = by_key[key]
        assert row['conversion_selector'] == conv, key
        assert row['value_source']['ivar'] == ivar, key
        assert row['value_source']['ivar_offset'] == offset, key
        assert row['boxed_value_spill'] and row['boxed_value_reload'], key
    for key in ('floatPos[VX]', 'floatPos[VY]'):
        row = by_key[key]
        assert row['conversion_selector'] == 'numberWithFloat:'
        assert row['value_source']['ivar'] == 'OBJC_IVAR_$_DynamicObject.floatPos'
        assert row['value_source']['ivar_offset'] == 24
    assert by_key['floatPos[VX]']['component_byte'] == 0
    assert by_key['floatPos[VY]']['component_byte'] == 4
    assert by_key['subItems']['pairing_kind'] == 'serialized_array'
    assert 'itemType and saveData' in by_key['subItems']['value_path']
    assert by_key['dynamicObjectSaveDict']['pairing_kind'] == 'passthrough_dict'
    assert by_key['priorityBlockheadUinqueID']['value_source']['ivar'] == 'OBJC_IVAR_$_FreeBlock.priorityBlockhead'
    print('freeblock-save-keys-evidence: PASS')


if __name__ == '__main__':
    main()
