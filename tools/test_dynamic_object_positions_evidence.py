#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    report=json.loads((NATIVE/'dynamicobject_positions.json').read_text())
    assert report['method_group']=='DynamicObject position getters'
    methods={m['name']:m for m in report['methods']}
    assert methods['pos']['imp']=='0x0083cfcc'
    assert methods['pos']['boundary_end']=='0x0083d02c'
    assert methods['pos']['verified_words']==22
    assert methods['pos']['ivar_symbol']=='OBJC_IVAR_$_DynamicObject.pos'
    assert methods['pos']['ivar_offset']==16
    assert methods['pos']['return_type']=='{?=ii}'
    assert methods['pos']['body_sha256']=='b9d8450a69c011366e6ab66a94e44506e79acbac199997b0e03d2f117a50bc31'
    assert methods['floatPos']['imp']=='0x0083d02c'
    assert methods['floatPos']['boundary_end']=='0x0083d08c'
    assert methods['floatPos']['ivar_symbol']=='OBJC_IVAR_$_DynamicObject.floatPos'
    assert methods['floatPos']['ivar_offset']==24
    assert methods['floatPos']['return_type']=='{Vector2=[2f]}'
    assert methods['floatPos']['body_sha256']=='9274f2322e4187ac871476f40f84d75fc85db64f00a6faf5ef2f3c8c50117266'
    print('dynamicobject-positions-evidence: PASS')

if __name__=='__main__':main()
