#!/usr/bin/env python3
"""Static contract for the bounded DynamicObject getSaveDict body."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'

def main():
    report=json.loads((NATIVE/'dynamicobject_getsavedict.json').read_text())
    assert report['method']=='DynamicObject -[getSaveDict]'
    assert report['imp']=='0x0083a7ac'
    assert report['boundary_end']=='0x0083aabc'
    assert report['code_end']=='0x0083aa70'
    assert report['code_words']==177
    assert report['coverage_words']==196
    assert report['body_sha256']=='817bee107a168228c4099457cb74d3df98e1d98296cddeb700d0e9418f0eb483'
    assert report['pic_base']=='0x0105faf4'
    assert len(report['objc_msgsend_sites'])==7
    assert report['objc_msgsend_sites_unresolved_count']==3
    assert report['indirect_blx_sites']==["0x0083aa3c","0x0083aa60"]
    assert report['known_selectors']=={
        'dictionary':'0x0083aa88',
        'numberWithFloat:':'0x0083aa98',
        'arrayWithObjects:':'0x0083aa9c',
        'setObject:forKey:':'0x0083aa78',
        'numberWithUnsignedLong:':'0x0083aa7c',
        'numberWithInt:':'0x0083aaa8',
    }
    assert report['known_ivars']=={
        'OBJC_IVAR_$_DynamicObject.floatPos':24,
        'OBJC_IVAR_$_DynamicObject.pos':16,
        'OBJC_IVAR_$_DynamicObject.uniqueID':40,
    }
    print('dynamicobject-getsavedict-evidence: PASS')

if __name__=='__main__':main()
