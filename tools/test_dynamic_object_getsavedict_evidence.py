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
    assert len(report['objc_msgsend_sites'])==9
    assert report['objc_msgsend_sites_unresolved_count']==0
    assert report['indirect_blx_sites']==["0x0083aa3c","0x0083aa60"]
    assert report['known_selectors']=={
        'dictionary':'0x0083aa88',
        'numberWithFloat:':'0x0083aa98',
        'arrayWithObjects:':'0x0083aa9c',
        'setObject:forKey:':'0x0083aa78',
        'numberWithUnsignedLong:':'0x0083aa7c',
        'numberWithInt:':'0x0083aaa8',
    }
    assert report['objc_msgsend_sites_known']=={
        '0x0083a820':'dictionary',
        '0x0083a888':'numberWithFloat:',
        '0x0083a8cc':'numberWithFloat:',
        '0x0083a8fc':'arrayWithObjects:',
        '0x0083a930':'setObject:forKey:',
        '0x0083a974':'numberWithInt:',
        '0x0083a99c':'setObject:forKey:',
        '0x0083a9d8':'numberWithInt:',
        '0x0083aa00':'setObject:forKey:',
    }
    assert report['indirect_blx_sites_known']=={
        '0x0083aa3c':'objc_msgSend',
        '0x0083aa60':'objc_msgSend',
    }
    assert report['indirect_call_contracts']=={
        '0x0083aa3c':{
            'dispatch':'objc_msgSend',
            'selector':'numberWithUnsignedLong:',
            'value_source':'DynamicObject.uniqueID (self + 40)',
        },
        '0x0083aa60':{
            'dispatch':'objc_msgSend',
            'selector':'setObject:forKey:',
            'value_source':'boxed uniqueID result from 0x0083aa3c',
            'key':'uniqueID',
        },
    }
    assert report['indirect_blx_sites_unresolved_count']==0
    assert report['save_dict_key_pairings']==[
        {'constant_string_object':'0x00f92108','cstring':'0x00f571af','ivar':'OBJC_IVAR_$_DynamicObject.floatPos','ivar_offset':24,'key':'floatPos','literal_cell':'0x0083aaa0','set_object_site':'0x0083a930'},
        {'constant_string_object':'0x00f920e8','cstring':'0x00f571a3','ivar':'OBJC_IVAR_$_DynamicObject.pos','ivar_offset':16,'key':'pos_x','literal_cell':'0x0083aaac','set_object_site':'0x0083a99c'},
        {'constant_string_object':'0x00f920f8','cstring':'0x00f571a9','ivar':'OBJC_IVAR_$_DynamicObject.pos','ivar_offset':20,'key':'pos_y','literal_cell':'0x0083aab0','set_object_site':'0x0083aa00'},
        {'constant_string_object':'0x00f920d8','cstring':'0x00f50df3','ivar':'OBJC_IVAR_$_DynamicObject.uniqueID','ivar_offset':40,'key':'uniqueID','literal_cell':'0x0083aa70','set_object_site':'0x0083aa60'},
    ]
    assert report['known_ivars']=={
        'OBJC_IVAR_$_DynamicObject.floatPos':24,
        'OBJC_IVAR_$_DynamicObject.pos':16,
        'OBJC_IVAR_$_DynamicObject.uniqueID':40,
    }
    print('dynamicobject-getsavedict-evidence: PASS')

if __name__=='__main__':main()
