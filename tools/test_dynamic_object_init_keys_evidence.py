#!/usr/bin/env python3
import json
from pathlib import Path
p=Path('reconstruction/reverse-v3/native/dynamicobject_init_keys.json')
d=json.loads(p.read_text())
assert d['elf_sha256']=='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
assert d['imp']=='0x00839f7c' and d['code_end']=='0x0083a368' and d['bounded_end']=='0x0083a3c0'
assert len(d['keys'])==4
expected={
 'uniqueID':(40,'uint64','unsignedLongValue'),
 'pos_x':(16,'int','intValue'),
 'pos_y':(20,'int','intValue'),
 'floatPos':(24,'Vector2','floatValue'),
}
for row in d['keys']:
    key=row['key']; assert key in expected
    assert (row['ivar_offset'],row['value_type'],row['conversion'])==expected[key]
    assert row['cstring'] in {'0x00f50df3','0x00f571a3','0x00f571a9','0x00f571af'}
    assert row['key_call'].startswith('0x0083a')
    assert row['write_sites']
assert d['keys'][-1]['array_indices']==[0,1]
print('dynamicobject-init-keys-evidence: PASS')
