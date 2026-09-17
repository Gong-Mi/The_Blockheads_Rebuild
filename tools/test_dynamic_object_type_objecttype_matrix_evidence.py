#!/usr/bin/env python3
import json
from pathlib import Path
p=Path('reconstruction/reverse-v3/native/dynamicobject_type_objecttype_matrix.json')
d=json.loads(p.read_text())
assert d['elf_sha256']=='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
assert d['direct_override_count']==56 and d['no_direct_override_count']==8
assert len(d['rows'])==64
expected_missing={13:'Dodo',25:'DropBear',28:'Donkey',35:'ClownFish',36:'Shark',39:'CaveTroll',51:'Scorpion',63:'Yak'}
missing={r['type_id']:r['class_name'] for r in d['rows'] if r['status']=='no_direct_override'}
assert missing==expected_missing
for r in d['rows']:
    if r['status']=='direct_override': assert r['returned_constant']==r['type_id']
print('dynamicobject-type-objecttype-matrix-evidence: PASS')
