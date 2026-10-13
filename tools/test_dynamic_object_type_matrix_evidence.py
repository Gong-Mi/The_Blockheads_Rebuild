#!/usr/bin/env python3
import json
from pathlib import Path
p=Path('reconstruction/reverse-v3/native/dynamicobject_type_matrix.json')
d=json.loads(p.read_text())
assert d['elf_sha256']=='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
assert d['function']=='_Z25classForDynamicObjectTypei'
assert d['function_address']=='0x00b597bc'
assert d['jump_table_address']=='0x00b597fc'
assert d['total_types']==64
assert len(d['types'])==64
expected={
 1:'AppleTree',13:'Dodo',14:'FreeBlock',16:'FireObject',20:'Door',
 22:'SurfaceBlock',23:'Bed',24:'Blockhead',25:'DropBear',28:'Donkey',
 29:'SnowSurfaceBlock',30:'Egg',35:'ClownFish',36:'Shark',39:'CaveTroll',
 42:'SteamTrain',45:'Workbench',46:'Chest',50:'TradePortal',51:'Scorpion',
 63:'Yak',64:'Mirror'}
by_id={t['type_id']:t['class_name'] for t in d['types']}
assert sorted(by_id)==list(range(1,65))
for tid,name in expected.items():
    assert by_id[tid]==name, f'type {tid}: expected {name}, got {by_id[tid]}'
print('dynamicobject-type-matrix-evidence: PASS')
