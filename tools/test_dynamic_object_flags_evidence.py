#!/usr/bin/env python3
import json
from pathlib import Path
p=Path('reconstruction/reverse-v3/native/dynamicobject_flags.json')
d=json.loads(p.read_text())
assert d['elf_sha256']=='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
assert d['range_start']=='0x0083d0f0' and d['range_end']=='0x0083d370'
assert len(d['methods'])==10
expected={
 'needsRemoved':('bool',0x30),'updateNeedsToBeSent':('bool',0x31),
 'creationDataNeedsToBeSent':('bool',0x32),'unreliableUpdateNeedsToBeSent':('bool',0x33),
 'isNet':('bool',0x34),'macroTileOwner':('pointer',0x0c)}
for r in d['methods']:
    if r['kind']=='setter': assert r['parameter_type']=='bool'
    else:
        assert r['return_type']==expected[r['selector']][0]
        assert r['ivar_offset']==expected[r['selector']][1]
    assert r['code_words'] in (13,15)
print('dynamicobject-flags-evidence: PASS')
