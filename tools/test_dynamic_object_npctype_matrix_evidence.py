#!/usr/bin/env python3
import json
from pathlib import Path
p=Path('reconstruction/reverse-v3/native/dynamicobject_npctype_matrix.json')
d=json.loads(p.read_text())
assert d['elf_sha256']=='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
assert d['function_address']=='0x006495a0' and d['jump_table_address']=='0x006495cc'
assert len(d['rows'])==9
assert {r['npc_type']:r['dynamic_object_type'] for r in d['rows']}=={0:0,1:13,2:25,3:28,4:35,5:36,6:39,7:51,8:63}
print('dynamicobject-npctype-matrix-evidence: PASS')
