#!/usr/bin/env python3
"""Hash-gated NPCType -> DynamicObjectType switch recovery."""
import argparse, hashlib, json
from pathlib import Path
from trace_objc_dispatch import ELFMemory

SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
FUNC=0x006495A0
EXPECTED={0:0,1:13,2:25,3:28,4:35,5:36,6:39,7:51,8:63}

def decode_movw(w):
 if (w & 0xfff0f000)!=0xe3000000: raise ValueError(f'not movw r0: {w:#x}')
 return ((w>>4)&0xf000)|(w&0xfff)

def recover(path):
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA: raise ValueError('ELF SHA mismatch')
 m=ELFMemory(path); rows=[]
 for npc_type,expected in EXPECTED.items():
  # PC at 0x6495c4 and table begins 0x6495cc.
  entry=0x006495CC+npc_type*4
  rel=m.word(entry)
  if rel is None: raise ValueError(f'missing jump entry {entry:#x}')
  target=0x006495CC+rel
  returned=decode_movw(m.word(target))
  if returned!=expected: raise ValueError(f'NPCType {npc_type}: {returned} != {expected}')
  rows.append({'npc_type':npc_type,'dynamic_object_type':returned,'jump_target':f'0x{target:08x}','return_instruction':f'0x{target:08x}'})
 return {'schema':1,'elf_sha256':SHA,'function':'_Z27dynamicObjectTypeForNPCType7NPCType','function_address':f'0x{FUNC:08x}','jump_table_address':'0x006495cc','rows':rows,'claim':'NPC shared objectType path closes the eight no-direct-override NPC classes'}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('elf',type=Path);ap.add_argument('--check',action='store_true');ap.add_argument('--output',type=Path,default=Path('reconstruction/reverse-v3/native/dynamicobject_npctype_matrix.json'));a=ap.parse_args();r=recover(a.elf);t=json.dumps(r,indent=2,sort_keys=True)+'\n'
 if a.check:
  if a.output.read_text()!=t: raise SystemExit('stale dynamicobject_npctype_matrix.json')
 else:a.output.write_text(t)
 print(f"dynamicobject-npctype-matrix: rows={len(r['rows'])} PASS")
if __name__=='__main__':main()
