#!/usr/bin/env python3
"""Hash-gated reconciliation of type-matrix classes and objectType IMPs."""
import argparse, hashlib, json, struct
from pathlib import Path
from trace_objc_dispatch import ELFMemory

SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'

def decode_mov_imm(word):
 if (word & 0xfff0f000) == 0xe3002000:
  return ((word >> 4) & 0xf000) | (word & 0xfff)
 if (word & 0xfffff000) == 0xe3a02000:
  return word & 0xff
 return None

def recover(elf_path, native):
 raw=elf_path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA: raise ValueError('ELF SHA mismatch')
 mem=ELFMemory(elf_path)
 methods={}
 for line in (native/'libApplication_objc_methods.tsv').read_text().splitlines()[1:]:
  p=line.split('\t')
  if len(p)==5: methods.setdefault(p[1],{})[p[3]]=p[0]
 matrix=json.loads((native/'dynamicobject_type_matrix.json').read_text())['types']
 rows=[]
 for item in matrix:
  cls=item['class_name']; expected=item['type_id']; imp=methods.get(cls,{}).get('objectType')
  if imp is None:
   rows.append({'type_id':expected,'class_name':cls,'status':'no_direct_override','reason':'shared/inherited objectType path pending'})
   continue
  addr=int(imp,16); first=mem.word(addr); second=mem.word(addr+4); ret=decode_mov_imm(second)
  if ret!=expected: raise ValueError(f'{cls}: objectType {ret} != {expected}')
  rows.append({'type_id':expected,'class_name':cls,'status':'direct_override','imp':imp,'returned_constant':ret,'instruction_words':[f'0x{first:08x}',f'0x{second:08x}']})
 return {'schema':1,'elf_sha256':SHA,'matrix_source':'reconstruction/reverse-v3/native/dynamicobject_type_matrix.json','direct_override_count':sum(r['status']=='direct_override' for r in rows),'no_direct_override_count':sum(r['status']=='no_direct_override' for r in rows),'rows':rows,'claim':'56 class-level objectType constants match the 1..64 native class matrix; 8 NPC classes have no direct override and remain on shared/inherited path'}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('elf',type=Path);ap.add_argument('--check',action='store_true');ap.add_argument('--output',type=Path,default=Path('reconstruction/reverse-v3/native/dynamicobject_type_objecttype_matrix.json'));a=ap.parse_args();r=recover(a.elf,a.output.parent);t=json.dumps(r,indent=2,sort_keys=True)+'\n'
 if a.check:
  if a.output.read_text()!=t:raise SystemExit('stale dynamicobject_type_objecttype_matrix.json')
 else:a.output.write_text(t)
 print(f"dynamicobject-type-objecttype-matrix: direct={r['direct_override_count']} no_direct={r['no_direct_override_count']} PASS")
if __name__=='__main__':main()
