#!/usr/bin/env python3
"""Hash-gated bounded evidence for DynamicObject saveDict initialization."""
import argparse, hashlib, io, json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly
ROOT=Path(__file__).resolve().parents[1];NATIVE=ROOT/'reconstruction/reverse-v3/native'
SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START=0x839f7c;CODE_END=0x83a368;END=0x83a3c0;BASE_ADD=0x839f8c;BASE_LITERAL=0x83a3bc
SELECTORS={0x83a36c:'init',0x83a378:'initDerivedStuff:loadPhysicalBlockIfNeeded:',0x83a37c:'floatValue',0x83a380:'objectAtIndex:',0x83a388:'objectForKey:',0x83a394:'intValue',0x83a3b4:'unsignedLongValue'}

def s(v):return v-(1<<32) if v&0x80000000 else v
def word(m,a):
 v=m.word(a)
 if v is None:raise ValueError(f'missing word {a:#x}')
 return int(v)
def recover(path):
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('ELF SHA mismatch')
 m=ELFMemory(path);text=(NATIVE/'disasm_dynamicobject_init_savedict.txt').read_text()
 coverage=verify_disassembly(m,text,START,END)
 base=(BASE_ADD+8+s(word(m,BASE_LITERAL)))&0xffffffff
 if base!=0x105faf4:raise ValueError('PIC base drift')
 selectors={}
 for cell,name in SELECTORS.items():
  slot=(base+s(word(m,cell)))&0xffffffff; value=word(m,slot)
  if m.selectors.get(value)!=name:raise ValueError(f'selector drift {name}')
  selectors[name]=f'0x{cell:08x}'
 imports=[]
 for cell in [0x83a368,0x83a374]:
  slot=(base+s(word(m,cell)))&0xffffffff;imports.append(m.imports.get(slot))
 if imports!=['objc_msgSendSuper2','objc_msgSend']:raise ValueError('dispatch imports drift')
 elf=ELFFile(io.BytesIO(raw));dynsym=elf.get_section_by_name('.dynsym')
 bodyoff=m.offset(START,CODE_END-START)
 if bodyoff is None:raise ValueError('missing body')
 bodyoff=int(bodyoff)
 return {'schema':1,'method':'DynamicObject -[initWithWorld:dynamicWorld:saveDict:cache:]','types':'@24@0:4@8@12@16@20','elf_sha256':hashlib.sha256(raw).hexdigest(),'imp':f'0x{START:08x}','code_end':f'0x{CODE_END:08x}','boundary_end':f'0x{END:08x}','code_words':(CODE_END-START)//4,'coverage_words':coverage,'body_sha256':hashlib.sha256(m.data[bodyoff:bodyoff+CODE_END-START]).hexdigest(),'pic_base':f'0x{base:08x}','dispatch_imports':imports,'known_selectors':selectors,'arguments':{'saveDict':'[fp+8] stored at [fp-0x30]','cache':'[fp+12] stored at [fp-0x34]'},'save_dict_access':['objectForKey:','floatValue','intValue','unsignedLongValue','objectAtIndex:'],'null_save_dict_gate':'[fp-0x20] == nil returns before field initialization','claim':'bounded static init evidence; key names, full field mapping, dynamic entity construction and runtime claim remain unresolved'}
def main():
 p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('--check',action='store_true');p.add_argument('--output',type=Path,default=NATIVE/'dynamicobject_init_savedict.json');a=p.parse_args();r=recover(a.elf);t=json.dumps(r,indent=2,sort_keys=True)+'\n'
 if a.check:
  if a.output.read_text()!=t:raise SystemExit('stale dynamicobject_init_savedict.json')
 else:a.output.write_text(t)
 print('init_savedict code_words=%d coverage=%d selectors=%d'%(r['code_words'],r['coverage_words'],len(r['known_selectors'])))
if __name__=='__main__':main()
