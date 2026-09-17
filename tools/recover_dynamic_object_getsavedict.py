#!/usr/bin/env python3
"""Hash-gated bounded selector/ivar inventory for DynamicObject getSaveDict."""
import argparse
import hashlib
import io
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'reconstruction/reverse-v3/native'
SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START=0x0083A7AC; CODE_END=0x0083AA70; END=0x0083AABC
BASE_ADD=0x0083A7BC; BASE_LITERAL=0x0083AAB8
SELECTOR_CELLS={
    0x0083AA88:'dictionary',
    0x0083AA98:'numberWithFloat:',
    0x0083AA9C:'arrayWithObjects:',
    0x0083AA78:'setObject:forKey:',
    0x0083AA7C:'numberWithUnsignedLong:',
    0x0083AAA8:'numberWithInt:',
}
IVAR_CELLS={
    0x0083AA94:('OBJC_IVAR_$_DynamicObject.floatPos',24),
    0x0083AAA4:('OBJC_IVAR_$_DynamicObject.pos',16),
    0x0083AAB4:('OBJC_IVAR_$_DynamicObject.uniqueID',40),
}
OBJC_MSGSEND_SITES=(0x0083A820,0x0083A888,0x0083A8CC,0x0083A8FC,0x0083A930,0x0083A974,0x0083A99C,0x0083A9D8,0x0083AA00)
BLX_SITES=(0x0083AA3C,0x0083AA60)
KEY_PAIRINGS=(
 ('floatPos',0x0083AAA0,0x00F571AF,0x0083A930,'OBJC_IVAR_$_DynamicObject.floatPos',24),
 ('pos_x',0x0083AAAC,0x00F571A3,0x0083A99C,'OBJC_IVAR_$_DynamicObject.pos',16),
 ('pos_y',0x0083AAB0,0x00F571A9,0x0083AA00,'OBJC_IVAR_$_DynamicObject.pos',20),
 ('uniqueID',0x0083AA70,0x00F50DF3,0x0083AA60,'OBJC_IVAR_$_DynamicObject.uniqueID',40),
)

def signed(v):return v-(1<<32) if v&0x80000000 else v

def checked_word(m,a):
 v=m.word(a)
 if v is None:raise ValueError(f'missing word {a:#x}')
 return int(v)

def cstring(m,address):
 offset=m.offset(address,1)
 if offset is None:raise ValueError(f'missing cstring {address:#x}')
 end=m.data.find(b'\0',offset,offset+256)
 if end<0:raise ValueError(f'unterminated cstring {address:#x}')
 return m.data[offset:end].decode('utf-8')

def recover(path):
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('original ELF SHA mismatch')
 m=ELFMemory(path);text=(NATIVE/'disasm_dynamicobject_getsavedict.txt').read_text()
 coverage=verify_disassembly(m,text,START,END)
 base=(BASE_ADD+8+signed(checked_word(m,BASE_LITERAL)))&0xffffffff
 if base!=0x0105FAF4:raise ValueError('PIC base drift')
 elf=ELFFile(io.BytesIO(raw));dynsym=elf.get_section_by_name('.dynsym')
 if dynsym is None:raise ValueError('missing dynsym')
 symbols={s['st_value']:s.name for s in getattr(dynsym,'iter_symbols')() if s['st_value']!=0}
 selectors={}
 for cell,name in SELECTOR_CELLS.items():
  slot=(base+signed(checked_word(m,cell)))&0xffffffff;value=checked_word(m,slot)
  if m.selectors.get(value)!=name:raise ValueError(f'selector drift {name}')
  selectors[name]=f'0x{cell:08x}'
 ivars={}
 for cell,(name,expected) in IVAR_CELLS.items():
  slot=(base+signed(checked_word(m,cell)))&0xffffffff;storage=checked_word(m,slot)
  if symbols.get(storage)!=name or checked_word(m,storage)!=expected:raise ValueError(f'ivar drift {name}')
  ivars[name]=expected
 key_pairings=[]
 for key,cell,cstring_address,call_site,ivar,offset in KEY_PAIRINGS:
  string_object=(base+signed(checked_word(m,cell)))&0xffffffff
  if checked_word(m,string_object+8)!=cstring_address or cstring(m,cstring_address)!=key:
   raise ValueError(f'key drift {key}')
  key_pairings.append({'key':key,'constant_string_object':f'0x{string_object:08x}','literal_cell':f'0x{cell:08x}','cstring':f'0x{cstring_address:08x}','set_object_site':f'0x{call_site:08x}','ivar':ivar,'ivar_offset':offset})
 body_offset=m.offset(START,CODE_END-START)
 if body_offset is None:raise ValueError('missing body')
 body_offset=int(body_offset);body=m.data[body_offset:body_offset+CODE_END-START]
 return {
  'schema':1,'method':'DynamicObject -[getSaveDict]','types':'@8@0:4',
  'elf_sha256':hashlib.sha256(raw).hexdigest(),'imp':f'0x{START:08x}',
  'code_end':f'0x{CODE_END:08x}','boundary_end':f'0x{END:08x}',
  'code_words':(CODE_END-START)//4,'coverage_words':coverage,
  'body_sha256':hashlib.sha256(body).hexdigest(),'pic_base':f'0x{base:08x}',
  'objc_msgsend_sites':[f'0x{x:08x}' for x in OBJC_MSGSEND_SITES],
  'objc_msgsend_sites_unresolved':[],
  'objc_msgsend_sites_unresolved_count':0,
  'objc_msgsend_sites_known':{f'0x{x:08x}':name for x,name in [(0x83A820,'dictionary'),(0x83A888,'numberWithFloat:'),(0x83A8CC,'numberWithFloat:'),(0x83A8FC,'arrayWithObjects:'),(0x83A930,'setObject:forKey:'),(0x83A974,'numberWithInt:'),(0x83A99C,'setObject:forKey:'),(0x83A9D8,'numberWithInt:'),(0x83AA00,'setObject:forKey:')]},
  'indirect_blx_sites':[f'0x{x:08x}' for x in BLX_SITES],
  'indirect_blx_sites_unresolved_count':2,
  'save_dict_key_pairings':key_pairings,
  'known_selectors':selectors,'known_ivars':ivars,
  'return_boundary':'result is reloaded from [fp-0x14] at 0x0083aa64 after dictionary assembly',
  'claim':'bounded static selector/ivar inventory plus four key-to-setObject/ivar source pairings; two stack-indirect call targets, complete schema and dynamic-object construction remain unresolved',
 }

def main():
 p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('--check',action='store_true');p.add_argument('--output',type=Path,default=NATIVE/'dynamicobject_getsavedict.json');a=p.parse_args();r=recover(a.elf);text=json.dumps(r,indent=2,sort_keys=True)+'\n'
 if a.check:
  if a.output.read_text()!=text:raise SystemExit('stale dynamicobject_getsavedict.json')
 else:a.output.write_text(text)
 print('getSaveDict code_words=%d objc_msgSend=%d unresolved=%d'%(r['code_words'],len(r['objc_msgsend_sites']),r['objc_msgsend_sites_unresolved_count']))
if __name__=='__main__':main()
