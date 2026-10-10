#!/usr/bin/env python3
"""Hash-gated key-source/value-conversion/ivar pairing for DynamicObject init."""
import argparse, hashlib, json
from pathlib import Path
from trace_objc_dispatch import ELFMemory

SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE=0x0105FAF4
START,CODE_END,BOUNDARY=0x839F7C,0x83A368,0x83A3C0
METHODS=[
 {'key':'uniqueID','cell':0x83A3B0,'cstring':0xF50DF3,'value_type':'uint64','key_call':0x83A194,'conversion':'unsignedLongValue','conversion_sites':[0x83A1A4],'write_sites':[0x83A1BC],'ivar_offset':40,'call_words':{0x83A194:0xEBE621A0,0x83A1A4:0xEBE6219C,0x83A1BC:0xE7A10002}},
 {'key':'pos_x','cell':0x83A39C,'cstring':0xF571A3,'value_type':'int','key_call':0x83A1DC,'conversion':'intValue','conversion_sites':[0x83A1EC],'write_sites':[0x83A200],'ivar_offset':16,'call_words':{0x83A1DC:0xE12FFF3C,0x83A1EC:0xE12FFF32,0x83A200:0xE5810000}},
 {'key':'pos_y','cell':0x83A398,'cstring':0xF571A9,'value_type':'int','key_call':0x83A218,'conversion':'intValue','conversion_sites':[0x83A228],'write_sites':[0x83A23C],'ivar_offset':20,'call_words':{0x83A218:0xE12FFF33,0x83A228:0xE12FFF32,0x83A23C:0xE5810004}},
 {'key':'floatPos','cell':0x83A384,'cstring':0xF571AF,'value_type':'Vector2','key_call':0x83A26C,'conversion':'floatValue','conversion_sites':[0x83A290,0x83A2D4],'write_sites':[0x83A310,0x83A318],'ivar_offset':24,'array_indices':[0,1],'call_words':{0x83A26C:0xE12FFF33,0x83A280:0xE12FFF33,0x83A290:0xE12FFF32,0x83A2B0:0xE12FFF33,0x83A2C4:0xE12FFF33,0x83A2D4:0xE12FFF32,0x83A310:0xE584E000,0x83A318:0xE584E004}},
]

def s(v): return v-(1<<32) if v&0x80000000 else v

def cstring(m,addr):
 off=m.offset(addr,1)
 if off is None: raise ValueError(f'missing cstring {addr:#x}')
 end=m.data.find(b'\0',off,off+256)
 if end<0: raise ValueError(f'unterminated cstring {addr:#x}')
 return m.data[off:end].decode('utf-8')

def recover(path):
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA: raise ValueError('ELF SHA mismatch')
 m=ELFMemory(path); rows=[]
 for item in METHODS:
  obj=(BASE+s(m.word(item['cell'])))&0xffffffff
  if m.word(obj+8)!=item['cstring']: raise ValueError(f"{item['key']}: constant string pointer drift")
  if cstring(m,item['cstring'])!=item['key']: raise ValueError(f"{item['key']}: cstring drift")
  for address,expected in item['call_words'].items():
   if m.word(address)!=expected: raise ValueError(f"{item['key']}: instruction drift at {address:#x}")
  row={k:v for k,v in item.items() if k not in ('call_words',)}
  row['constant_string_object']=f'0x{obj:08x}'
  row['literal_cell']=f'0x{item["cell"]:08x}'
  row['cstring']=f'0x{item["cstring"]:08x}'
  row['key_call']=f'0x{item["key_call"]:08x}'
  row['conversion_sites']=[f'0x{x:08x}' for x in item['conversion_sites']]
  row['write_sites']=[f'0x{x:08x}' for x in item['write_sites']]
  del row['cell']
  rows.append(row)
 return {'schema':2,'elf_sha256':SHA,'method':'DynamicObject -[initWithWorld:dynamicWorld:saveDict:cache:]','imp':f'0x{START:08x}','code_end':f'0x{CODE_END:08x}','bounded_end':f'0x{BOUNDARY:08x}','pic_base':f'0x{BASE:08x}','keys':rows,'claim':'four key-source/value-conversion/ivar-write pairings are statically bounded; ownerID and complete save schema remain unresolved'}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('elf',type=Path);ap.add_argument('--check',action='store_true');ap.add_argument('--output',type=Path,default=Path('reconstruction/reverse-v3/native/dynamicobject_init_keys.json'));a=ap.parse_args();r=recover(a.elf);t=json.dumps(r,indent=2,sort_keys=True)+'\n'
 if a.check:
  if a.output.read_text()!=t: raise SystemExit('stale dynamicobject_init_keys.json')
 else:a.output.write_text(t)
 print(f"dynamicobject-init-keys: keys={len(r['keys'])} PASS")
if __name__=='__main__':main()
