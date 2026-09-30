#!/usr/bin/env python3
"""Hash-pinned original ARM helper differential. Not an app/device test.

Loads original ELF instructions into Unicorn; only imported __aeabi_idiv is
provided as an explicit signed integer division shim. C++ O0/O2 implementations
are compared against those instructions, not against generated expected tables.
Requires local original ELF, unicorn, pyelftools and clang++. CI's mandatory
source tests do not pretend to have this copyrighted original binary.
"""
import argparse,ctypes,hashlib,json,struct,subprocess,collections
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC

SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
SPECS=[
 ('itemTypeIsValidFillItem','_Z23itemTypeIsValidFillItem8ItemType',0x580cdc,384),
 ('itemTypeIsValidInventoryItem','_Z28itemTypeIsValidInventoryItem8ItemType',0xc5e9ac,116),
 ('itemTypeIsLiquid','_Z16itemTypeIsLiquid8ItemType',0xc5ea20,24),
 ('itemTypeCarriesLiquids','_Z22itemTypeCarriesLiquids8ItemType',0xc5ea90,24),
 ('itemTypeSubItemsCanBeModifiedWhileCarried','_Z41itemTypeSubItemsCanBeModifiedWhileCarried8ItemType',0x4eb960,68),
 ('itemTypeCanBeColored','_Z20itemTypeCanBeColored8ItemType',0x4d6128,248),
 ('itemTypeIsStackable','_Z19itemTypeIsStackable8ItemTypett',0x4ea3cc,244),
 ('usageIncrementPerUse','_Z20usageIncrementPerUse8ItemTypeiaa',0x5e9c30,884),
]
def signed(n): return ctypes.c_int32(n).value

def main():
 p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
 raw=a.elf.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA: raise ValueError('original ELF SHA mismatch')
 a.output_dir.mkdir(parents=True,exist_ok=True)
 with a.elf.open('rb') as f:
  elf=ELFFile(f)
  assert elf['e_machine']=='EM_ARM' and elf.elfclass==32
  syms={s.name:(s['st_value'],s['st_size']) for s in elf.get_section_by_name('.dynsym').iter_symbols()}
  loads=[(s['p_vaddr'],s['p_memsz'],s.data()) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
 def read(va,size):
  for base,_,data in loads:
   if base<=va and va+size<=base+len(data):return data[va-base:va-base+size]
  raise ValueError(hex(va))
 uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
 pages=set()
 for base,size,_ in loads:
  pages.update(range(base&~4095,(base+size+4095)&~4095,4096))
 for page in sorted(pages):uc.mem_map(page,4096)
 for base,_,data in loads:uc.mem_write(base,data)
 stack=0x70000000;stop=0x71000000
 uc.mem_map(stack,0x10000);uc.mem_map(stop,4096)
 def branch_target(at):
  word=struct.unpack('<I',read(at,4))[0];assert word>>24==0xeb
  imm=word&0xffffff
  if imm&0x800000:imm-=1<<24
  return at+8+imm*4
 div=branch_target(0x5e9f28);assert div==branch_target(0x5e9f6c)
 def imported_division(uc,address,size,data):
  x=signed(uc.reg_read(UC_ARM_REG_R0));y=signed(uc.reg_read(UC_ARM_REG_R1))
  assert y!=0
  q=abs(x)//abs(y)
  if (x<0)!=(y<0):q=-q
  uc.reg_write(UC_ARM_REG_R0,q&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 uc.hook_add(UC_HOOK_CODE,imported_division,begin=div,end=div)
 repo=Path(__file__).resolve().parents[1]
 implementations=[]
 for opt in (0,2):
  lib=a.output_dir/f'inventory-rules-O{opt}.so'
  subprocess.run(['clang++','-std=c++17',f'-O{opt}','-shared','-fPIC','-DINVENTORY_RULES_SHARED_TEST',
   '-I'+str(repo/'reconstruction/recovered'),str(repo/'tools/test_inventory_rules.cpp'),
   str(repo/'reconstruction/recovered/inventory_rules.cpp'),'-o',str(lib)],check=True)
  fn=ctypes.CDLL(str(lib)).inventory_rule_probe
  fn.argtypes=[ctypes.c_int32,ctypes.c_int32,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint32];fn.restype=ctypes.c_int32
  implementations.append(fn)
 types=list(range(-4,0x460))+[-2147483648,2147483647]
 counts=collections.Counter();records=[]
 with (a.output_dir/'cases.jsonl').open('w') as evidence:
  for index,(name,symbol,entry,size) in enumerate(SPECS):
   assert syms[symbol]==(entry,size),(symbol,syms[symbol])
   body=read(entry,size)
   records.append(dict(name=name,symbol=symbol,implementation=hex(entry),size=size,sha256=hashlib.sha256(body).hexdigest(),fixed_words=[f'{w:08x}' for w in struct.unpack('<'+'I'*(size//4),body)],original_app_runtime_verified=False))
   for t in types:
    args=[(0,0,0)]
    if index==6:args=[(x,y,0) for x,y in [(0,0),(1,1),(0,1),(1,0),(1,2),(65535,65534),(32768,0),(65535,65535)]]
    if index==7:args=[(m,f2,f3) for m in (-1,0,1,2,3,4) for f2,f3 in [(0,0),(1,0),(0,1),(-128,-1)]]
    for x,y,z in args:
     for reg,value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),(t,x,y,z)):uc.reg_write(reg,value&0xffffffff)
     uc.reg_write(UC_ARM_REG_SP,stack+0x8000);uc.reg_write(UC_ARM_REG_LR,stop)
     uc.emu_start(entry,stop,count=2000)
     assert uc.reg_read(UC_ARM_REG_PC)==stop,(name,'instruction budget exceeded')
     expected=signed(uc.reg_read(UC_ARM_REG_R0))
     actual=[fn(index,t,x&0xffffffff,y&0xffffffff,z&0xffffffff) for fn in implementations]
     row=dict(function=name,args=[t,x,y,z],arm=expected,cpp_O0=actual[0],cpp_O2=actual[1]);evidence.write(json.dumps(row)+'\n')
     assert actual==[expected,expected],row
     counts[name]+=1
   evidence.flush()
 report=dict(elf_sha256=SHA,methods=records,case_counts=dict(counts),total_cases=sum(counts.values()),imported_division_shim=hex(div),boundary='Original ARM helper instructions under Unicorn vs C++ O0/O2, not original app runtime or Android gameplay')
 (a.output_dir/'inventory_rules.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({k:v for k,v in report.items() if k!='methods'},indent=2))
if __name__=='__main__':main()
