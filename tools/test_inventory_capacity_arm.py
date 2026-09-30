#!/usr/bin/env python3
"""Original capacity ARM instructions vs recovered C++, with explicit synthetic
immutable ObjC message receivers (not Foundation or original-app runtime).
Covers the full original entry/body on flat inventory and nil-subitems inputs;
nested-array/mutation behavior remains in the separate C++ contract tests.
"""
import argparse,ctypes,hashlib,itertools,json,struct,subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
def main():
 p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
 assert hashlib.sha256(a.elf.read_bytes()).hexdigest()==SHA
 a.output_dir.mkdir(parents=True,exist_ok=True)
 with a.elf.open('rb') as f:
  elf=ELFFile(f);assert elf['e_machine']=='EM_ARM' and elf.elfclass==32
  loads=[(s['p_vaddr'],s['p_memsz'],s.data()) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
 uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);pages=set()
 for base,size,_ in loads:pages.update(range(base&~4095,(base+size+4095)&~4095,4096))
 for page in sorted(pages):uc.mem_map(page,4096)
 for base,_,data in loads:uc.mem_write(base,data)
 graph=0x60000000;stack=0x70000000;stop=0x71000000;dispatch=0x72000000
 uc.mem_map(graph,0x10000);uc.mem_map(stack,0x10000);uc.mem_map(stop,4096);uc.mem_map(dispatch,4096)
 def word(at,value):uc.mem_write(at,struct.pack('<I',value&0xffffffff))
 self,world,inventory,slot,item=[graph+i*0x1000 for i in range(5)]
 word(self+4,world);word(self+0x298,inventory)
 # Original symbol/relocation independently verified by recover_inventory_capacity.
 word(0x105b7a0,dispatch)
 context={};calls={}
 def send(uc,address,size,data):
  receiver=uc.reg_read(UC_ARM_REG_R0);selptr=uc.reg_read(UC_ARM_REG_R1)
  selector=bytes(uc.mem_read(selptr,180)).split(b'\0')[0].decode()
  argument=uc.reg_read(UC_ARM_REG_R2);calls[selector]=calls.get(selector,0)+1
  if receiver==0:result=0
  elif selector=='worldUIDragging':assert receiver==world;result=context['dragging']
  elif selector=='count':
   assert receiver in (inventory,slot);result=8 if receiver==inventory else context['count']
  elif selector=='objectAtIndex:':
   if receiver==inventory:assert argument<8;result=slot
   else:assert receiver==slot and argument==0;result=item
  elif selector=='itemType':assert receiver==item;result=context['existingType']
  elif selector=='dataB':assert receiver==item;result=context['existingB']
  elif selector=='subItems':assert receiver==item;result=0
  else:raise AssertionError(('unimplemented message',hex(receiver),selector))
  uc.reg_write(UC_ARM_REG_R0,result&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 uc.hook_add(UC_HOOK_CODE,send,begin=dispatch,end=dispatch)
 repo=Path(__file__).resolve().parents[1];functions=[]
 for opt in (0,2):
  lib=a.output_dir/f'capacity-O{opt}.so'
  subprocess.run(['clang++','-std=c++17',f'-O{opt}','-UNDEBUG','-fPIC','-shared',
   '-I'+str(repo/'reconstruction/recovered'),str(repo/'tools/inventory_capacity_arm_bridge.cpp'),
   *[str(repo/'reconstruction/recovered'/f'inventory_{s}.cpp') for s in ('capacity','rules')],'-o',str(lib)],check=True)
  fn=ctypes.CDLL(str(lib)).recovered_capacity_probe;fn.argtypes=[ctypes.c_int32]*7;fn.restype=ctypes.c_int32;functions.append(fn)
 types=[-1,0,1,3,12,20,0x54,0x5b,0x67,0xa6,0xa7,0x104,0x12a,0x157,0x158,0x400,0x422,0x452]
 existing=[1,12,20,0x54,0x5b,0x67,0xa6,0xa7,0x104]
 variants=list(itertools.product(types,existing,(0,98,99),((0,0,0),(0,99,1),(0,100,65535),(1,0,0)),(0,-128)))
 total=0
 with (a.output_dir/'capacity-cases.jsonl').open('w') as output:
  for t,et,n,(ia,ib,eb),drag in variants:
   context.update(existingType=et,count=n,existingB=eb,dragging=drag)
   for reg,value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),(self,0,t,0)):uc.reg_write(reg,value&0xffffffff)
   sp=stack+0x8000;uc.reg_write(UC_ARM_REG_SP,sp);uc.reg_write(UC_ARM_REG_LR,stop);word(sp,ia);word(sp+4,ib)
   uc.emu_start(0xc5d7b8,stop,count=20000);assert uc.reg_read(UC_ARM_REG_PC)==stop
   expected=ctypes.c_int32(uc.reg_read(UC_ARM_REG_R0)).value
   args=[t,et,n,ia,ib,eb,drag];actual=[fn(*args) for fn in functions]
   row=dict(args=args,arm=expected,cpp=actual);output.write(json.dumps(row)+'\n')
   assert actual==[expected,expected],row
   total+=1
 report=dict(sha256=SHA,method='canPickUpItemOfType:subItems:dataA:dataB:',cases=total,match=True,message_counts=calls,boundary='Unicorn original ARM + synthetic immutable ObjC messages vs recovered C++ O0/O2. Flat/nil-subitems domain only; not Foundation or original-app execution.')
 (a.output_dir/'capacity-arm-result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
