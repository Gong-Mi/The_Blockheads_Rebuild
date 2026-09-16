#!/usr/bin/env python3
"""Seven complete ownership helpers: original ARM vs C++ O0/O2, no hooks."""
import argparse, ctypes, hashlib, json, random, subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
FUNCTIONS=[('workbenchKindForItemType',0x5deeb8,0x5df240),('itemTypeIsWorkbench',0x5b2aa0,0x5b2ad4),('itemTypeIsTorch',0x5df794,0x5df88c),('itemTypeIsStairs',0x5b2b0c,0x5b2ca0),('itemTypeIsColumn',0x5b291c,0x5b2aa0),('itemTypeIsPainting',0x5b902c,0x5b90c0),('itemTypeRequiresOwnershipToRemove',0x627c40,0x627f74)]
def main():
    p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
    assert hashlib.sha256(a.elf.read_bytes()).hexdigest()==SHA
    a.output_dir.mkdir(parents=True,exist_ok=True)
    with a.elf.open('rb') as f:
        e=ELFFile(f)
        assert e['e_machine']=='EM_ARM'
        loads=[(s['p_vaddr'],s['p_memsz'],s.data()) for s in e.iter_segments() if s['p_type']=='PT_LOAD']
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM); pages=set()
    for b,n,_ in loads:pages.update(range(b&~4095,(b+n+4095)&~4095,4096))
    for b in sorted(pages):u.mem_map(b,4096)
    for b,n,d in loads:u.mem_write(b,d)
    stack,stop=0x70000000,0x71000000
    u.mem_map(stack,0x10000);u.mem_map(stop,4096)
    root=Path(__file__).resolve().parents[1]
    bridge=a.output_dir/'ownership_bridge.cpp'
    bridge.write_text('#include "inventory_ownership.h"\n'+ '\n'.join('extern "C" int probe'+str(i)+'(int t) { return blockheads::recovered::ownership::'+name+'(t); }' for i,(name,_,_) in enumerate(FUNCTIONS)))
    libs=[]
    for opt in ('O0','O2'):
        out=a.output_dir/(opt+'.so')
        subprocess.run(['clang++','-std=c++17','-'+opt,'-shared','-fPIC','-I'+str(root/'reconstruction/recovered'),str(bridge),str(root/'reconstruction/recovered/inventory_ownership.cpp'),'-o',str(out)],check=True)
        lib=ctypes.CDLL(str(out));probes=[]
        for i in range(len(FUNCTIONS)):
            fn=getattr(lib,'probe'+str(i));fn.argtypes=[ctypes.c_int32];fn.restype=ctypes.c_int32;probes.append(fn)
        libs.append((lib,probes))
    rng=random.Random(0x627c40)
    values=sorted(set(range(65536))|{-1,-2,-32768,-65536,65536,2147483647,-2147483648}|{ctypes.c_int32(rng.getrandbits(32)).value for _ in range(1024)})
    report={'sha256':SHA,'scope':'complete seven pure ARM bodies including dependency calls; no function/import hooks; all uint16 values plus signed boundaries and seeded int32 probes, not exhaustive int32','inputs_per_function':len(values),'functions':[]}
    for index,(name,start,end) in enumerate(FUNCTIONS):
        mismatch=[];positive=[]
        for value in values:
            u.reg_write(UC_ARM_REG_SP,stack+0x8000);u.reg_write(UC_ARM_REG_LR,stop);u.reg_write(UC_ARM_REG_R0,value&0xffffffff)
            u.emu_start(start,stop,count=3000)
            assert u.reg_read(UC_ARM_REG_PC)==stop
            arm=ctypes.c_int32(u.reg_read(UC_ARM_REG_R0)).value
            cpp=[probes[index](value) for _,probes in libs]
            if any(x!=arm for x in cpp):mismatch.append({'input':value,'arm':arm,'cpp':cpp})
            if arm:positive.append([value,arm])
        row={'name':name,'start':hex(start),'end':hex(end),'body_sha256':hashlib.sha256(bytes(u.mem_read(start,end-start))).hexdigest(),'mismatches':mismatch,'nonzero_inputs':positive}
        report['functions'].append(row)
        (a.output_dir/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(name,'inputs',len(values),'O0/O2 mismatches',len(mismatch),flush=True)
        assert not mismatch
    assert len(report['functions'])==7
if __name__=='__main__':main()
