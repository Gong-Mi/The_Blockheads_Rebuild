#!/usr/bin/env python3
"""Hash-gated bounded recovery of DynamicObject flag accessors."""
import argparse, hashlib, json, re
from pathlib import Path
from trace_objc_dispatch import ELFMemory

SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"
START, END, BASE = 0x83D0F0, 0x83D370, 0x0105FAF4
METHODS = [
 ("needsRemoved",0x83D0F0,0x83D124,0x83D12C,"getter",0x30,0x83D124,0x83D128,"OBJC_IVAR_$_DynamicObject.needsRemoved"),
 ("setNeedsRemoved:",0x83D12C,0x83D168,0x83D170,"setter",0x30,0x83D168,0x83D16C,"OBJC_IVAR_$_DynamicObject.needsRemoved"),
 ("updateNeedsToBeSent",0x83D170,0x83D1A4,0x83D1AC,"getter",0x31,0x83D1A4,0x83D1A8,"OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent"),
 ("setUpdateNeedsToBeSent:",0x83D1AC,0x83D1E8,0x83D1F0,"setter",0x31,0x83D1E8,0x83D1EC,"OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent"),
 ("creationDataNeedsToBeSent",0x83D1F0,0x83D224,0x83D22C,"getter",0x32,0x83D224,0x83D228,"OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent"),
 ("setCreationDataNeedsToBeSent:",0x83D22C,0x83D268,0x83D270,"setter",0x32,0x83D268,0x83D26C,"OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent"),
 ("unreliableUpdateNeedsToBeSent",0x83D270,0x83D2A4,0x83D2AC,"getter",0x33,0x83D2A4,0x83D2A8,"OBJC_IVAR_$_DynamicObject.unreliableUpdateNeedsToBeSent"),
 ("setUnreliableUpdateNeedsToBeSent:",0x83D2AC,0x83D2E8,0x83D2F0,"setter",0x33,0x83D2E8,0x83D2EC,"OBJC_IVAR_$_DynamicObject.unreliableUpdateNeedsToBeSent"),
 ("isNet",0x83D2F0,0x83D324,0x83D32C,"getter",0x34,0x83D324,0x83D328,"OBJC_IVAR_$_DynamicObject.isNet"),
 ("macroTileOwner",0x83D32C,0x83D368,0x83D370,"pointer_getter",0x0C,0x83D368,0x83D36C,"OBJC_IVAR_$_DynamicObject.macroTileOwner"),
]

def s(v): return v-(1<<32) if v&0x80000000 else v

def recover(path, disasm):
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SHA: raise ValueError('ELF SHA mismatch')
    m=ELFMemory(path)
    text=disasm.read_text()
    for a in range(START,END,4):
        if not re.search(rf'^0x{a:08x}\t',text,re.M): raise ValueError(f'missing disassembly {a:#x}')
    rows=[]
    for name,imp,code_end,boundary,kind,expected_offset,ivar_cell,base_cell,ivar_name in METHODS:
        if not (imp <= code_end <= boundary <= END) or (code_end-imp)%4: raise ValueError(f'bad boundary {name}')
        base=BASE
        storage=m.word((base+s(m.word(ivar_cell)))&0xffffffff)
        if m.word(storage)!=expected_offset: raise ValueError(f'ivar offset drift {name}')
        # Symbol name is resolved from the fixed ivar address in the known binary.
        if storage not in {0xF33E44,0xF33E48,0xF33E4C,0xF33E50,0xF33E40,0xF33E2C}: raise ValueError(f'unknown ivar storage {name}')
        bodyoff=m.offset(imp,code_end-imp)
        body=m.data[bodyoff:bodyoff+code_end-imp]
        row={'selector':name,'imp':f'0x{imp:08x}','code_end':f'0x{code_end:08x}','bounded_end':f'0x{boundary:08x}','kind':kind,'code_words':(code_end-imp)//4,'bounded_words':(boundary-imp)//4,'body_sha256':hashlib.sha256(body).hexdigest(),'ivar':ivar_name,'ivar_offset':expected_offset,'pic_base':f'0x{BASE:08x}','ivar_cell':f'0x{ivar_cell:08x}','base_cell':f'0x{base_cell:08x}'}
        if kind=='getter':
            if m.word(imp+0x28)!=0xe1d000d0: raise ValueError(f'getter pattern drift {name}')
            row['return_type']='bool'
        elif kind=='setter':
            if any(m.word(imp+x)!=v for x,v in ((0x28,0xf57ff05b),(0x2c,0xe7c02001),(0x30,0xf57ff05b))): raise ValueError(f'setter pattern drift {name}')
            row['parameter_type']='bool'
        else:
            if m.word(imp+0x24)!=0xe7900001 or m.word(imp+0x28)!=0xf57ff05b: raise ValueError('pointer getter pattern drift')
            row['return_type']='pointer'
        rows.append(row)
    return {'schema':1,'elf_sha256':SHA,'range_start':f'0x{START:08x}','range_end':f'0x{END:08x}','methods':rows,'claim':'bounded static ARM32 evidence; no runtime or APK integration claim'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('elf',type=Path);ap.add_argument('--check',action='store_true');ap.add_argument('--output',type=Path,default=Path('reconstruction/reverse-v3/native/dynamicobject_flags.json'));ap.add_argument('--disasm',type=Path,default=Path('reconstruction/reverse-v3/native/disasm_dynamicobject_flags.txt'));a=ap.parse_args();r=recover(a.elf,a.disasm);t=json.dumps(r,indent=2,sort_keys=True)+'\n'
    if a.check:
        if a.output.read_text()!=t: raise SystemExit('stale dynamicobject_flags.json')
    else: a.output.write_text(t)
    print(f"dynamicobject-flags: methods={len(r['methods'])} words={(END-START)//4} PASS")
if __name__=='__main__': main()
