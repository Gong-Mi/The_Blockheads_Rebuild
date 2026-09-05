#!/usr/bin/env python3
"""Recover hash-pinned complete setter, PIC fields, ABI boundaries and CFG edges."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from recover_world_view_contracts import SHA, require

START, END, POOL_END = 0x5531d0, 0x55365c, 0x5536a4
REGION_SHA = 'a587b51ed92d57877723438e5518d8a149f84c1df11468b61b0b8a380279a9e1'
BRANCHES = {
 0x553270:'BLT: x < signed(width<<5) OR unordered -> negative-check; otherwise positive wrap',
 0x55331c:'BLT: goal.x < width OR unordered -> skip goal subtraction',
 0x553380:'join wrapping at 0x5534a4',
 0x5533ac:'BPL: x >= 0 OR unordered -> skip negative wrap',
 0x553438:'BPL: goal.x >= 0 OR unordered -> skip goal addition',
 0x55349c:'join 0x5534a0', 0x5534a0:'join 0x5534a4',
 0x5534dc:'BPL: pinchScale >= 1 OR unordered -> retain; otherwise local clamp to 1',
}

def recover(path):
    require(hashlib.sha256(path.read_bytes()).hexdigest()==SHA,'ELF SHA mismatch')
    with path.open('rb') as f:
        elf=ELFFile(f)
        segments=[(s['p_vaddr'],s.data()) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
        symbols={s.name:s['st_value'] for sec in elf.iter_sections() if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols()}
        relocs={}
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_REL','SHT_RELA'):
                table=elf.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    relocs[r['r_offset']]=(r['r_info_type'],table.get_symbol(r['r_info_sym']).name)
    def read(a,n):
        for b,d in segments:
            if b<=a and a+n<=b+len(d): return d[a-b:a-b+n]
        raise ValueError(hex(a))
    def word(a): return struct.unpack('<I',read(a,4))[0]
    require(hashlib.sha256(read(START,POOL_END-START)).hexdigest()==REGION_SHA,'setter bytes changed')
    base=(0x5531e0+8+word(0x5536a0))&0xffffffff
    require(base==0x105faf4,'PIC base mismatch')
    fields=[]
    for literal,name,offset in [(0x553668,'accurateTranslation',0x270),(0x553670,'worldWidthMacro',0xc),
                                (0x553674,'translationGoal',0x278),(0x553688,'pinchScale',0x190),
                                (0x55368c,'roundedTranslation',0x268)]:
        slot=(base+word(literal))&0xffffffff; symbol=word(slot)
        require(relocs[slot]==(23,'') and symbols['OBJC_IVAR_$_World.'+name]==symbol and word(symbol)==offset,'ivar chain mismatch')
        fields.append(dict(name=name,offset=hex(offset),literal=hex(literal),slot=hex(slot),symbol=hex(symbol)))
    dispatch=[]
    for literal,expected in [(0x553698,b'instance'),(0x55369c,b'setListenerPosition:zoom:')]:
        ref=(base+word(literal))&0xffffffff; address=word(ref)
        require(relocs[ref]==(23,'') and read(address,len(expected)+1)==expected+b'\0','selector chain mismatch')
        dispatch.append(dict(selector=expected.decode(),ref=hex(ref),string=hex(address)))
    classref=(base+word(0x553694))&0xffffffff
    require(relocs[classref]==(23,'') and word(classref)==symbols['OBJC_CLASS_$_MJSoundManager'],'classref mismatch')
    # Decode both PLT veneers independently, including ARM rotated immediate.
    def imm(w):
        v=w&255; rot=((w>>8)&15)*2
        return ((v>>rot)|(v<<(32-rot)))&0xffffffff if rot else v
    for plt,symbol in [(0x1c3d4c,'__wrap_fmodf'),(0x1c281c,'objc_msgSend')]:
        a,b,c=[word(plt+4*i) for i in range(3)]
        require(a&0xfffff000==0xe28fc000 and b&0xfffff000==0xe28cc000 and c&0xfffff000==0xe5bcf000,'PLT format')
        slot=(plt+8+imm(a)+imm(b)+(c&4095))&0xffffffff
        require(relocs[slot][1]==symbol,'PLT target mismatch')
    helper='e24dd004 e58d0000 e59d0000 e28dd004 e12fff1e'
    require(read(0x4bdaac,20)==b''.join(struct.pack('<I',int(x,16)) for x in helper.split()),'Vector2 conversion not identity')
    require(struct.unpack('<d',read(0x553660,8))[0]==40.0,'quantum constant')
    # VFPExpandImm(0x70): sign=0, exponent=0x3ff, fraction=0 -> 1.0.
    require(word(0x5534a8)==0xeeb70b00 and word(0x553518)==0xeeb73b00,'VFP immediate words')
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM); insns=list(md.disasm(read(START,END-START),START))
    require(len(insns)*4==END-START,'incomplete code coverage')
    calls=[]; branches=[]
    for i in insns:
        if i.mnemonic=='bl':
            target=int(i.op_str.lstrip('#'),16)
            require(target in (0x4bdaac,0x1c3d4c,0x1c281c),'unexpected dependency')
            if target==0x4bdaac:
                receiver={0x55323c:'self.accurateTranslation (initial x check)',0x5532c4:'self.accurateTranslation (subtract width)',
                          0x5532f0:'self.translationGoal (positive check)',0x55336c:'self.translationGoal (subtract width)',
                          0x55339c:'self.accurateTranslation (negative check)',0x5533fc:'self.accurateTranslation (add width)',
                          0x553428:'self.translationGoal (negative check)',0x553488:'self.translationGoal (add width)',
                          0x5534f8:'by-value input (save x)',0x553508:'by-value input (fmod x)',
                          0x55356c:'self.roundedTranslation (write x)',0x55357c:'by-value input (save y)',
                          0x55358c:'by-value input (fmod y)',0x5535d4:'self.roundedTranslation (write y)'}[i.address]
                effect='Vector2::operator float*(): r0='+receiver+'; returns r0 unchanged; complete 20-byte body verified'
            elif target==0x1c3d4c: effect='__wrap_fmodf(original input '+('x' if i.address==0x553534 else 'y')+', float(1.0/(40.0/localScale))); r0/r1 -> r0'
            elif i.address==0x5535f4: effect='objc_msgSend: r0=class MJSoundManager, r1=instance; returns receiver; may mutate world'
            else: effect='objc_msgSend: r0=prior instance result, r1=setListenerPosition:zoom:, r2/r3=POST-CALL accurateTranslation, [sp]=float(POST-CALL pinchScale)'
            calls.append(dict(address=hex(i.address),target=hex(target),effect=effect))
        elif i.mnemonic.startswith('b'):
            require(i.address in BRANCHES,'unmapped branch')
            branches.append(dict(address=hex(i.address),opcode=i.mnemonic,target=i.op_str,meaning=BRANCHES[i.address]))
    require({int(x['address'],16) for x in branches}==set(BRANCHES),'branch map mismatch')
    root=Path(__file__).resolve().parents[1]
    rows=[x.split('\t') for x in (root/'reconstruction/reverse-v3/native/libApplication_objc_methods.tsv').read_text().splitlines()]
    types=[r[4] for r in rows if len(r)>=5 and r[:4]==['0x005531d0','World','instance','setTranslation:']]
    require(len(types)==1,'method ABI missing')
    result=dict(schema=1,elf_sha256=SHA,region_sha256=REGION_SHA,implementation=hex(START),code_end=hex(END),pool_end=hex(POOL_END),
                selector='setTranslation:',types=types[0],complete_local_method=True,stage='implemented',runtime_verified=False,integrated_into_game=False,
                fields=fields,selectors=dispatch,receiver_class='MJSoundManager',classref=hex(classref),
                instruction_count=len(insns),calls=calls,call_count=len(calls),branches=branches,branch_count=len(branches),
                numeric_constants={'width_shift':5,'quantum_numerator_f64':40.0,'scale_floor_f64':1.0},
                unresolved_boundaries=['Imported __wrap_fmodf implementation/FP environment','Dynamic MJSoundManager instance and setListenerPosition:zoom: implementations; explicit mandatory runtime interfaces, not no-op stubs'])
    return json.dumps(result,indent=2,ensure_ascii=False)+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--elf',required=True,type=Path);p.add_argument('--check',action='store_true')
    p.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'reconstruction/reverse-v3/native/world_translation.json');a=p.parse_args()
    text=recover(a.elf)
    if a.check: require(a.output.read_text()==text,'stale evidence')
    else: a.output.write_text(text)
    d=json.loads(text);print(f"PASS: {d['instruction_count']} instructions, {d['call_count']} calls, {d['branch_count']} branches; PIC/PLT/ABI/constants verified")
if __name__=='__main__': main()
