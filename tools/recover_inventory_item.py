#!/usr/bin/env python3
"""Reproduce bounded InventoryItem evidence, NOT an automatic decompiler.
Requires pyelftools and capstone 5.0.7. No APK/ELF is included in the repo.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
from elftools.elf.elffile import ELFFile

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
ROOT = Path(__file__).resolve().parents[1]
# End bounds are exclusive. exidx coalesces setDataB with the next IMP;
# split at the independently indexed dynamicObjectSaveDict IMP, NOT at exidx end.
REGIONS = [
    ('initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:',0xac5644,0xac5b00,0xac5b4c,'logic'),
    ('subItemSlotCount helper',0xac5b4c,0xac5cd8,0xac5cd8,'numeric-helper'),
    ('dealloc',0xac5cd8,0xac5db8,0xac5dd8,'runtime-only'),
    ('initWithSaveData:',0xac5dd8,0xac6434,0xac64b0,'logic'),
    ('plist decode options-zero wrapper',0xac64b0,0xac64d4,0xac64d4,'external-helper'),
    ('saveData',0xac64d4,0xac6c14,0xac6c70,'logic'),
    ('plist encode XML helper',0xac6c70,0xac6db8,0xac6ddc,'external-helper'),
    ('updateSubItemSlot:atIndex:',0xac6ddc,0xac7100,0xac7130,'logic'),
    ('subItemSlotDataAtIndex:',0xac7130,0xac7434,0xac745c,'logic'),
    ('itemType',0xac745c,0xac7490,0xac7498,'logic'),
    ('subItems',0xac7498,0xac74d4,0xac74dc,'logic'),
    ('selectedSubItemIndex',0xac74dc,0xac7510,0xac7518,'logic'),
    ('setSelectedSubItemIndex:',0xac7518,0xac7554,0xac755c,'logic'),
    ('dataA',0xac755c,0xac7590,0xac7598,'logic'),
    ('setDataA:',0xac7598,0xac75d8,0xac75e0,'logic'),
    ('dataB',0xac75e0,0xac7614,0xac761c,'logic'),
    ('setDataB:',0xac761c,0xac765c,0xac7664,'logic'),
    ('dynamicObjectSaveDict',0xac7664,0xac76a0,0xac76a8,'logic'),
    ('plist decode helper',0xac76a8,0xac77f0,0xac7814,'external-helper'),
]
ANCHORS = {0xac56c8:0xe50b1024,0xac5e40:0xe50b102c,
           0xac5870:0x9a00007b,0xac5fe8:0x9a000051,
           0xac658c:0xe14b03b0,0xac65a4:0xe14b02be,
           0xac65bc:0xe14b02bc,0xac65d4:0xe54b002a,
           0xac6cd4:0xe3a00064,0xac6e3c:0x3a0000ad,
           0xac718c:0x3a0000a3,0xac7484:0xf57ff05b}

def require(ok, message):
    if not ok:
        raise ValueError(message)

def recover(path):
    blob = path.read_bytes()
    require(hashlib.sha256(blob).hexdigest() == SHA, 'ELF SHA mismatch')
    with path.open('rb') as f:
        elf = ELFFile(f)
        require(elf.elfclass == 32 and elf.little_endian and elf['e_machine']=='EM_ARM', 'ARM32 LE required')
        segments = [(s['p_vaddr'],s.data()) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
        symbols = {s.name:s['st_value'] for sec in elf.iter_sections() if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols()}
        rels = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_REL','SHT_RELA'):
                tab = elf.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    rels[r['r_offset']] = (r['r_info_type'],tab.get_symbol(r['r_info_sym']).name)
    def read(a,n):
        for base,data in segments:
            if base<=a and a+n<=base+len(data): return data[a-base:a-base+n]
        raise ValueError('not file backed: '+hex(a))
    def word(a): return struct.unpack('<I',read(a,4))[0]
    def string(a):
        out=bytearray()
        for _ in range(512):
            b=read(a,1); a+=1
            if b==b'\0':
                require(bool(out) and all(32<=v<127 for v in out), 'not printable string')
                return out.decode('ascii')
            out+=b
        raise ValueError('unterminated string')
    base=(0xac5654+8+word(0xac5b48))&0xffffffff
    require(base==0x105faf4,'PIC base changed')
    for a,w in ANCHORS.items(): require(word(a)==w,'instruction anchor '+hex(a))
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM); md.detail=True
    methods=[]; all_refs=[]; pics=[]
    for name,start,pool,end,kind in REGIONS:
        instructions=[]; calls=[]; branches=[]; refs={}; last=None
        for a in range(start,pool,4):
            decoded=list(md.disasm(read(a,4),a)); require(len(decoded)==1,'decode '+hex(a))
            i=decoded[0]
            row=dict(address=hex(a),word=f'{word(a):08x}',mnemonic=i.mnemonic,operands=i.op_str)
            instructions.append(row)
            if i.mnemonic in ('bl','blx'): calls.append(hex(a))
            elif i.mnemonic.startswith('b') and i.mnemonic not in ('bic','bics'): branches.append(hex(a))
            if i.mnemonic=='ldr' and len(i.operands)==2 and i.operands[1].type==ARM_OP_MEM and i.operands[1].mem.base==ARM_REG_PC:
                literal=a+8+i.operands[1].mem.disp
                require(pool<=literal<end,'literal outside bounded pool '+hex(a))
                refs.setdefault(literal,[]).append(hex(a))
            if i.mnemonic=='add' and len(i.operands)==3 and i.operands[1].type==ARM_OP_REG and i.operands[1].reg==ARM_REG_PC:
                require(last is not None and last.mnemonic=='ldr' and last.operands[0].reg==i.operands[2].reg and last.operands[1].type==ARM_OP_MEM and last.operands[1].mem.base==ARM_REG_PC,'PIC pair '+hex(a))
                lit=last.address+8+last.operands[1].mem.disp
                require((a+8+word(lit))&0xffffffff==base,'PIC chain '+hex(a))
                pics.append(dict(add=hex(a),literal=hex(lit),base=hex(base)))
            last=i
        for lit,uses in sorted(refs.items()):
            target=(base+word(lit))&0xffffffff
            row=dict(owner=name,literal=hex(lit),value=hex(word(lit)),uses=uses,target=hex(target))
            relocation=rels.get(target)
            if relocation: row['relocation']=list(relocation)
            if relocation and relocation[1]=='__CFConstantStringClassReference':
                row.update(kind='constant-string',name=string(word(target+8)),length=word(target+12))
            elif relocation and relocation[1]:
                row.update(kind='import',name=relocation[1])
            elif relocation==(23,''):
                names=[n for n,v in symbols.items() if v==word(target) and n.startswith('OBJC_IVAR_$_InventoryItem.')]
                if names:
                    require(len(names)==1,'ivar ambiguity')
                    row.update(kind='ivar',name=names[0],symbol_address=hex(word(target)),offset=word(word(target)))
                else:
                    try: row.update(kind='selector',name=string(word(target)))
                    except ValueError:
                        pointee=word(target)
                        row.update(kind='object-reference',pointee=hex(pointee),pointee_relocation=list(rels.get(pointee,(0,''))))
                        # ObjC2 class: isa/super/cache/vtable/data; class_ro name +16.
                        try:
                            ro=word(pointee+16)&~3
                            row.update(class_name=string(word(ro+16)),class_ro=hex(ro),superclass_relocation=list(rels.get(pointee+4,(0,''))))
                        except ValueError:
                            pass
            else:
                try: row.update(kind='constant-string',name=string(word(target+8)),length=word(target+12))
                except ValueError: row['kind']='pic-displacement' if any(x['literal']==hex(lit) for x in pics) else 'unresolved-literal'
            all_refs.append(row)
        methods.append(dict(name=name,kind=kind,start=hex(start),pool_start=hex(pool),end=hex(end),region_sha256=hashlib.sha256(read(start,end-start)).hexdigest(),instructions=instructions,pool_words=[dict(address=hex(a),word=f'{word(a):08x}') for a in range(pool,end,4)],calls=calls,branches=branches))
    ivars={r['name']:r['offset'] for r in all_refs if r['kind']=='ivar'}
    require(ivars=={'OBJC_IVAR_$_InventoryItem.itemType':4,
                    'OBJC_IVAR_$_InventoryItem.dataA':8,
                    'OBJC_IVAR_$_InventoryItem.dataB':10,
                    'OBJC_IVAR_$_InventoryItem.subItems':12,
                    'OBJC_IVAR_$_InventoryItem.selectedSubItemIndex':16,
                    'OBJC_IVAR_$_InventoryItem.dynamicObjectSaveDict':20},'ivar layout changed')
    require(all(len(r['instructions'])+len(r['pool_words'])==(int(r['end'],16)-int(r['start'],16))//4 for r in methods),'complete word coverage')
    require(all(int(a['end'],16)==int(b['start'],16) for a,b in zip(methods,methods[1:])),'nonoverlapping contiguous regions')
    require({r['name'] for r in all_refs if r['kind']=='constant-string'} >= {'d','s'},'d/s CFString keys')
    require({r['name'] for r in all_refs if r['kind']=='selector'} >= {'init','saveData','gzipInflate','gzipDeflate','dataWithPropertyList:format:options:error:','propertyListWithData:options:format:error:'},'codec selector chain')
    result=dict(schema=1,elf_sha256=SHA,architecture='ARM32 LE ARM-state',pic_base=hex(base),regions=methods,pic_setups=pics,pic_references=all_refs,ivars=ivars,anchors={hex(a):hex(w) for a,w in ANCHORS.items()},logic_method_count=sum(r[-1]=='logic' for r in REGIONS),runtime_verified=False,foundation_runtime_implemented=False,integrated_into_game=False,scope='Complete logical method bodies under fresh-object, stable ordinary-container contracts. Not full Objective-C dynamic equivalence; see INVENTORY_ITEM.md.')
    return json.dumps(result,indent=2)+'\n'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--out-dir',type=Path,default=ROOT/'reconstruction/reverse-v3/native')
    p.add_argument('--check',action='store_true')
    a=p.parse_args(); data=recover(a.elf); target=a.out_dir/'inventory_item.json'
    if a.check: require(target.read_text()==data,'stale '+str(target))
    else: a.out_dir.mkdir(parents=True,exist_ok=True); target.write_text(data)
    d=json.loads(data)
    print(json.dumps(dict(status='PASS',regions=len(d['regions']),logical_methods=d['logic_method_count'],instructions=sum(len(x['instructions']) for x in d['regions']),pool_words=sum(len(x['pool_words']) for x in d['regions']),calls=sum(len(x['calls']) for x in d['regions']),ivars=d['ivars'],unresolved=[x for x in d['pic_references'] if x['kind']=='unresolved-literal'])))
if __name__=='__main__': main()
