#!/usr/bin/env python3
"""Bounded ARM32 register/stack provenance for pickup lookup.

The output is candidate-level evidence, not semantic decompilation. It uses a
reachable CFG, bounded register/stack transfer, explicit caller-saved clobbers,
and compact fingerprints so loops converge without emitting giant nested phi
expressions.
"""
import argparse, hashlib, json, struct
from collections import defaultdict, deque
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from armv7_semantics import (arm_pc, branch_target, canonical_reg,
                             decode_address, decode_bfc, decode_data_op,
                             decode_memory, operand_value, transfer_bfc)

SHA='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START,END=0xc61dd0,0xc626d8
ROOT=Path(__file__).resolve().parents[1]
REGS={f'r{i}' for i in range(13)}|{'ip','lr','fp','sp'}
CALLER={'r0','r1','r2','r3','r12','ip','lr'}


def req(x,m):
    if not x: raise ValueError(m)

def K(x): return json.dumps(x,sort_keys=True,separators=(',',':'))
def V(k,**kw): return {'kind':k,**kw}

def compact(x, depth=0):
    if not isinstance(x,dict): return x
    if depth>4: return {'kind':'widened'}
    y={}
    for k,v in x.items():
        if k in ('left','right','base','index_value'): y[k]=compact(v,depth+1)
        elif k=='alternatives': y[k]=[compact(z,depth+1) for z in v[:4]]
        else:y[k]=v
    return y

def join(vals):
    flat=[]
    for x in vals:
        if not x: continue
        if x.get('kind')=='phi': flat += x.get('alternatives',[])
        else: flat.append(x)
    uniq={K(x):x for x in flat}
    if not uniq:return V('unknown')
    if len(uniq)==1:return next(iter(uniq.values()))
    return V('phi',alternatives=list(uniq.values())[:4])

def fp(st): return K(st)[:24000]

def recover(path):
    blob=path.read_bytes(); req(hashlib.sha256(blob).hexdigest()==SHA,'ELF SHA mismatch')
    with path.open('rb') as f:
        e=ELFFile(f); req(e.elfclass==32 and e.little_endian,'ARM32 LE required')
        seg=[(s['p_vaddr'],s.data()) for s in e.iter_segments() if str(s['p_type']) in ('PT_LOAD','1')]
        md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.detail=True
        def read(a,n=4):
            for b,d in seg:
                if b<=a and a+n<=b+len(d):return d[a-b:a-b+n]
            raise ValueError(hex(a))
        def word(a):return struct.unpack('<I',read(a))[0]
        ins={}
        for a in range(START,END,4):
            z=list(md.disasm(read(a),a));req(len(z)==1,'undecodable '+hex(a));ins[a]=z[0]

        def target(i):
            return branch_target(i)

        def pc_value(address):
            return arm_pc(address)

        def canonical(i, n):
            if len(i.operands)<=n or i.operands[n].type != 1:
                return None
            return canonical_reg(i.reg_name(i.operands[n].reg))

        def mem_semantics(i):
            return decode_memory(i)

        def bfc_semantics(i):
            return decode_bfc(i)

        def apply_bfc(value, spec):
            return transfer_bfc(value, spec)

        def data_semantics(i):
            d = decode_data_op(i)
            if d is None:
                return None
            return {
                'mnemonic': d.mnemonic,
                'destination': d.destination,
                'left': operand_value(i, 1 if d.destination else 0),
                'right': operand_value(i, 2 if d.destination else 1),
                'shift': ({'kind': d.shift.kind, 'amount': d.shift.amount,
                           'register': d.shift.register,
                           'by_register': d.shift.by_register}
                          if d.shift else None),
                'set_flags': d.set_flags,
            }
        succ=defaultdict(list); reachable=set(); todo=[START]
        while todo:
            a=todo.pop()
            if a in reachable or a not in ins:continue
            reachable.add(a);i=ins[a];n=a+4;t=target(i);m=i.mnemonic
            if m=='b' and t is not None: succ[a].append(t);todo.append(t)
            elif m.startswith('b') and m not in ('bic','bfc') and t is not None:
                succ[a]+=[t,n];todo += [t,n]
            elif (m=='bx' and 'lr' in i.op_str) or (m=='pop' and 'pc' in i.op_str):pass
            else:succ[a].append(n);todo.append(n)

        def reg(i,n):
            if len(i.operands)<=n or i.operands[n].type!=1:return None
            return i.reg_name(i.operands[n].reg)
        def operand(st,i,n):
            if len(i.operands)<=n:return V('unknown')
            o=i.operands[n]
            if o.type==1:
                r=canonical_reg(i.reg_name(o.reg))
                return st['r'].get(r,V('unknown'))
            if o.type==2:return V('const',value=o.imm&0xffffffff)
            if o.type==3:
                addr=decode_address(i,n)
                if addr is None:return V('unknown')
                base,index=addr.base,addr.index
                if base=='fp' and not index:return st['s'].get(addr.offset,V('stack-unknown',offset=addr.offset))
                return V('load',base_reg=base,offset=addr.offset,index=index,
                         base_value=st['r'].get(base,V('unknown')),
                         index_value=st['r'].get(index,V('unknown')) if index else None,
                         writeback=addr.writeback,pre_index=addr.pre_index)
            return V('unknown')
        def mem(i,n=1):
            if len(i.operands)<=n or i.operands[n].type!=3:return None
            x=i.operands[n].mem
            return i.reg_name(x.base),x.disp,i.reg_name(x.index) if x.index else None
        def merge(a,b):
            if a is None:return {'r':dict(b['r']),'s':dict(b['s'])}
            return {'r':{x:join([a['r'].get(x),b['r'].get(x)]) for x in REGS},
                    's':{x:join([a['s'].get(x),b['s'].get(x)]) for x in set(a['s'])|set(b['s'])}}

        init={'r':{x:V('input',register=x) for x in REGS},'s':{}}
        states={START:init};q=deque([START]);calls={};data_ops={};iterations=0
        while q and iterations<20000:
            iterations+=1;a=q.popleft();st={'r':dict(states[a]['r']),'s':dict(states[a]['s'])};i=ins[a];m=i.mnemonic;d=reg(i,0)
            if m in ('bl','blx'):
                t=target(i);calls.setdefault(a,{'address':hex(a),'target':hex(t) if t is not None else 'indirect-register','operand':i.op_str,'receiver':compact(st['r'].get('r0',V('unknown'))),'selector':compact(st['r'].get('r1',V('unknown'))),'args':{r:compact(st['r'].get(r,V('unknown'))) for r in ('r2','r3')},'stack_args':{str(k):compact(v) for k,v in st['s'].items() if k>=0}})
            ds = data_semantics(i)
            if ds is not None:
                data_ops.setdefault(a, ds)
            if m in ('mov','movw','movt') and d:
                st['r'][canonical_reg(d)]=operand(st,i,1)
            elif m in ('add','sub') and d:
                st['r'][canonical_reg(d)]=V('arith',op=m,left=operand(st,i,1),right=operand(st,i,2))
            elif m in ('ldr','ldrb','ldrsb','ldrh','ldrsh','ldrd') and d:
                mm=mem_semantics(i)
                addr=mm.address if mm else None
                st['r'][canonical_reg(d)]=st['s'].get(addr.offset,V('stack-unknown',offset=addr.offset)) if addr and addr.base=='fp' and not addr.index else operand(st,i,1)
            elif m == 'bfc' and d:
                spec=bfc_semantics(i)
                old=st['r'].get(canonical_reg(d))
                value=old.get('value') if old and old.get('kind')=='const' else None
                result=apply_bfc(value,spec) if spec else None
                st['r'][canonical_reg(d)]=V('const',value=result) if result is not None else V('bfc',spec=spec or {})
            elif m in ('str','strb','strh'):
                mm=mem_semantics(i)
                addr=mm.address if mm else None
                if addr and addr.base=='fp' and not addr.index:st['s'][addr.offset]=operand(st,i,0)
            if m in ('bl','blx'):
                for r in CALLER:st['r'][r]=V('call-clobbered',call=hex(a),register=r)
                st['r']['r0']=V('call-return',call=hex(a))
            for b in succ.get(a,[]):
                if b not in ins:continue
                z=merge(states.get(b),st)
                if fp(z)!=fp(states.get(b,{})):states[b]=z;q.append(b)
        result={'schema':2,'elf_sha256':SHA,'region':{'start':hex(START),'end':hex(END),'reachable_instructions':len(reachable),'linear_words':(END-START)//4},'cfg':{'edges':{hex(a):[hex(b) for b in bs] for a,bs in sorted(succ.items())}},'callsite_dataflow':list(calls.values()),'data_processing':{hex(a):v for a,v in sorted(data_ops.items())},'analysis':{'iterations':iterations,'soundness_boundary':'bounded candidate provenance; dynamic dispatch is not guessed'}}
        return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--elf',type=Path,required=True);p.add_argument('--check',action='store_true');a=p.parse_args();d=recover(a.elf);out=ROOT/'reconstruction/reverse-v3/native/inventory_pickup_dataflow.json';s=json.dumps(d,indent=2)+'\n'
    if a.check:req(out.read_text()==s,'stale output')
    else:out.write_text(s)
    print(json.dumps({'reachable_instructions':d['region']['reachable_instructions'],'linear_words':d['region']['linear_words'],'callsites':len(d['callsite_dataflow']),'iterations':d['analysis']['iterations']}))
if __name__=='__main__':main()
