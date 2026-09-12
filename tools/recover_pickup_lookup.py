#!/usr/bin/env python3
"""Recover the bounded freeblock/tile lookup region of pickup.

This is a hash-pinned ARM32 structural manifest: instruction coverage, CFG
edges, direct imports/helpers and callsite boundaries. It deliberately does
not assign dynamic receivers or invent fast-enumeration selector bindings.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
START, END = 0xc61dd0, 0xc626d8
ROOT = Path(__file__).resolve().parents[1]
DIRECT = {
    0x1c281c: 'objc_msgSend',
    0x1c3f08: '__aeabi_memmove',
    0x627c40: 'itemTypeRequiresOwnershipToRemove(ItemType)',
}
REGIONS = [
    (0xc61dd0, 0xc621c4, 'fast-enumeration / Tile-pack preparation'),
    (0xc621c8, 0xc623bc, 'freeblock type lookup and ownership gate'),
    (0xc623bc, 0xc62500, 'ItemType ownership/removal dispatch'),
    (0xc62500, 0xc626d8, 'remaining removal predicates and priority gate'),
]


def require(x, msg):
    if not x:
        raise ValueError(msg)


def recover(path):
    blob = path.read_bytes()
    require(hashlib.sha256(blob).hexdigest() == SHA, 'ELF SHA mismatch')
    with path.open('rb') as f:
        elf = ELFFile(f)
        require(elf.elfclass == 32 and elf.little_endian, 'ARM32 LE required')
        segs = [(s['p_vaddr'], s.data()) for s in elf.iter_segments()
                if str(s['p_type']) in ('PT_LOAD', '1')]
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        md.detail = True
        def read(a, n=4):
            for base, data in segs:
                if base <= a and a + n <= base + len(data):
                    return data[a-base:a-base+n]
            raise ValueError('not file-backed ' + hex(a))
        def word(a):
            return struct.unpack('<I', read(a))[0]
        insns = {}
        for a in range(START, END, 4):
            decoded = list(md.disasm(read(a), a))
            require(len(decoded) == 1, 'undecodable word at ' + hex(a))
            insns[a] = decoded[0]
        calls, branches = [], []
        for a, i in insns.items():
            if i.mnemonic in ('bl', 'blx'):
                target = None
                if i.mnemonic == 'bl' and i.operands and i.operands[0].type == 2:
                    target = i.operands[0].imm & 0xffffffff
                item = dict(address=hex(a), opcode=i.mnemonic,
                            operand=i.op_str)
                if target is not None:
                    item['target'] = hex(target)
                    if target in DIRECT:
                        item['symbol'] = DIRECT[target]
                calls.append(item)
            elif i.mnemonic.startswith('b') and i.mnemonic not in ('bic', 'bfc'):
                target = None
                if i.operands and i.operands[0].type == 2:
                    target = i.operands[0].imm & 0xffffffff
                item = dict(address=hex(a), opcode=i.mnemonic,
                            operand=i.op_str)
                if target is not None:
                    item['target'] = hex(target)
                branches.append(item)
        require(len(insns) * 4 == END - START, 'word coverage')
        # Resolve the CFConstantString objects used by the ownership/removal
        # dispatch. Their class-reference relocations are at the PIC-derived
        # slots; the payload pointer is word+8 and the stored length is word+12.
        cfstrings = []
        for slot in (0xfa20a8, 0xfa20b8, 0xfa20c8, 0xfa20d8, 0xfa20e8):
            try:
                payload = word(slot + 8)
                length = word(slot + 12)
                raw = read(payload, length)
                value = raw.decode('utf-8', 'replace')
                cfstrings.append(dict(slot=hex(slot), payload=hex(payload),
                                      length=length, value=value))
            except (TypeError, ValueError, UnicodeDecodeError):
                pass
        selector_refs = []
        for slot, expected in (
            (0xe870f4, 'itemType'), (0xe87168, 'isAdmin'),
            (0xe87084, 'objectForKey:'), (0xe8709c, 'localNetID'),
            (0xe871cc, 'dynamicObjectSaveDict'),
            (0xe870d0, 'isEqualToString:'), (0xe87028, 'isClient'),
            (0xe876b0, 'priorityBlockheadCannotPickup'),
        ):
            try:
                selector_refs.append(dict(slot=hex(slot), selector=expected,
                                          payload=hex(word(slot))))
            except (TypeError, ValueError):
                pass

        return dict(
            schema=1,
            elf_sha256=SHA,
            method='pickupFreeblockIfPossible:inTile:intentional:',
            region=dict(start=hex(START), end=hex(END),
                        sha256=hashlib.sha256(read(START, END-START)).hexdigest(),
                        instruction_count=len(insns)),
            regions=[dict(start=hex(a), end=hex(b), label=label,
                          instruction_count=(b-a)//4)
                     for a,b,label in REGIONS],
            calls=calls,
            branches=branches,
            structural_findings=[
                dict(address='0xc61dd0', finding='two-word collection/state header comparison before enumeration'),
                dict(address='0xc61e10', finding='indirect Objective-C dispatch; receiver/selector/stack-buffer binding unresolved'),
                dict(address='0xc62108', finding='__aeabi_memmove used while constructing enumeration/object storage'),
                dict(address='0xc6214c', finding='bounded loop advances enumeration cursor by two bytes/words; exact object layout pending'),
                dict(address='0xc6225c', finding='direct ItemType ownership helper call'),
                dict(address='0xc623bc', finding='ItemType dispatch: 0x428/0x429/0xa4..0xa8/0xcf branches'),
                dict(address='0xc62500', finding='secondary removal predicates and priority/self comparison'),
            ],
            cfstrings=cfstrings,
            selector_refs=selector_refs,
            dynamic_bindings_pending=[
                'fast-enumeration receiver and selector at 0xc61e10',
                'per-entry remove*AtPos: selector and receiver calls',
                'Tile coordinate struct field layout used by stack copies',
            ],
            static_only=True,
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--elf', type=Path, required=True)
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()
    data = recover(args.elf)
    out = ROOT / 'reconstruction/reverse-v3/native/inventory_pickup_lookup.json'
    payload = json.dumps(data, indent=2) + '\n'
    if args.check:
        require(out.read_text() == payload, 'stale ' + str(out))
    else:
        out.write_text(payload)
    print(json.dumps({
        'instructions': data['region']['instruction_count'],
        'calls': len(data['calls']),
        'branches': len(data['branches']),
        'direct_symbols': sorted({x['symbol'] for x in data['calls'] if 'symbol' in x}),
        'dynamic_bindings_pending': len(data['dynamic_bindings_pending']),
        'cfstrings': data['cfstrings'],
        'selector_refs': data['selector_refs'],
    }))


if __name__ == '__main__':
    main()
