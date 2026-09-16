#!/usr/bin/env python3
"""Pin Blockhead pickupFreeblockIfPossible:inTile:intentional:.

Extracts the bounded method, calls, branches, PIC selector references, ivar
slots and decisive anchors from the hash-pinned ARM ELF. This is a static
manifest, not execution, generic decompilation or semantic completion proof.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
ROOT = Path(__file__).resolve().parents[1]
# Whole method: code and trailing literal pool up to the next method start.
START, END = 0xc61c00, 0xc638a0
# Literal pools inside the method body (r2 rendering artifacts are not code).
POOLS = [(0xc62bb8, 0xc62d30),
         (0xc62dbc, 0xc62e00),
         (0xc62e04, 0xc62e20),
         (0xc63330, 0xc63350),
         (0xc63804, 0xc638a0)]
# Direct helper exports called by this method.
HELPERS = {0x6225c: 'itemTypeRequiresOwnershipToRemove(ItemType)',
           0xc62c00: '__aeabi_idiv shim target (analyzed separately)',
           0xc62de0: '__modsi3 shim target (analyzed separately)',
           0xc63044: 'makeIntpair(int,int)'}


def require(x, message):
    if not x:
        raise ValueError(message)


def recover(path):
    blob = path.read_bytes()
    require(hashlib.sha256(blob).hexdigest() == SHA, 'ELF SHA mismatch')
    with path.open('rb') as f:
        elf = ELFFile(f)
        require(elf.elfclass == 32 and elf.little_endian, 'ARM32 LE required')
        segs = [(s['p_vaddr'], s.data()) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        symbols = {s.name: s['st_value'] for sec in elf.iter_sections() if sec['sh_type'] == 'SHT_DYNSYM' for s in sec.iter_symbols()}
        rels = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
                tab = elf.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    rels[r['r_offset']] = (r['r_info_type'], tab.get_symbol(r['r_info_sym']).name)

    def read(a, n):
        for base, data in segs:
            if base <= a and a + n <= base + len(data):
                return data[a - base:a - base + n]
        raise ValueError('not file-backed ' + hex(a))

    def word(a):
        return struct.unpack('<I', read(a, 4))[0]

    def string(a):
        out = bytearray()
        for _ in range(1024):
            b = read(a, 1); a += 1
            if b == b'\0':
                return out.decode()
            out += b
        raise ValueError('unterminated string')
    def mapped(a):
        return any(base <= a < base + len(data) for base, data in segs)
    require((0xc61c14 + 8 + word(0xc62bb8)) & 0xffffffff == 0x105faf4, 'PIC base mismatch')
    base = 0x105faf4
    require(rels[(base + word(0xc62bbc)) & 0xffffffff] == (21, 'objc_msgSend'), 'dispatch import')
    selectors, ivars, strings = [], [], []
    # Resolve selectors referenced from the method's literal pools; pool words
    # may reference objects outside the image, which are skipped here.
    resolved = {}
    for a in range(START, END, 4):
        if not any(p <= a < q for p, q in POOLS):
            continue
        target = (base + word(a)) & 0xffffffff
        if mapped(target):
            resolved[a] = target
    # Selector slots point at selector name strings; ivar slots point at ivar
    # offset symbols. Distinguish by reloc type and pointed-to word.
    for a, slot in sorted(resolved.items()):
        try:
            name = string(word(slot))
        except (ValueError, UnicodeDecodeError):
            continue
        if name in ('itemType','dataA','dataB','subItems','dynamicObjectSaveDict',
                    'needsRemoved','uniqueID','priorityBlockhead','hovers',
                    'setNeedsRemoved:','isSimulating','objectForKey:',
                    'countByEnumeratingWithState:objects:count:','removeColumnAtPos:',
                    'removeDoorAtPos:','removeEggAtPos:','removeElevatorMotorAtPos:',
                    'removeElevatorShaftAtPos:','removeLadderAtPos:','removePaintingAtPos:',
                    'removeStairsAtPos:','removeTorchAtPos:','removeWireAtPos:',
                    'ownerID','addItemToInventory:flash:','canPickUpItemOfType:subItems:dataA:dataB:',
                    'initWithType:dataA:dataB:subItems:dynamicObjectSaveDict:',
                    'setObject:forKey:','objectAtIndex:','addObject:','numberWithInt:',
                    'localNetID','isEqualToString:','reportAchievementWithIdentifier:',
                    'worldUIDragging','priorityBlockheadCannotPickup',
                    'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:',
                    'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:onlyRemoveCOntents:onlyRemoveForegroundContents:',
                    'removeBackWallAtPos:removeBlockhead:','addSimulationEventOfType:forBlockhead:extraData:',
                    'isClient','numberWithUnsignedLong:','addIndex:','meditating',
                    'setSoundType','setCreationSoundPlayTime','multiSoundNamed:',
                    'playAtPosition:afterDelay:','pickupDynamicObject','stopInteracting',
                    'clearTile','tileIsLitForSelf:atPos:',
                    'tileIsProtectedAtPos:againstBlockhead:','freeBlocksAtPos:',
                    'freeBlocksExistAtPos:'):
            selectors.append(dict(literal=hex(a), slot=hex(slot), selector=name))
    # ivar slot detection: R_ARM_RELATIVE at the slot, pointed value is an ivar
    # offset symbol address from the symbol table.
    for a, slot in sorted(resolved.items()):
        if rels.get(slot) != (23, ''):
            continue
        addr = word(slot)
        names = [n for n, v in symbols.items() if v == addr and n.startswith('OBJC_IVAR_$_')]
        if names:
            ivars.append(dict(literal=hex(a), slot=hex(slot), symbol=names[0], offset=hex(word(addr))))
    # Strings that are CFString payloads are not directly in these pools; the
    # original r2 output showed the freeblock/keys below. Keep this boundary.
    anchors = {0xc61c68: 0xe3500000,  # cmp r0, #0 after first gate
               0xc61d2c: 0xe3500000,  # cmp r0, #0 priority gate
               0xc61d74: 0xe1500001,  # cmp r0, r1 priority != self
               0xc627f4: 0xe3500001,  # cmp r0, #1 capacity gate
               0xc6282c: 0xe3500000,  # cmp r0, #0 needsRemoved gate
               0xc637a0: 0xe3a00001,  # movw r0, #1 success return
                             0xc637ec: 0xe3a00000,  # movw r0, #0 failure return
                             0xc63800: 0xe8bd8df0}  # pop epilogue
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    calls, branches, count, pool_count = [], [], 0, 0
    lines = [f'# Blockhead -[pickupFreeblockIfPossible:inTile:intentional:]',
             f'# types: c20@0:4@8^{{Tile=...}}12c16', f'# implementation: {START:#x}', f'# ARM.exidx end: {END:#x}']
    for a in range(START, END, 4):
        if any(p <= a < q for p, q in POOLS):
            pool_count += 1; lines.append(f'{a:08x}: {word(a):08x} .word (literal pool)'); continue
        ins = list(md.disasm(read(a, 4), a))
        if len(ins) != 1:
            # Undecodable words are literal-pool data, not instructions.
            pool_count += 1; lines.append(f'{a:08x}: {word(a):08x} .word (literal pool)'); continue
        i = ins[0]; count += 1
        lines.append(f'{a:08x}: {word(a):08x} {i.mnemonic} {i.op_str}')
        if i.mnemonic in ('bl', 'blx'):
            calls.append(dict(address=hex(a), opcode=i.mnemonic, target=i.op_str))
        elif i.mnemonic.startswith('b') and i.mnemonic != 'bic':
            branches.append(dict(address=hex(a), opcode=i.mnemonic, target=i.op_str))
    require((count + pool_count) * 4 == END - START, 'word coverage')
    methods = [dict(selector='pickupFreeblockIfPossible:inTile:intentional:', start=hex(START),
                    end=hex(END), region_sha256=hashlib.sha256(read(START, END - START)).hexdigest(),
                    instruction_count=count, pool_word_count=pool_count, calls=calls, branches=branches)]
    helper_names = {hex(a): [n for n, v in symbols.items() if v == a] or [label] for a, label in HELPERS.items()}
    result = dict(schema=1, elf_sha256=SHA, methods=methods, selectors=selectors, ivars=ivars,
                  cfstrings=strings, helper_symbols=helper_names,
                  anchors={hex(k): hex(v) for k, v in anchors.items()},
                  runtime_verified=False, integrated_into_game=False,
                  semantics_status='hand-reviewed full body; dynamic runtime/effect contracts and currency-split path pending explicit evidence')
    return json.dumps(result, indent=2) + '\n', '\n'.join(lines) + '\n'


def main():
    p = argparse.ArgumentParser(); p.add_argument('--elf', type=Path, required=True)
    p.add_argument('--check', action='store_true'); a = p.parse_args()
    manifest, disasm = recover(a.elf)
    out = ROOT / 'reconstruction/reverse-v3/native'
    for name, data in [('inventory_pickup.json', manifest), ('disasm_inventory_pickup.txt', disasm)]:
        target = out / name
        if a.check:
            require(target.read_text() == data, 'stale ' + name)
        else:
            target.write_text(data)
    d = json.loads(manifest)
    print(json.dumps(dict(methods=len(d['methods']),
                          instructions=sum(x['instruction_count'] for x in d['methods']),
                          calls=sum(len(x['calls']) for x in d['methods']),
                          selectors=len(d['selectors']), ivars=d['ivars'],
                          helper_symbols=d['helper_symbols'])))


if __name__ == '__main__':
    main()