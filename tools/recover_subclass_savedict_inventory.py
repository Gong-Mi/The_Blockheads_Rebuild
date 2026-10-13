#!/usr/bin/env python3
"""Hash-gated inventory of DynamicObject subclass -[getSaveDict] overrides.

Family A (15 classes): the 27-word `[super getSaveDict]` forwarding template
(first pinned on ClownFish). Per class: exact template body equality, then the
four pool cells resolve to the objc_msgSendSuper2 GOT import, the getSaveDict
selref cstring, the class's own struct (name-walk from +0x24/+0x10), and the
PIC base anchor.

Family B (2 classes): tail-dispatch to a sibling variant instead of super:
  Blockhead -> objc_msgSend(self, getSaveDictIncludingWorkbenchOrInterationObject:, NO)
  Chest     -> objc_msgSend(self, getSaveDictIncludingInventory:, chestType == 4)
All gate addresses/words come from the instruction stream of the pinned ELF.

Static level-A evidence only; the 46 larger overrides that reassemble their
own key sets are not covered by this batch.
"""
import argparse, hashlib, io, json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4
MSGSEND = 0x0105B7A0
MSGSEND_SUPER2 = 0x0105B79C
TEMPLATE_WORDS = 27  # code words before the 4-cell literal pool

# class -> (imp, boundary=next method IMP)
FORWARDERS = {
 'ClownFish':   (0x0078E76C, 0x0078E7E8),
 'Shark':       (0x007C8C34, 0x007C8CB0),
 'CoffeeTree':  (0x007DEC20, 0x007DECA0),
 'LimeTree':    (0x00809D34, 0x00809DB0),
 'PassengerCar':(0x0081C034, 0x0081C0B0),
 'Scorpion':    (0x00894080, 0x008940FC),
 'FreightCar':  (0x00A40940, 0x00A409BC),
 'HandCar':     (0x00A4F8D0, 0x00A4F94C),
 'Dodo':        (0x00A6BB04, 0x00A6BB80),
 'OrangeTree':  (0x00A966FC, 0x00A96778),
 'CoconutTree': (0x00A99AB4, 0x00A99B30),
 'Mirror':      (0x00A9FB0C, 0x00A9FB88),
 'CherryTree':  (0x00D0E024, 0x00D0E0A0),
 'MangoTree':   (0x00D4B5EC, 0x00D4B668),
 'MapleTree':   (0x00DB60AC, 0x00DB6128),
}
# template anchors inside the 31-word method: ldr/add for the base at +0xC/+0x10
BASE_LDR_SITE = 0x0C
BASE_ADD_SITE = 0x10

TAIL_DISPATCH = {
 'Blockhead': {
   'imp': 0x00B9E9D4, 'boundary': 0x00B9EA28,
   'send_site': 0x00B9EA10, 'send_word': '3cff2fe1',  # blx ip
   'got_cell': 0x00B9EA1C, 'selref_cell': 0x00B9EA20, 'base_cell': 0x00B9EA24,
   'base_add_site': 0x00B9E9E4,
   'selector': 'getSaveDictIncludingWorkbenchOrInterationObject:',
   'arg_words': {0x00B9E9E8: '003000e3', 0x00B9EA0C: '7320afe6'},
   'route': '[self getSaveDictIncludingWorkbenchOrInterationObject:NO]',
 },
 'Chest': {
   'imp': 0x00CB95B0, 'boundary': 0x00CB9638,
   'send_site': 0x00CB961C, 'send_word': '33ff2fe1',  # blx r3
   'got_cell': 0x00CB9628, 'selref_cell': 0x00CB962C,
   'ivar_cell': 0x00CB9630, 'base_cell': 0x00CB9634,
   'base_add_site': 0x00CB95C0,
   'selector': 'getSaveDictIncludingInventory:',
   'ivar_symbol': 'OBJC_IVAR_$_Chest.chestType', 'ivar_offset': 108,
   'arg_words': {0x00CB95F8: '040051e3',   # cmp r1,#4
                 0x00CB95FC: '001000e3',   # movw r1,0
                 0x00CB9600: '0110a013',   # movne r1,1
                 0x00CB9604: '011001e2',   # and r1,r1,#1
                 0x00CB9618: '7220afe6'},  # sxtb r2,r2
   'route': '[self getSaveDictIncludingInventory:(chestType == 4)]',
 },
}


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def recover(path):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original ELF SHA mismatch')
    m = ELFMemory(path)

    def word(a):
        v = m.word(a)
        if v is None:
            raise ValueError(f'missing word {a:#x}')
        return int(v)

    def cstr(a):
        off = m.offset(a, 1)
        if off is None:
            raise ValueError(f'no bytes {a:#x}')
        end = m.data.find(b'\0', off, off + 256)
        if end < 0:
            raise ValueError(f'unterminated {a:#x}')
        return m.data[off:end].decode('utf-8')

    elf = ELFFile(io.BytesIO(raw))
    dynsym = elf.get_section_by_name('.dynsym')
    symbols = {s['st_value']: s.name for s in dynsym.iter_symbols() if s['st_value']}

    def class_name(class_addr):
        # Apportable/ARM32 class_t: data pointer at +0x10, class_ro name at +0x10.
        ro = word(class_addr + 0x10)
        return cstr(word(ro + 0x10))

    # method-map agreement
    tsv = (NATIVE / 'libApplication_objc_methods.tsv').read_text().splitlines()[1:]
    by_imp = {}
    for l in (x.split('\t') for x in tsv):
        by_imp[int(l[0], 16)] = l

    template = [word(FORWARDERS['ClownFish'][0] + 4 * k) for k in range(TEMPLATE_WORDS)]

    overrides = []
    for cls, (imp, boundary) in sorted(FORWARDERS.items()):
        row = by_imp.get(imp)
        if row is None or row[1] != cls or row[3] != 'getSaveDict':
            raise ValueError(f'{cls}: method map drift at {imp:#x}')
        body = [word(imp + 4 * k) for k in range(TEMPLATE_WORDS)]
        if body != template:
            raise ValueError(f'{cls}: body drift from forwarding template')
        pool = imp + 4 * TEMPLATE_WORDS
        if pool + 16 > boundary:
            raise ValueError(f'{cls}: pool past boundary')
        w_got, w_sel, w_cls, w_base = (word(pool + 4 * i) for i in range(4))
        if (BASE + signed(w_got)) & 0xFFFFFFFF != MSGSEND_SUPER2:
            raise ValueError(f'{cls}: super2 GOT cell drift')
        if m.imports.get(MSGSEND_SUPER2) != 'objc_msgSendSuper2':
            raise ValueError(f'{cls}: GOT import drift')
        sel_slot = (BASE + signed(w_sel)) & 0xFFFFFFFF
        if cstr(word(sel_slot)) != 'getSaveDict':
            raise ValueError(f'{cls}: selref cstring drift')
        cls_slot = (BASE + signed(w_cls)) & 0xFFFFFFFF
        cls_addr = word(cls_slot)
        if class_name(cls_addr) != cls:
            raise ValueError(f'{cls}: class name walk drift')
        if (imp + BASE_ADD_SITE + 8 + signed(w_base)) & 0xFFFFFFFF != BASE:
            raise ValueError(f'{cls}: PIC base anchor drift')
        overrides.append({
            'class': cls, 'imp': f'0x{imp:08x}', 'boundary': f'0x{boundary:08x}',
            'code_words': TEMPLATE_WORDS, 'pool_cell': f'0x{pool:08x}',
            'style': 'super_forward', 'dispatch': 'objc_msgSendSuper2',
            'selector': 'getSaveDict', 'route': '[super getSaveDict] passthrough',
            'class_struct': f'0x{cls_addr:08x}',
        })

    for cls, t in sorted(TAIL_DISPATCH.items()):
        row = by_imp.get(t['imp'])
        if row is None or row[1] != cls or row[3] != 'getSaveDict':
            raise ValueError(f'{cls}: tail method map drift')
        if word(t['send_site']).to_bytes(4, 'little').hex() != t['send_word']:
            raise ValueError(f'{cls}: send site drift')
        if (BASE + signed(word(t['got_cell']))) & 0xFFFFFFFF != MSGSEND:
            raise ValueError(f'{cls}: objc_msgSend GOT drift')
        sel_slot = (BASE + signed(word(t['selref_cell']))) & 0xFFFFFFFF
        if cstr(word(sel_slot)) != t['selector']:
            raise ValueError(f'{cls}: selector drift')
        if (t['base_add_site'] + 8 + signed(word(t['base_cell']))) & 0xFFFFFFFF != BASE:
            raise ValueError(f'{cls}: PIC base anchor drift')
        for a, wh in t['arg_words'].items():
            if word(a).to_bytes(4, 'little').hex() != wh:
                raise ValueError(f'{cls}: arg word drift {a:#x}')
        entry = {
            'class': cls, 'imp': f"0x{t['imp']:08x}",
            'boundary': f"0x{t['boundary']:08x}",
            'code_words': (t['boundary'] - t['imp'] - 16) // 4,
            'style': 'tail_dispatch', 'dispatch': 'objc_msgSend',
            'selector': t['selector'], 'route': t['route'],
        }
        if 'ivar_symbol' in t:
            ivar_slot = (BASE + signed(word(t['ivar_cell']))) & 0xFFFFFFFF
            off_addr = word(ivar_slot)
            if symbols.get(off_addr) != t['ivar_symbol'] or word(off_addr) != t['ivar_offset']:
                raise ValueError(f'{cls}: ivar offset drift')
            entry['argument_ivar'] = {'symbol': t['ivar_symbol'],
                                      'offset': t['ivar_offset'],
                                      'comparison': '== 4'}
        overrides.append(entry)

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'DynamicObject subclass -[getSaveDict] override inventory (batch 1)',
        'forwarder_template_words': TEMPLATE_WORDS,
        'forwarder_count': len(FORWARDERS), 'tail_dispatch_count': len(TAIL_DISPATCH),
        'overrides': overrides,
        'claim': ('15 exact-template [super getSaveDict] forwarders (body, GOT import, '
                  'selref cstring, class name walk, PIC anchor all pinned) plus Blockhead '
                  'and Chest tail-dispatch variants with argument producers; 46 remaining '
                  'subclass overrides reassemble parent dictionaries with their own keys '
                  'and stay unpaired in this batch; static evidence, not save-roundtrip '
                  'behavior'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path,
                   default=NATIVE / 'subclass_savedict_inventory.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_inventory.json')
    else:
        a.output.write_text(text)
    print('subclass-savedict batch1 forwarders=%d tail=%d'
          % (len(FORWARDERS), len(TAIL_DISPATCH)))


if __name__ == '__main__':
    main()
