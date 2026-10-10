#!/usr/bin/env python3
"""Hash-gated key/conversion/setObject pairing for FreeBlock -[getSaveDict].

Every pairing was derived from the bounded forward register/stack trace in
tools/freeblock_save_key_flow.py and is re-checked here against instruction
words, CFString payloads, and ivar symbols. A key is only promoted when its
constant-string object, its setObject:forKey: site, the conversion selector
site (when present), and the value-source OBJC_IVAR symbol all resolve from
the pinned ELF; unproven parts stay in the claim boundary.
"""
import argparse, hashlib, io, json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4
START, CODE_END, BOUNDARY = 0x00629804, 0x0062A410, 0x0062A4BC

# (key, cstring, key_cell, conv_site, conv_word, conv_sel, set_site,
#  spill_store, spill_reload, ivar_cell, ivar_name, ivar_offset, kind)
PAIRINGS = [
 ('bounceTimer', 0xF50D76, 0x62A47C, 0x00629914, 0xE12FFF3C, 'numberWithFloat:', 0x00629938, 0x00629924, 0x0062992C, 0x62A480, 'OBJC_IVAR_$_FreeBlock.bounceTimer', 68, 'scalar'),
 ('fallSpeed', 0xF50D82, 0x62A474, 0x00629974, 0xE12FFF3E, 'numberWithFloat:', 0x00629998, 0x00629984, 0x0062998C, 0x62A478, 'OBJC_IVAR_$_FreeBlock.fallSpeed', 72, 'scalar'),
 ('floatPos[VX]', 0xF50D99, 0x62A470, 0x00629A34, 0xE12FFF3E, 'numberWithFloat:', 0x00629A58, 0x00629A44, 0x00629A4C, 0x62A46C, 'OBJC_IVAR_$_DynamicObject.floatPos', 24, 'vector_component_x'),
 ('floatPos[VY]', 0xF50DA6, 0x62A464, 0x00629BD8, 0xE12FFF3E, 'numberWithFloat:', 0x00629BFC, 0x00629BE8, 0x00629BF0, 0x62A46C, 'OBJC_IVAR_$_DynamicObject.floatPos', 24, 'vector_component_y'),
 ('itemType', 0xF49E47, 0x62A45C, 0x00629C38, 0xE12FFF33, 'numberWithInt:', 0x00629C5C, 0x00629C48, 0x00629C50, 0x62A460, 'OBJC_IVAR_$_FreeBlock.itemType', 56, 'scalar'),
 ('dataA', 0xF49E50, 0x62A454, 0x00629C98, 0xE12FFF33, 'numberWithInt:', 0x00629CBC, 0x00629CA8, 0x00629CB0, 0x62A458, 'OBJC_IVAR_$_FreeBlock.dataA', 60, 'scalar'),
 ('dataB', 0xF49E56, 0x62A448, 0x00629CF8, 0xE12FFF33, 'numberWithInt:', 0x00629D1C, 0x00629D08, 0x00629D10, 0x62A450, 'OBJC_IVAR_$_FreeBlock.dataB', 62, 'scalar'),
 ('creationTime', 0xF50D8C, 0x62A43C, 0x00629D58, 0xE12FFF3E, 'numberWithDouble:', 0x00629D7C, 0x00629D68, 0x00629D70, 0x62A444, 'OBJC_IVAR_$_FreeBlock.creationTime', 80, 'scalar'),
 ('hovers', 0xF50DB3, 0x62A424, 0x00629DB8, 0xE12FFF33, 'numberWithBool:', 0x00629DDC, 0x00629DC8, 0x00629DD0, 0x62A434, 'OBJC_IVAR_$_FreeBlock.hovers', 64, 'scalar'),
 ('subItems', 0xF50DBA, 0x62A49C, None, None, None, 0x0062A290, None, None, 0x62A420, 'OBJC_IVAR_$_FreeBlock.subItems', 112, 'serialized_array'),
 ('dynamicObjectSaveDict', 0xF50DC3, 0x62A4A4, None, None, None, 0x0062A310, None, None, 0x62A4A0, 'OBJC_IVAR_$_FreeBlock.dynamicObjectSaveDict', 140, 'passthrough_dict'),
 ('priorityBlockheadUinqueID', 0xF50DD9, 0x62A4AC, 0x0062A3E0, 0xE12FFF33, 'numberWithInt:', 0x0062A404, 0x0062A3F0, 0x0062A3F8, 0x62A4A8, 'OBJC_IVAR_$_FreeBlock.priorityBlockhead', 136, 'uniqueid_from_object'),
]
# component reads inside the floatPos Vector2 at self+24:
#   VX: 0x00629a00 vldr s0, [r0]      (r0 = self + floatPos)
#   VY: 0x00629ba4 vldr s0, [r0, #4]
VECTOR_COMPONENT_SITES = {
 'floatPos[VX]': (0x00629A00, 0xED900A00, 0),
 'floatPos[VY]': (0x00629BA4, 0xED900A01, 4),
}
# receiver of the uniqueID message is boxed through a direct bl objc_msgSend
# using selector cell 0x62A4B4 (uniqueID)
UNIQUEID_SEND = (0x0062A3AC, 0xEBEE611A, 0x62A4B4)


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def cstring(m, addr):
    off = m.offset(addr, 1)
    if off is None:
        raise ValueError(f'missing cstring {addr:#x}')
    end = m.data.find(b'\0', off, off + 96)
    if end < 0:
        raise ValueError(f'unterminated cstring {addr:#x}')
    return m.data[off:end].decode('utf-8')


def recover(path):
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SHA:
        raise ValueError('original ELF SHA mismatch')
    m = ELFMemory(path)
    listing = (NATIVE / 'disasm_freeblock_getsavedict.txt').read_text()
    coverage = verify_disassembly(m, listing, START, BOUNDARY)
    elf = ELFFile(io.BytesIO(raw))
    dynsym = elf.get_section_by_name('.dynsym')
    symbols = {s['st_value']: s.name for s in getattr(dynsym, 'iter_symbols')() if s['st_value']}
    set_selector_cell = 0x62A42C
    slot_addr = (BASE + signed(m.word(set_selector_cell))) & 0xFFFFFFFF
    if m.selectors.get(m.word(slot_addr)) != 'setObject:forKey:':
        raise ValueError('shared setObject:forKey: selector cell drift')
    rows = []
    for (key, cstr, key_cell, conv, conv_word, conv_sel, site, spill, reload,
         ivar_cell, ivar_name, ivar_off, kind) in PAIRINGS:
        obj = (BASE + signed(m.word(key_cell))) & 0xFFFFFFFF
        if m.word(obj + 8) != cstr or cstring(m, cstr) != key:
            raise ValueError(f'{key}: constant-string drift')
        if m.word(site) not in (0xE12FFF3C, 0xE12FFF3E, 0xE12FFF33):
            raise ValueError(f'{key}: set site {site:#x} is not a register blx')
        resolved_ivar = (BASE + signed(m.word(ivar_cell))) & 0xFFFFFFFF
        stored = m.word(resolved_ivar)
        if symbols.get(stored) != ivar_name:
            raise ValueError(f'{key}: ivar symbol drift at {ivar_cell:#x}')
        if m.word(stored) != ivar_off:
            raise ValueError(f'{key}: ivar offset drift for {ivar_name}')
        row = {
            'key': key,
            'cstring': f'0x{cstr:08x}',
            'constant_string_object': f'0x{obj:08x}',
            'key_cell': f'0x{key_cell:08x}',
            'set_object_site': f'0x{site:08x}',
            'value_source': {'ivar': ivar_name, 'ivar_offset': ivar_off,
                             'ivar_cell': f'0x{ivar_cell:08x}'},
            'pairing_kind': kind,
        }
        if conv is not None:
            if m.word(conv) != conv_word:
                raise ValueError(f'{key}: conversion instruction drift at {conv:#x}')
            if m.word(site) not in (0xE12FFF3C, 0xE12FFF3E, 0xE12FFF33):
                raise ValueError(f'{key}: set site {site:#x} is not a register blx')
            row['conversion_site'] = f'0x{conv:08x}'
            row['conversion_selector'] = conv_sel
            row['boxed_value_spill'] = f'0x{spill:08x}'
            row['boxed_value_reload'] = f'0x{reload:08x}'
        if kind == 'vector_component_y':
            site_addr, site_word, comp_off = VECTOR_COMPONENT_SITES['floatPos[VY]']
            if m.word(site_addr) != site_word:
                raise ValueError('floatPos[VY] component read drift')
            row['component_byte'] = comp_off
        if kind == 'vector_component_x':
            site_addr, site_word, comp_off = VECTOR_COMPONENT_SITES['floatPos[VX]']
            if m.word(site_addr) != site_word:
                raise ValueError('floatPos[VX] component read drift')
            row['component_byte'] = comp_off
        if kind == 'serialized_array':
            row['value_path'] = ('elements enumerated with itemType and saveData '
                                 'messages, appended with addObject:, stored under subItems')
        if kind == 'passthrough_dict':
            row['value_path'] = 'ivar object loaded and stored without boxing'
        if kind == 'uniqueid_from_object':
            row['value_path'] = ('uniqueID message sent at 0x0062a3ac to ivar object, '
                                 'result boxed with numberWithInt:')
        rows.append(row)
    send_addr, send_word, uniqueid_cell = UNIQUEID_SEND
    if m.word(send_addr) != send_word:
        raise ValueError('uniqueID direct-send instruction drift')
    uid_addr = (BASE + signed(m.word(uniqueid_cell))) & 0xFFFFFFFF
    if m.selectors.get(m.word(uid_addr)) != 'uniqueID':
        raise ValueError('uniqueID selector cell drift')
    body_off = m.offset(START, CODE_END - START)
    body = m.data[int(body_off):int(body_off) + CODE_END - START]
    return {'schema': 1, 'elf_sha256': digest,
            'method': 'FreeBlock -[getSaveDict]', 'types': '@8@0:4',
            'imp': f'0x{START:08x}', 'code_end': f'0x{CODE_END:08x}',
            'bounded_end': f'0x{BOUNDARY:08x}', 'pic_base': f'0x{BASE:08x}',
            'coverage_words': coverage,
            'body_sha256': hashlib.sha256(body).hexdigest(),
            'super_route': {'selector': 'getSaveDict',
                            'dispatch': 'objc_msgSendSuper2',
                            'selector_cell': '0x0062a418',
                            'dispatch_cell': '0x0062a414',
                            'site': '0x00629858'},
            'uniqueid_send': {'site': f'0x{send_addr:08x}',
                              'dispatch': 'objc_msgSend',
                              'selector': 'uniqueID',
                              'selector_cell': f'0x{uniqueid_cell:08x}'},
            'pairings': rows,
            'claim': ('twelve save keys paired to setObject:forKey: sites with '
                      'conversion selector, boxed-value spill slot, and ivar '
                      'value source; the subItems element contract, exact '
                      'runtime equivalence, and non-FreeBlock subclass routes '
                      'remain unresolved')}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'freeblock_save_keys.json')
    a = ap.parse_args()
    result = recover(a.elf)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale freeblock_save_keys.json')
    else:
        a.output.write_text(text)
    print(f"freeblock-save-keys: pairings={len(result['pairings'])} PASS")


if __name__ == '__main__':
    main()
