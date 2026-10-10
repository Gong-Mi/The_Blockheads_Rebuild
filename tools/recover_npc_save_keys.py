#!/usr/bin/env python3
"""Hash-gated key/conversion/setObject pairing for NPC -[getSaveDict].

Derived from the bounded forward register/stack trace (tools/freeblock_save_key_flow.py
run over 0x00645aac..0x0064667c) and re-checked here against instruction words,
CFString payloads, selector cells, and ivar symbols from the pinned ELF.
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
START, CODE_END, BOUNDARY = 0x00645AAC, 0x0064667C, 0x00646738

# (key, cstring, key_cell, conv_site, conv_word, conv_sel, conv_sel_cell,
#  set_site, spill_store, spill_reload, ivar_cell, ivar_name, ivar_off, kind)
BLX_IP, BLX_LR, BLX_R3 = 0xE12FFF3C, 0xE12FFF3E, 0xE12FFF33
PAIRINGS = [
 ('damage',                      0xF5102F, 0x6466F4, 0x00645D2C, BLX_IP, 'numberWithInt:',    0x6466D4, 0x00645D50, 0x00645D3C, 0x00645D44, 0x6466F8, 'OBJC_IVAR_$_NPC.damage', 54, 'scalar'),
 ('breed',                       0xF5109A, 0x6466EC, 0x00645D8C, BLX_R3, 'numberWithInt:', 0x6466D4, 0x00645DB0, 0x00645D9C, 0x00645DA4, 0x6466F0, 'OBJC_IVAR_$_NPC.breed', 96, 'scalar'),
 ('fullness',                    0xF5101D, 0x6466E4, 0x00645DEC, BLX_LR, 'numberWithFloat:',  0x6466B0, 0x00645E10, 0x00645DFC, 0x00645E04, 0x6466E8, 'OBJC_IVAR_$_NPC.fullness', 68, 'scalar'),
 ('layTimer',                    0xF51026, 0x6466DC, 0x00645E4C, BLX_LR, 'numberWithFloat:',  0x6466B0, 0x00645E70, 0x00645E5C, 0x00645E64, 0x6466E0, 'OBJC_IVAR_$_NPC.layTimer', 80, 'scalar'),
 ('mateBreed',                   0xF51090, 0x6466D0, 0x00645EAC, BLX_R3, 'numberWithInt:',    0x6466D4, 0x00645ED0, 0x00645EBC, 0x00645EC4, 0x6466D8, 'OBJC_IVAR_$_NPC.mateBreed', 98, 'scalar'),
 ('tameCooldownTimer',           0xF51047, 0x6466C8, 0x00645F0C, BLX_LR, 'numberWithFloat:',  0x6466B0, 0x00645F30, 0x00645F1C, 0x00645F24, 0x6466CC, 'OBJC_IVAR_$_NPC.tameCooldownTimer', 72, 'scalar'),
 ('layCooldownTimer',            0xF51036, 0x6466C0, 0x00645F6C, BLX_LR, 'numberWithFloat:',  0x6466B0, 0x00645F90, 0x00645F7C, 0x00645F84, 0x6466C4, 'OBJC_IVAR_$_NPC.layCooldownTimer', 84, 'scalar'),
 ('mateCooldownTimer',           0xF51059, 0x6466B8, 0x00645FCC, BLX_LR, 'numberWithFloat:',  0x6466B0, 0x00645FF0, 0x00645FDC, 0x00645FE4, 0x6466BC, 'OBJC_IVAR_$_NPC.mateCooldownTimer', 76, 'scalar'),
 ('age',                         0xF49FAA, 0x6466AC, 0x0064602C, BLX_LR, 'numberWithFloat:',  0x6466B0, 0x00646050, 0x0064603C, 0x00646044, 0x6466B4, 'OBJC_IVAR_$_NPC.age', 88, 'scalar'),
 ('hasBred',                     0xF5106B, 0x6466A4, 0x0064608C, BLX_R3, 'numberWithBool:',   0x646698, 0x006460B0, 0x0064609C, 0x006460A4, 0x6466A8, 'OBJC_IVAR_$_NPC.hasBred', 100, 'scalar'),
 ('hasBeenFedByBlockheadOrChest',0xF51073, 0x64668C, 0x006460EC, BLX_R3, 'numberWithBool:',   0x646698, 0x00646110, 0x006460FC, 0x00646104, 0x64669C, 'OBJC_IVAR_$_NPC.hasBeenFedByBlockheadOrChest', 101, 'scalar'),
 ('name',                        0xF371CC, 0x6466FC, None, None, None, None, 0x00646188, None, None, 0x646688, 'OBJC_IVAR_$_NPC.name', 92, 'direct_object'),
 ('saveTime',                    0xF4A006, 0x646704, 0x00646244, BLX_R3, 'numberWithFloat:',  0x6466B0, 0x00646268, 0x00646254, 0x0064625C, 0x64670C, 'OBJC_IVAR_$_DynamicObject.world', 4, 'world_time'),
 ('tameCountsByClientID',        0xF510AE, 0x646710, None, None, None, None, 0x006462E0, None, None, 0x646700, 'OBJC_IVAR_$_NPC.tameCountsByClientID', 104, 'direct_object'),
 ('tamedClientID',               0xF510A0, 0x646718, None, None, None, None, 0x00646360, None, None, 0x646714, 'OBJC_IVAR_$_NPC.tamedClientID', 108, 'direct_object'),
 ('currentBlockheadIndex',       0xF50839, 0x646730, 0x00646644, BLX_LR, 'numberWithInt:',    0x6466D4, 0x00646668, 0x00646654, 0x0064665C, 0x646728, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8, 'rider_index_loop'),
]
SUPER_ROUTE = {'selector_cell': 0x646680, 'dispatch_cell': 0x64667C, 'site': 0x00645B00}
WORLD_TIME_SEL_CELL = 0x646708
RIDER_IVAR_CELL = 0x64671C
BLOCKHEADS_SEL_CELL = 0x646724
NEEDS_REMOVED_SEL_CELL = 0x64672C


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
    listing = (NATIVE / 'disasm_npc_getsavedict.txt').read_text()
    coverage = verify_disassembly(m, listing, START, BOUNDARY)
    elf = ELFFile(io.BytesIO(raw))
    symbols = {s['st_value']: s.name
               for s in elf.get_section_by_name('.dynsym').iter_symbols() if s['st_value']}

    def sel_at(cell, expected):
        addr = (BASE + signed(m.word(cell))) & 0xFFFFFFFF
        if m.selectors.get(m.word(addr)) != expected:
            raise ValueError(f'selector cell drift {expected}')

    super_addr = (BASE + signed(m.word(SUPER_ROUTE['dispatch_cell']))) & 0xFFFFFFFF
    if m.imports.get(super_addr) != 'objc_msgSendSuper2':
        raise ValueError('super dispatch import drift')
    sel_at(SUPER_ROUTE['selector_cell'], 'getSaveDict')
    if m.word(SUPER_ROUTE['site']) not in (BLX_IP, BLX_LR, BLX_R3):
        raise ValueError('super call site not a register blx')
    sel_at(WORLD_TIME_SEL_CELL, 'worldTime')
    sel_at(BLOCKHEADS_SEL_CELL, 'blockheads')
    sel_at(NEEDS_REMOVED_SEL_CELL, 'needsRemoved')

    rows = []
    for (key, cstr, key_cell, conv, conv_word, conv_sel, conv_sel_cell, site,
         spill, reload, ivar_cell, ivar_name, ivar_off, kind) in PAIRINGS:
        obj = (BASE + signed(m.word(key_cell))) & 0xFFFFFFFF
        if m.word(obj + 8) != cstr or cstring(m, cstr) != key:
            raise ValueError(f'{key}: constant-string drift')
        if m.word(site) not in (BLX_IP, BLX_LR, BLX_R3):
            raise ValueError(f'{key}: set site {site:#x} is not a register blx')
        resolved_ivar = (BASE + signed(m.word(ivar_cell))) & 0xFFFFFFFF
        stored = m.word(resolved_ivar)
        if symbols.get(stored) != ivar_name:
            raise ValueError(f'{key}: ivar symbol drift at {ivar_cell:#x}')
        if m.word(stored) != ivar_off:
            raise ValueError(f'{key}: ivar offset drift for {ivar_name}')
        row = {'key': key,
               'cstring': f'0x{cstr:08x}',
               'constant_string_object': f'0x{obj:08x}',
               'key_cell': f'0x{key_cell:08x}',
               'set_object_site': f'0x{site:08x}',
               'value_source': {'ivar': ivar_name, 'ivar_offset': ivar_off,
                                'ivar_cell': f'0x{ivar_cell:08x}'},
               'pairing_kind': kind}
        if conv is not None:
            if m.word(conv) != conv_word:
                raise ValueError(f'{key}: conversion instruction drift at {conv:#x}')
            sel_at(conv_sel_cell, conv_sel)
            row['conversion_site'] = f'0x{conv:08x}'
            row['conversion_selector'] = conv_sel
            row['boxed_value_spill'] = f'0x{spill:08x}'
            row['boxed_value_reload'] = f'0x{reload:08x}'
        if kind == 'world_time':
            row['value_path'] = ('[self+world] receiver receives worldTime at '
                                 '0x00646220, result boxed with numberWithFloat:')
        if kind == 'rider_index_loop':
            rider_addr = (BASE + signed(m.word(RIDER_IVAR_CELL))) & 0xFFFFFFFF
            if symbols.get(m.word(rider_addr)) != 'OBJC_IVAR_$_NPC.rider':
                raise ValueError('rider ivar symbol drift')
            row['value_path'] = ('enumerate dynamicWorld blockheads, compare '
                                 'needsRemoved, match self in rider list; index '
                                 'boxed with numberWithInt:')
        rows.append(row)
    body_off = m.offset(START, CODE_END - START)
    body = m.data[int(body_off):int(body_off) + CODE_END - START]
    return {'schema': 1, 'elf_sha256': digest,
            'method': 'NPC -[getSaveDict]', 'types': '@8@0:4',
            'imp': f'0x{START:08x}', 'code_end': f'0x{CODE_END:08x}',
            'bounded_end': f'0x{BOUNDARY:08x}', 'pic_base': f'0x{BASE:08x}',
            'coverage_words': coverage,
            'body_sha256': hashlib.sha256(body).hexdigest(),
            'super_route': {'selector': 'getSaveDict',
                            'dispatch': 'objc_msgSendSuper2',
                            'selector_cell': f'0x{SUPER_ROUTE["selector_cell"]:08x}',
                            'dispatch_cell': f'0x{SUPER_ROUTE["dispatch_cell"]:08x}',
                            'site': f'0x{SUPER_ROUTE["site"]:08x}'},
            'pairings': rows,
            'claim': ('sixteen save keys paired to setObject:forKey: sites with '
                      'conversion selector, boxed-value spill slot, and ivar '
                      'value source; the currentBlockheadIndex rider loop '
                      'matches semantics (index of the riding Blockhead, -1 or '
                      'absent when unpaired) remain unproven; subclass routes '
                      'and runtime equivalence unresolved')}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--output', type=Path, default=NATIVE / 'npc_save_keys.json')
    a = ap.parse_args()
    result = recover(a.elf)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale npc_save_keys.json')
    else:
        a.output.write_text(text)
    print(f"npc-save-keys: pairings={len(result['pairings'])} PASS")


if __name__ == '__main__':
    main()
