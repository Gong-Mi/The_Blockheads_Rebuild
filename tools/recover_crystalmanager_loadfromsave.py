#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3e: `-[CrystalManager
loadFromSave]` 0x009f3d44 (506 w, boundary 0x009f452c) — the crystal-count
persistence path (keychain first, file fallback, with a tamper gate).

Shape decoded from the instruction stream:

  A. KEYCHAIN PATH
     [SFHFKeychainUtils
        getPasswordForUsername:@"com.majicjungle.blockheads.crystalcount"
        andServiceName:@"com.majicjungle.blockheads.crystalcount"
        error:&err]                                  (call 0x009f3da4)
     if (password == nil || err != nil) → file path  (0x9f3db8 bne / 0x9f3dc8)
     else:
       crystalCount@8      = [password intValue]                 (0x9f3e6c str)
       amountString@12     = [[NSString stringWithFormat:
                              @"7acfe93afc08%dc65ae2c54ecaf07f",
                              crystalCount] stringFromMD5] retain  (0x9f3ed4)
     → return

  B. FILE PATH
     paths = NSSearchPathForDirectoriesInDomains(14, 1, 1)   (ABI veneer 0x1c3f20)
     p1    = [[paths objectAtIndex:0]
              stringByAppendingPathComponent:
              @"game/4bbf9ea9f3e11dd7afcb0f22ccb635d2"]
     s     = [NSString stringWithContentsOfFile:p1
                encoding:4(NSUTF8StringEncoding) error:nil]
     if (s == nil) → return                                   (0x9f3fc8 beq)
     data  = [NSData dataWithContentsOfFile:<game/%@ path>]     (0x9f42a4)
     data  = [data gzipInflate]                                 (0x9f42bc)
     plist = helper(data)   (local thunk 0x009f4508 → 0x9f602c) (0x9f42c0 bl)
     if (plist == nil || derived == nil) → return               (0x9f42d4/e4)
     if (![derived isEqualToString:[plist objectForKey:@"loadSaveIDB"]])
         → return                                              (0x9f4350 beq)
     crystalCount@8  = [s intValue] >> 2        (0x9f4400 asr r0,r0,#2 → str)
     amountString@12 = [[NSString stringWithFormat:
                         @"7acfe93afc08%dc65ae2c54ecaf07f",
                         crystalCount] stringFromMD5] retain     (0x9f447c)

  The tail helper 0x009f4508 (inside this boundary) is a two-instruction
  forwarder to 0x009f602c carrying r0 unchanged and r1 = 0; its callee is NOT
  decoded in this batch. The `derived` string chain (device name /
  `game/%@` / `%@_%@` / `stringFromMD5` mix) is gated call-site by call-site
  but not symbolically evaluated — stated as a boundary, not a claim.

Facts worth freezing: the on-disk string stores 4× the crystal count
(`>> 2` on load), the keychain path is tried first and wins unless it returns
nil *or* an error object, and a failed `loadSaveIDB` comparison leaves both
ivars untouched (no partial write).
"""
import argparse
import copy
import hashlib
import io
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from trace_objc_dispatch import ELFMemory  # noqa: E402

ROOT = TOOLS.parent
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4
CLASS = 'CrystalManager'
IMP = 0x009F3D44
BOUNDARY = 0x009F452C
VENUE_PATH = 0x001C3F20          # ABI veneer used for NSSearchPathForDirectoriesInDomains
PARSER_THUNK = 0x009F4508        # local forwarder → 0x009f602c
PARSER_CALLEE = 0x009F602C

KEY_CELLS = {
    'com.majicjungle.blockheads.crystalcount': 0x00F96B58,
    '7acfe93afc08%dc65ae2c54ecaf07f': 0x00F96B68,
    'game/4bbf9ea9f3e11dd7afcb0f22ccb635d2': 0x00F96B78,
    '7a7224101400f92fa0fad63308856865': 0x00F96B88,
    '%@_%@': 0x00F96B98,
    'game/%@': 0x00F96BA8,
    'loadSaveIDB': 0x00F96BB8,
}
IVAR_OFFSETS = {'crystalCount': 8, 'amountString': 12}
CLASS_OBJECTS = {                 # resolved through ABS32 classref cells
    'getpassword_class': (0x00E8ADD0, None),   # resolved at run time
    'uiddevice_cell': (0x00E8ADD8, None),
    'nsstring_cell': (0x00E8ADD4, 'OBJC_CLASS_$_NSString'),
    'nsdata_cell': (0x00E8ADDC, 'OBJC_CLASS_$_NSData'),
}
EXPECTED_SELREFS = {
    'getPasswordForUsername:andServiceName:error:', 'retain', 'stringFromMD5',
    'stringWithFormat:', 'intValue', 'stringWithContentsOfFile:encoding:error:',
    'stringByAppendingPathComponent:', 'objectAtIndex:',
    'stringByAppendingFormat:', 'name', 'currentDevice', 'gzipInflate',
    'dataWithContentsOfFile:', 'isEqualToString:', 'objectForKey:',
}
# sites: (label, addr, word) ; BL sites are additionally asserted by target
GATES = [
    ('super2_absent_got_check', 0x009F3D50, 'e59f27ac'),      # PIC base load
    ('error_outparam_lr', 0x009F3D64, 'e24be028'),
    ('keychain_call', 0x009F3DA4, 'e12fff34'),
    ('keychain_password_cmp', 0x009F3DB4, 'e1500001'),
    ('keychain_password_beq_file', 0x009F3DB8, '0a000047'),
    ('keychain_error_cmp', 0x009F3DC4, 'e1510000'),
    ('keychain_error_bne_file', 0x009F3DC8, '1a000043'),
    ('keychain_intvalue_call', 0x009F3E58, 'e12fff32'),
    ('keychain_crystalcount_store', 0x009F3E6C, 'e5810000'),
    ('keychain_stringwithformat_call', 0x009F3EA0, 'e12fff3e'),
    ('keychain_stringfrommd5_call', 0x009F3EB0, 'e12fff32'),
    ('keychain_retain_call', 0x009F3EC0, 'e12fff32'),
    ('keychain_amountstring_store', 0x009F3ED4, 'e5810000'),
    ('keychain_return_branch', 0x009F3ED8, 'ea00016a'),
    ('file_searchdir_const14', 0x009F3EDC, 'e300000e'),
    ('file_searchdir_domain1', 0x009F3EE0, 'e3001001'),
    ('file_searchdir_tilde1', 0x009F3EE4, 'e3002001'),
    ('file_searchpath_call', 0x009F3F00, 'ebdf4006'),
    ('file_encoding_utf8_4', 0x009F3F08, 'e3003004'),
    ('file_objectatindex_call', 0x009F3F74, 'e12fff3a'),
    ('file_appendpath_call', 0x009F3F88, 'e12fff33'),
    ('file_path_store', 0x009F3F98, 'e50b009c'),
    ('file_stringwithcontents_call', 0x009F3FB4, 'e12fff3e'),
    ('file_string_store', 0x009F3FB8, 'e50b0030'),
    ('file_string_nil_cmp', 0x009F3FC4, 'e1500001'),
    ('file_string_nil_beq_end', 0x009F3FC8, '0a00012d'),
    ('file_second_searchpath_call', 0x009F4194, 'ebdf3f61'),
    ('file_datawithcontents_call', 0x009F42A4, 'e12fff33'),
    ('file_gzipinflate_call', 0x009F42BC, 'e12fff32'),
    ('file_parser_thunk_bl', 0x009F42C0, 'eb000090'),
    ('plist_nil_cmp', 0x009F42D0, 'e1500001'),
    ('plist_nil_beq_end', 0x009F42D4, '0a000069'),
    ('derived_nil_cmp', 0x009F42E0, 'e1510000'),
    ('derived_nil_beq_end', 0x009F42E4, '0a000065'),
    ('loadsaveidb_objectforkey_call', 0x009F4330, 'e12fff3c'),
    ('isequal_call', 0x009F4344, 'e12fff33'),
    ('isequal_sxtb', 0x009F4348, 'e6af0070'),
    ('isequal_cmp_zero', 0x009F434C, 'e3500000'),
    ('isequal_fail_beq_end', 0x009F4350, '0a00004a'),
    ('file_movw_r1_2', 0x009F43A4, 'e3001002'),
    ('file_intvalue_call', 0x009F43F4, 'e12fff32'),
    ('file_asr_by_2', 0x009F4400, 'e1a00140'),
    ('file_crystalcount_store', 0x009F4414, 'e5810000'),
    ('file_stringwithformat_call', 0x009F4448, 'e12fff3e'),
    ('file_stringfrommd5_call', 0x009F4458, 'e12fff32'),
    ('file_retain_call', 0x009F4468, 'e12fff32'),
    ('file_amountstring_store', 0x009F447C, 'e5810000'),
    ('parser_thunk_prologue', 0x009F4508, 'e92d4800'),
    ('parser_thunk_callee_bl', 0x009F4520, 'eb0006c1'),
]
FORBIDDEN_KEYS = {'craftableItem', 'saveTime', 'skinOptions', 'name'}


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(word, addr):
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 0x1000000
    return (addr + 8 + (imm << 2)) & 0xFFFFFFFF


class ELF:
    def __init__(self, path):
        self.raw = path.read_bytes()
        if hashlib.sha256(self.raw).hexdigest() != SHA:
            raise ValueError('original ELF SHA mismatch')
        self.m = ELFMemory(path)
        self.elf = ELFFile(io.BytesIO(self.raw))
        self.rel = {}
        for s in self.elf.iter_sections():
            if isinstance(s, RelocationSection):
                syms = self.elf.get_section(s['sh_link'])
                for r in s.iter_relocations():
                    self.rel.setdefault(r['r_offset'], []).append(
                        (r['r_info_type'],
                         syms.get_symbol(r['r_info_sym']).name
                         if r['r_info_sym'] else ''))
        self.ivar_slots, self.classes = {}, {}
        for s in self.elf.get_section_by_name('.dynsym').iter_symbols():
            if not s['st_value']:
                continue
            if s.name.startswith('OBJC_IVAR_$_'):
                self.ivar_slots[s['st_value']] = (s.name, self.rw(s['st_value']))
            elif s.name.startswith('OBJC_CLASS_$_'):
                self.classes[s['st_value']] = s.name
        tsv = (NATIVE / 'libApplication_objc_methods.tsv').read_text().splitlines()[1:]
        self.imps = sorted(int(l.split('\t')[0], 16) for l in tsv)
        self.rows = {int(l.split('\t')[0], 16): l.split('\t') for l in tsv}

    def rw(self, a, n=4):
        off = self.m.offset(a, n)
        return None if off is None else int.from_bytes(self.m.data[off:off + n],
                                                       'little')

    def cstr(self, a):
        off = self.m.offset(a, 1)
        if off is None:
            return None
        e = self.m.data.find(b'\0', off, off + 128)
        return self.m.data[off:e].decode('ascii', 'replace') if e > 0 else None

    def word_eq(self, a, wh):
        return f'{(self.rw(a) or 0):08x}' == wh

    def offset_of(self, vaddr):
        off = self.m.offset(vaddr, 1)
        if off is None:
            raise ValueError(f'unmapped vaddr 0x{vaddr:08x}')
        return off

    def mutate(self, vaddr, new_bytes):
        clone = copy.copy(self)
        clone.m = copy.copy(self.m)
        data = bytearray(self.m.data)
        off = self.offset_of(vaddr)
        data[off:off + len(new_bytes)] = new_bytes
        clone.m.data = bytes(data)
        return clone

    def slot_of_ivar(self, name):
        for a, v in self.ivar_slots.items():
            if v[0] == name:
                return a
        raise ValueError(f'ivar symbol missing: {name}')

    def literal_cells(self, lo, hi):
        keys, selrefs, ivars, classes, got, other = {}, {}, {}, {}, {}, {}
        for a in range(lo, hi, 4):
            w = self.rw(a) or 0
            if w & 0x0FFF0000 != 0x059F0000 or (w >> 12) & 0xF == 15:
                continue
            lit = (a + 8 + (w & 0xFFF)) & 0xFFFFFFFF
            t = (BASE + signed(self.rw(lit) or 0)) & 0xFFFFFFFF
            imp = self.m.imports.get(t)
            if imp:
                got[lit] = (t, imp)
                continue
            rel_t = self.rel.get(t, [])
            owned = [n for ty, n in rel_t
                     if ty == 2 and n.startswith('OBJC_IVAR_$_')]
            if owned:
                ivars[lit] = (t, owned[0], self.rw(t))
                continue
            if any(ty == 21 for ty, _ in rel_t):
                got[lit] = (t, [n for ty, n in rel_t if ty == 21][0])
                continue
            if any(n == '__CFConstantStringClassReference' for _, n in rel_t):
                data = self.rw(t + 8)
                keys[lit] = (t, self.cstr(data) if data else None,
                             self.rw(t + 12))
                continue
            cls_rel = [n for ty, n in rel_t if ty == 2 and n.startswith('OBJC_CLASS_$_')]
            if cls_rel:
                classes[lit] = (t, cls_rel[0])
                continue
            wv = self.rw(t)
            if wv is not None and wv in self.ivar_slots:
                ivars[lit] = (t, self.ivar_slots[wv][0], self.rw(wv))
                continue
            if wv is not None and wv in self.classes:
                classes[lit] = (t, self.classes[wv])
                continue
            if wv is not None and self.m.selectors.get(wv):
                selrefs[lit] = (t, self.m.selectors[wv])
                continue
            other[lit] = (t, wv)
        return {'keys': keys, 'selrefs': selrefs, 'ivars': ivars,
                'classes': classes, 'got': got, 'other': other}


def veneer_import(elf, addr):
    """Resolve the imported symbol a PIC veneer jumps to: either the
    add/add/ldr-pc pattern (b3d) or a plain ldr rX,[pc,#imm] tail."""
    w0 = elf.rw(addr) or 0
    if w0 & 0x0FFF0000 == 0x028F0000:            # add ip, pc, #imm1
        w1 = elf.rw(addr + 4) or 0
        w2 = elf.rw(addr + 8) or 0
        if w1 & 0x0FFF0000 != 0x028C0000 or w2 & 0x0FFF0000 != 0x05BC0000:
            raise ValueError(f'veneer 0x{addr:08x}: unexpected shape')

        def arm_imm(w):
            imm12 = w & 0xFFF
            rot = (imm12 >> 8) * 2
            v = imm12 & 0xFF
            if rot:
                v = ((v >> rot) | (v << (32 - rot))) & 0xFFFFFFFF
            return v
        ip = (addr + 8 + arm_imm(w0) + arm_imm(w1)) & 0xFFFFFFFF
        slot = (ip + (w2 & 0xFFF)) & 0xFFFFFFFF
    elif w0 & 0x0FFF0000 == 0x059F0000:          # ldr rX, [pc, #imm]
        slot = (addr + 8 + (w0 & 0xFFF)) & 0xFFFFFFFF
    else:
        raise ValueError(f'veneer 0x{addr:08x}: unrecognized prologue')
    return elf.m.imports.get(slot), slot


def recover(elf):
    row = elf.rows.get(IMP)
    if row is None or row[1] != CLASS or row[3] != 'loadFromSave':
        raise ValueError('CrystalManager: method-map drift')
    if min(i for i in elf.imps if i > IMP) != BOUNDARY:
        raise ValueError('CrystalManager: boundary drift')
    cells = elf.literal_cells(IMP, BOUNDARY)

    # ---- CFString pool: exact set equality
    found = {k: lit for lit, (t, k, ln) in cells['keys'].items() if k}
    if set(found) != set(KEY_CELLS):
        raise ValueError(f'CrystalManager: key set drift '
                         f'{set(found) ^ set(KEY_CELLS)}')
    for lit, (t, k, ln) in cells['keys'].items():
        if k is None or ln != len(k.encode()):
            raise ValueError(f'CrystalManager: CFString payload drift 0x{lit:08x}')
    pools = {}
    for k, want in KEY_CELLS.items():
        t = cells['keys'][found[k]][0]
        if t != want:
            raise ValueError(f'CrystalManager: {k} cell drift 0x{t:08x}')
        pools[k] = f'0x{t:08x}'
    for forbidden in FORBIDDEN_KEYS & set(found):
        raise ValueError(f'CrystalManager: forbidden key present: {forbidden}')

    # ---- no super call in this method; msgSend GOT must be present
    if 'objc_msgSend' not in {n for _, n in cells['got'].values()}:
        raise ValueError('CrystalManager: objc_msgSend GOT cell missing')
    if 'objc_msgSendSuper2' in {n for _, n in cells['got'].values()}:
        raise ValueError('CrystalManager: unexpected super2 dispatch')

    # ---- structural gates
    for name, site, wh in GATES:
        if not elf.word_eq(site, wh):
            raise ValueError(f'CrystalManager gate {name} drift @0x{site:08x}')

    # ---- BL sites: assert resolved target, not only the word
    bl_checks = [
        ('file_searchpath_call', 0x009F3F00, VENUE_PATH),
        ('file_second_searchpath_call', 0x009F4194, VENUE_PATH),
        ('file_parser_thunk_bl', 0x009F42C0, PARSER_THUNK),
        ('parser_thunk_callee_bl', 0x009F4520, PARSER_CALLEE),
    ]
    for label, site, want in bl_checks:
        got = bl_target(elf.rw(site) or 0, site)
        if got != want:
            raise ValueError(f'CrystalManager {label}: BL target drift '
                             f'0x{got:08x} != 0x{want:08x}')

    # ---- ABI / thunk resolution
    sym, slot = veneer_import(elf, VENUE_PATH)
    if sym != 'NSSearchPathForDirectoriesInDomains':
        raise ValueError(f'CrystalManager: search-path veneer target drift {sym}')

    # ---- classref cells: two flavors in __objc_classrefs (R_ARM_ABS32 with a
    # zero file word, or a direct R_ARM_RELATIVE pointer to the class object)
    class_out = {}
    for label, (addr, want) in CLASS_OBJECTS.items():
        rel_cell = elf.rel.get(addr, [])
        abs32 = [n for ty, n in rel_cell
                 if ty == 2 and n.startswith('OBJC_CLASS_$_')]
        if abs32:
            name, kind = abs32[0], 'abs32_zero_slot'
        else:
            if not any(ty == 23 for ty, _ in rel_cell):
                raise ValueError(f'CrystalManager: classref cell 0x{addr:08x} drift')
            name = elf.classes.get(elf.rw(addr) or 0, '')
            if not name:
                raise ValueError(f'CrystalManager: classref 0x{addr:08x} '
                                 'pointer does not resolve to a class')
            kind = 'relative_pointer'
        if want and name != want:
            raise ValueError(f'CrystalManager: classref 0x{addr:08x} = {name}')
        class_out[label] = {'cell': f'0x{addr:08x}', 'class': name, 'kind': kind}
    keychain_class = class_out['getpassword_class']['class']
    if 'Keychain' not in keychain_class:
        raise ValueError(f'CrystalManager: keychain class drift {keychain_class}')
    if class_out['uiddevice_cell']['class'] != 'OBJC_CLASS_$_UIDevice':
        raise ValueError('CrystalManager: UIDevice classref drift')

    # ---- ivars + selrefs census
    ivar_found = {n.split('.', 1)[1]: off
                  for _, (t, n, off) in cells['ivars'].items()}
    for name, want in IVAR_OFFSETS.items():
        if (elf.rw(elf.slot_of_ivar(f'OBJC_IVAR_$_{CLASS}.{name}')) or -1) != want:
            raise ValueError(f'CrystalManager: {name} offset drift')
    if ivar_found != IVAR_OFFSETS:
        raise ValueError(f'CrystalManager: ivar-slot drift {ivar_found}')
    sels = {n for _, n in cells['selrefs'].values()
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]*', n or '')}
    if sels != EXPECTED_SELREFS:
        raise ValueError(f'CrystalManager: selref drift '
                         f'{sels ^ EXPECTED_SELREFS}')

    return {
        'schema': 1, 'batch': 'b3e', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': 'CrystalManager loadFromSave read-back evidence (batch b3e)',
        'class': CLASS, 'imp': f'0x{IMP:08x}', 'boundary': f'0x{BOUNDARY:08x}',
        'code_words': (BOUNDARY - IMP) // 4, 'selector': 'loadFromSave',
        'super_call': None,
        'keychain_path': {
            'class': keychain_class,
            'selector': 'getPasswordForUsername:andServiceName:error:',
            'call_site': '0x009f3da4',
            'username_and_service_key':
                'com.majicjungle.blockheads.crystalcount',
            'error_out_param': 'fp-0x28',
            'guard': 'password != nil && error == nil, else file path '
                     '(0x009f3db8 / 0x009f3dc8)',
            'writes': {'crystalCount@8': '[password intValue] (0x009f3e6c)',
                       'amountString@12': 'retain([[NSString '
                       'stringWithFormat:@"7acfe93afc08%dc65ae2c54ecaf07f", '
                       'crystalCount] stringFromMD5]) (0x009f3ed4)'},
        },
        'file_path': {
            'search_paths': 'NSSearchPathForDirectoriesInDomains(14,1,1) via '
                            f'ABI veneer 0x{VENUE_PATH:08x} '
                            f'(slot 0x{slot:08x})',
            'string_file': 'docs/game/4bbf9ea9f3e11dd7afcb0f22ccb635d2, '
                           'read with stringWithContentsOfFile:encoding:4 '
                           'error:nil (0x009f3fb4); nil → return',
            'data_file': 'NSData dataWithContentsOfFile:<game/%@ path> '
                         '(0x009f42a4) → gzipInflate (0x009f42bc)',
            'parser_thunk': f'0x{PARSER_THUNK:08x} → 0x{PARSER_CALLEE:08x} '
                            '(r0 unchanged, r1=0; callee NOT decoded)',
            'tamper_gate': '[[derived] isEqualToString:[plist '
                           'objectForKey:@"loadSaveIDB"]] (0x009f4344); '
                           'mismatch → return without writing',
            'writes': {'crystalCount@8': '[string intValue] >> 2 (0x009f4400 '
                                         'asr r0,r0,#2 → 0x009f4414)',
                       'amountString@12': 'retain([[NSString '
                       'stringWithFormat:@"7acfe93afc08%dc65ae2c54ecaf07f", '
                       'crystalCount] stringFromMD5]) (0x009f447c)'},
            'not_decoded': 'the derived-string mix (device name / game/%@ / '
                           '%@_%@ / stringFromMD5) is gated call-site by '
                           'call-site but not symbolically evaluated',
        },
        'stored_scale': {'file': 4, 'keychain': 1,
                         'note': 'the on-disk string holds 4x the crystal '
                                 'count; the keychain password holds it 1:1'},
        'constants': {'search_path_directory': 14,
                      'search_path_domain_mask': 1, 'expand_tilde': 1,
                      'file_encoding_utf8': 4},
        'classref_cells': class_out,
        'pool_keys': sorted(pools), 'pool_key_cells': pools,
        'selrefs': sorted(sels),
        'ivar_offsets': IVAR_OFFSETS,
        'claim': (
            'CrystalManager -[loadFromSave] (506 w) has no super call: it '
            'first asks SFHFKeychainUtils '
            'getPasswordForUsername:andServiceName:error: for the literal '
            'account com.majicjungle.blockheads.crystalcount and, when the '
            'password is non-nil and the error is nil, sets crystalCount@8 = '
            '[password intValue] and amountString@12 = a retained MD5 of '
            'stringWithFormat:@"7acfe93afc08%dc65ae2c54ecaf07f" with that '
            'count; otherwise it falls back to the file path '
            '(NSSearchPathForDirectoriesInDomains(14,1,1) → '
            'docs/game/4bbf9ea9f3e11dd7afcb0f22ccb635d2 read as a UTF-8 '
            'string, then NSData dataWithContentsOfFile: → gzipInflate → a '
            'local parser thunk 0x009f4508 → 0x009f602c whose callee is not '
            'decoded), requires [derived isEqualToString:[plist '
            'objectForKey:@"loadSaveIDB"]] before writing, and finally sets '
            'crystalCount@8 = [fileString intValue] >> 2 (the file stores 4x '
            'the count) and amountString@12 to the same retained MD5 form; '
            'static level-A evidence only, no runtime roundtrip'),
    }


MUTATIONS = [
    ('crystal_keychain_class_cell', 0x00E8ADD0, bytes.fromhex('fce8e800'),
     'keychain class drift'),
    ('crystal_searchdir_const', 0x009F3EDC, bytes.fromhex('e300000f'),
     'file_searchdir_const14 drift'),
    ('crystal_utf8_encoding', 0x009F3F08, bytes.fromhex('e3003005'),
     'file_encoding_utf8_4 drift'),
    ('crystal_searchpath_bl_target', 0x009F3F00, bytes.fromhex('ebdf4007'),
     'file_searchpath_call'),
    ('crystal_keychain_guard_beq', 0x009F3DB8, bytes.fromhex('0a000048'),
     'keychain_password_beq_file drift'),
    ('crystal_asr_shift', 0x009F4400, bytes.fromhex('2001a0e1'),
     'file_asr_by_2 drift'),
    ('crystal_loadsaveidb_beq', 0x009F4350, bytes.fromhex('0a00004b'),
     'isequal_fail_beq_end drift'),
    ('crystal_amountstring_ivar', 'ivar:OBJC_IVAR_$_CrystalManager.amountString',
     bytes.fromhex('10000000'), 'offset drift'),
    ('crystal_key_cell_payload', 0x009F44FC, bytes.fromhex('c070f3ff'),
     'key set drift'),
    ('crystal_parser_thunk_bl', 0x009F42C0, bytes.fromhex('eb000091'),
     'file_parser_thunk_bl'),
    ('crystal_parser_callee_bl', 0x009F4520, bytes.fromhex('eb0006c2'),
     'parser_thunk_callee_bl'),
    ('crystal_string_file_key_cell', 0x009F44C4, bytes.fromhex('8870f3ff'),
     'key set drift'),
]


def resolve_target(elf, target):
    if isinstance(target, int):
        return target
    if isinstance(target, str) and target.startswith('ivar:'):
        return elf.slot_of_ivar(target[len('ivar:'):])
    raise ValueError(f'unresolvable mutation target {target!r}')


def self_test(elf):
    failures = []
    for name, target, patch, expect in MUTATIONS:
        try:
            recover(elf.mutate(resolve_target(elf, target), patch))
        except ValueError as exc:
            if expect not in str(exc):
                failures.append(f'{name}: wrong failure: {exc}')
        except Exception as exc:  # noqa: BLE001
            failures.append(f'{name}: unexpected {type(exc).__name__}: {exc}')
        else:
            failures.append(f'{name}: mutation was NOT detected')
    if failures:
        for f in failures:
            print('MUTATION FAIL:', f)
        raise SystemExit(f'{len(failures)}/{len(MUTATIONS)} negative controls failed')
    print(f'b3e self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'crystalmanager_loadfromsave.json')
    a = ap.parse_args()
    elf = ELF(a.elf)
    if a.self_test:
        self_test(elf)
        return
    text = json.dumps(recover(elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit(f'stale {a.output.name}')
    else:
        a.output.write_text(text)
    print('b3e CrystalManager: keychain+file paths, 7 keys, 2 ivars, '
          'tamper gate gated')


if __name__ == '__main__':
    main()
