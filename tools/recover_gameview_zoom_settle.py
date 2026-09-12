#!/usr/bin/env python3
"""Hash-gated evidence for the entire post-cap GameView zoom-settling region."""
import argparse
import json
import re
import struct
from pathlib import Path
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

NATIVE = Path(__file__).resolve().parents[1] / 'reconstruction/reverse-v3/native'
START, END = 0x926acc, 0x927ed8
# Locally reviewed r0/r1 routes, not automatic alias or callee verification.
CALL_ROUTES = {0x926c20: (0x927550, 'takingPhoto', 'self.world')}
DEFAULT_CALL_PAIRS = (
    (0x926dcc, 0x926dfc), (0x926f3c, 0x926f6c),
    (0x92712c, 0x92715c), (0x9272ec, 0x92731c),
    (0x9274dc, 0x92750c), (0x9276b4, 0x9276e4),
    (0x927850, 0x927880), (0x9279ec, 0x927a1c),
    (0x927bb8, 0x927be8), (0x927d78, 0x927da8),
)
for get, put in DEFAULT_CALL_PAIRS:
    CALL_ROUTES[get] = (0x926904 if get < 0x927000 else 0x927ffc,
                        'standardUserDefaults', 'NSUserDefaults classref')
    CALL_ROUTES[put] = (0x927354 if put < 0x927000 else 0x928028,
                        'setFloat:forKey:', 'previous standardUserDefaults result')
NOTIFY_CALLS = (0x926fa0, 0x927188, 0x927348, 0x927538, 0x927710,
                0x9278ac, 0x927a48, 0x927c14, 0x927dd4)
for call in NOTIFY_CALLS:
    CALL_ROUTES[call] = (0x927718 if call < 0x927000 else 0x928020,
                         'pinchScaleChanged', 'self')
# Numerical paths: each entry explicitly tracks effect sites and raw literals.
BRANCHES = (
    ('HalfDown', 0x926cd8, 0x926cec, 'subtract', 0x926ba8, '<', 0x926dcc, 0x926dfc, 0x926fa0),
    ('OneUp', 0x926e44, 0x926e5c, 'add', 0x926bb8, '>', 0x926f3c, 0x926f6c, 0x926fa0),
    ('OneDown', 0x927038, 0x92703c, 'subtract', None, '<', 0x92712c, 0x92715c, 0x927188),
    ('OneHalfUp', 0x9271f8, 0x92720c, 'add', 0x927380, '>', 0x9272ec, 0x92731c, 0x927348),
    ('OneHalfDown', 0x9273e8, 0x9273fc, 'subtract', 0x927390, '<', 0x9274dc, 0x92750c, 0x927538),
    ('TwoUp', 0x9275b0, 0x9275c8, 'add', 0x9273a0, '>', 0x9276b4, 0x9276e4, 0x927710),
    ('TwoDown', 0x92774c, 0x927764, 'subtract', 0x9273b0, '<', 0x927850, 0x927880, 0x9278ac),
    ('ThreeUp', 0x9278e8, 0x927900, 'add', 0x927c28, '>', 0x9279ec, 0x927a1c, 0x927a48),
    ('ThreeDown', 0x927ab4, 0x927acc, 'subtract', 0x927c40, '<', 0x927bb8, 0x927be8, 0x927c14),
    ('EightUp', 0x927c74, 0x927c8c, 'add', 0x927ff0, '>', 0x927d78, 0x927da8, 0x927dd4),
)


def recover(path):
    from elftools.elf.elffile import ELFFile
    from recover_gameview_update_boundary import expand_vfp_immediate
    mem = ELFMemory(path)
    text = (NATIVE / 'disasm_gameview_update.txt').read_text()
    lines = []
    for line in text.splitlines():
        match = re.search(r'(0x[0-9a-f]{8})\s+([0-9a-f]{8})\s+(.*)', line)
        if match and START <= int(match[1], 16) < END:
            lines.append((int(match[1], 16), match[3], line))
    verified = verify_disassembly(mem, '\n'.join(row[2] for row in lines), START, END)
    calls = {a for a, ins, _ in lines if re.match(r'blx?\s', ins)}
    if calls != set(CALL_ROUTES):
        raise ValueError('reviewed map must cover every call, exactly')
    base = (0x9259d8 + mem.word(0x9268e8)) & 0xffffffff
    routes = []
    for call, (literal, expected, receiver) in sorted(CALL_ROUTES.items()):
        name = mem.selectors.get(mem.word((base + mem.word(literal)) & 0xffffffff))
        if name != expected:
            raise ValueError('selector route changed')
        routes.append({'call': f'0x{call:08x}', 'literal': f'0x{literal:08x}',
                       'selector': name, 'receiver': receiver, 'status': 'locally reviewed; runtime unverified'})
    literals, immediates = {}, {}
    for a, ins, _ in lines:
        match = re.match(r'vldr d[0-9]+, \[(0x[0-9a-f]+)\]', ins)
        if match:
            va = int(match[1], 16)
            raw = mem.word(va).to_bytes(4, 'little') + mem.word(va+4).to_bytes(4, 'little')
            value = struct.unpack('<d', raw)[0]
            literals[f'0x{va:08x}'] = {'bits': f'0x{int.from_bytes(raw, "little"):016x}',
                                      'value': value, 'hex_float': value.hex()}
        if re.match(r'vmov\.f(?:32|64) ', ins):
            word = mem.word(a)
            width = 32 if ins.startswith('vmov.f32') else 64
            imm8 = (((word >> 16) & 15) << 4) | (word & 15)
            immediates[f'0x{a:08x}'] = {'word': f'0x{word:08x}', 'width': width,
                                       'value': expand_vfp_immediate(imm8, width)}
    with path.open('rb') as stream:
        from elftools.elf.relocation import RelocationSection
        elf = ELFFile(stream)
        symbols = {s['st_value']: s.name for s in elf.get_section_by_name('.dynsym').iter_symbols()}
        classref = (base + mem.word(0x928000)) & 0xffffffff
        class_relocations = []
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                table = elf.get_section(section['sh_link'])
                for rel in section.iter_relocations():
                    if rel['r_offset'] == classref:
                        class_relocations.append((rel['r_info_type'], table.get_symbol(rel['r_info_sym']).name))
        if class_relocations != [(2, 'OBJC_CLASS_$_NSUserDefaults')]:
            raise ValueError('NSUserDefaults classref relocation changed')
    message_got = (base + mem.word(0x927ff8)) & 0xffffffff
    if mem.imports.get(message_got) != 'objc_msgSend':
        raise ValueError('message-send import changed')
    fields = []
    for literal in (0x927a50, 0x926b64, 0x927194, 0x928010, 0x928014, 0x928018, 0x92801c):
        ptr = mem.word((base + mem.word(literal)) & 0xffffffff)
        name = symbols.get(ptr)
        if not name or not name.startswith('OBJC_IVAR_$_GameView.'):
            raise ValueError('missing GameView ivar')
        fields.append({'literal': f'0x{literal:08x}', 'symbol': name, 'offset': mem.word(ptr)})
    key = (base + mem.word(0x928024)) & 0xffffffff
    ptr, length = mem.word(key+8), mem.word(key+12)
    offset = mem.offset(ptr, length)
    if offset is None or mem.data[offset:offset+length] != b'pinchScale':
        raise ValueError('CFString key changed')
    branches = []
    for name, start, target, sign, threshold, comparison, get, put, notify in BRANCHES:
        branches.append({'name': name, 'start': f'0x{start:08x}',
            'target_immediate': f'0x{target:08x}', 'target': immediates[f'0x{target:08x}']['value'],
            'bias_operation': sign, 'snap_comparison': comparison,
            'snap_threshold_literal': f'0x{threshold:08x}' if threshold else None,
            'snap_threshold': literals[f'0x{threshold:08x}']['value'] if threshold else 1.0,
            'defaults_get': f'0x{get:08x}', 'defaults_put': f'0x{put:08x}', 'notify': f'0x{notify:08x}'})
    return {'start': f'0x{START:08x}', 'end_exclusive': f'0x{END:08x}',
            'verified_words': verified, 'call_count': len(calls), 'calls': routes,
            'fields': fields, 'double_literals': dict(sorted(literals.items())),
            'vfp_immediates': immediates, 'settling_paths': branches,
            'defaults_key': 'pinchScale',
            'defaults_classref': {'address': f'0x{classref:08x}', 'relocation_type': 2,
                                  'symbol': class_relocations[0][1]},
            'message_import': {'got_address': f'0x{message_got:08x}', 'symbol': 'objc_msgSend'},
            'runtime_verified': False,
            'boundary': 'Snapshot numerical/effect source only. Caller reloads after external callbacks are not simulated.'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = recover(a.elf)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('verified_words', 'call_count', 'runtime_verified')}))


if __name__ == '__main__':
    main()
