#!/usr/bin/env python3
"""Hash-gated getSaveDict key pairings for batch 2l: CaveTroll, Plant.
Addresses/words extracted mechanically from the annotated listings +
freeblock simulator (tools/gen_b2l_table.py), then gated against the
pinned ELF, with hand-verified corrections for the state NSData path.

Shapes:
  CaveTroll 0x00D54924: [super getSaveDict] @0xd54978, then:
    state = [NSData dataWithBytes:&state length:0x24] — a 36-byte RAW
      BUFFER serialized from CaveTroll.state@208 (dataWithBytes:length:
      selref @0xd54e0c, movw #0x24 @0xd54a0c, set 0xd54ad4);
    dead = numberWithBool: of the INHERITED NPC.dead@56 (ldrb @0xd54af4
      + sxtb @0xd54b08, conv 0xd54b10, set 0xd54b34);
    defendSquare.x/.y = numberWithInt: of CaveTroll.defendSquare@356
      word+0 (ldr @0xd54b54, conv 0xd54b70, set 0xd54b94) and word+4
      (ldr #4 @0xd54bb4, conv 0xd54bd0, set 0xd54bf4);
    attackingNPC = numberWithBool: of CaveTroll.chasingNPC@388 (ldrb
      @0xd54c94 + sxtb @0xd54cac, conv 0xd54cdc blx sl, set 0xd54d00);
    lastKnownNPCPosition.x/.y = numberWithInt: of
      CaveTroll.lastKnownNPCPosition@392 word+0 (ldr @0xd54d20, conv
      0xd54d3c, set 0xd54d60) and word+4 (ldr #4 @0xd54d80, conv
      0xd54d9c, set 0xd54dc0).
  Plant 0x00955D7C: [super getSaveDict] @0x955dd0, then:
    saveTime = numberWithDouble:([self.world worldTime]) — a 64-bit
      double from the WORLD CLOCK selector (msgSend worldTime
      @0x956000, vmov d0 @0x956004, conv 0x956020, set 0x956044);
    seasonOffset@68 numberWithInt:, age@72 numberWithFloat (vldr s2),
    gatherProgress@80 numberWithInt:,
    hasFloweredThisSeason@84 numberWithBool (ldrb @0x956184),
    flowering@85 numberWithBool (ldrb @0x9561e4 — BYTE offset 85,
      adjacent to hasFloweredThisSeason@84),
    frozen@76 numberWithBool (ldrb @0x956244),
    maxAgeGene@54 / growthRateGene@56 numberWithInt:,
    maxAge@88 / growthRate@92 numberWithFloat (vldr s2).

Facts:
- CaveTroll.state is the FIRST dataWithBytes:length: serialization in
  the save path: 36 raw bytes of a struct ivar boxed as NSData — not a
  direct object, not a NSNumber.
- CaveTroll.dead uses an INHERITED ivar (NPC.dead@56), proving subclass
  saves can reach parent-family fields beyond DynamicObject.ownerID.
- Plant.saveTime is the FIRST numberWithDouble: key, and its value is
  world-fed ([self.world worldTime]), not an ivar — same worldTime
  contract the Egg batch noted as a stamp.
- Plant.flowering@85 and hasFloweredThisSeason@84 are ADJACENT BYTES
  (85 = 84+1), both ldrb+sxtb bools.
"""
import argparse, hashlib, io, json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from trace_objc_dispatch import ELFMemory

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
BASE = 0x0105FAF4
MSGSEND_SUPER2 = 0x0105B79C

# cls, imp, boundary, super_site, super_got_cell, super_sel_cell, super_class_cell
SUPER = {
 'CaveTroll': (0x00D54924, 0x00D54E2C, 0x00D54978, 0x00D54DD0, 0x00D54DD4, 0x00D54DD8),
 'Plant':     (0x00955D7C, 0x0095649C, 0x00955DD0, 0x00956414, 0x00956418, 0x0095641C),
}

# cls, key, key_cell, cfstring_obj, ivar, off, conv, conv_site, conv_word,
# ncell, conv_sel_cell, set_site, set_word, set_sel_cell
# state's conv_site is the dataWithBytes: msgSend call site (blx ip);
# its selref cell (0xd54e0c) and NSData classref cell (0xd54e14) are
# gated separately via the dataWithBytes branch below.
KEYS = [
 ('CaveTroll','state',0x00D54E08,0x00FAE768,'OBJC_IVAR_$_CaveTroll.state',208,
  'dataWithBytes:length:',0x00D54AA8,'3cff2fe1',None,0x00D54E0C,0x00D54AD4,'3cff2fe1',0x00D54DE8),
 ('CaveTroll','dead',0x00D54DFC,0x00FAE778,'OBJC_IVAR_$_NPC.dead',56,
  'numberWithBool:',0x00D54B10,'33ff2fe1',0x00D54DF4,0x00D54E00,0x00D54B34,'3cff2fe1',0x00D54DE8),
 ('CaveTroll','defendSquare.x',0x00D54DF8,0x00FAE748,'OBJC_IVAR_$_CaveTroll.defendSquare',356,
  'numberWithInt:',0x00D54B70,'33ff2fe1',0x00D54DF4,0x00D54DEC,0x00D54B94,'3cff2fe1',0x00D54DE8),
 ('CaveTroll','defendSquare.y',0x00D54DE0,0x00FAE758,'OBJC_IVAR_$_CaveTroll.defendSquare',356,
  'numberWithInt:',0x00D54BD0,'33ff2fe1',0x00D54DF4,0x00D54DEC,0x00D54BF4,'3cff2fe1',0x00D54DE8),
 ('CaveTroll','attackingNPC',0x00D54E24,0x00FAE788,'OBJC_IVAR_$_CaveTroll.chasingNPC',388,
  'numberWithBool:',0x00D54CDC,'3aff2fe1',0x00D54DF4,0x00D54E00,0x00D54D00,'3cff2fe1',0x00D54DE8),
 ('CaveTroll','lastKnownNPCPosition.x',0x00D54E20,0x00FAE798,'OBJC_IVAR_$_CaveTroll.lastKnownNPCPosition',392,
  'numberWithInt:',0x00D54D3C,'33ff2fe1',0x00D54DF4,0x00D54DEC,0x00D54D60,'3cff2fe1',0x00D54DE8),
 ('CaveTroll','lastKnownNPCPosition.y',0x00D54E18,0x00FAE7A8,'OBJC_IVAR_$_CaveTroll.lastKnownNPCPosition',392,
  'numberWithInt:',0x00D54D9C,'33ff2fe1',0x00D54DF4,0x00D54DEC,0x00D54DC0,'3cff2fe1',0x00D54DE8),
 ('Plant','saveTime',0x00956488,0x00F95578,None,0,
  'numberWithDouble:',0x00956020,'3cff2fe1',0x00956434,0x0095648C,0x00956044,'3cff2fe1',0x00956428),
 ('Plant','seasonOffset',0x00956480,0x00F954F8,'OBJC_IVAR_$_Plant.seasonOffset',68,
  'numberWithInt:',0x00956080,'33ff2fe1',0x00956434,0x00956444,0x009560A4,'3cff2fe1',0x00956428),
 ('Plant','age',0x00956478,0x00F95508,'OBJC_IVAR_$_Plant.age',72,
  'numberWithFloat:',0x009560E0,'3eff2fe1',0x00956434,0x0095642C,0x00956104,'3cff2fe1',0x00956428),
 ('Plant','gatherProgress',0x00956470,0x00F95518,'OBJC_IVAR_$_Plant.gatherProgress',80,
  'numberWithInt:',0x00956140,'33ff2fe1',0x00956434,0x00956444,0x00956164,'3cff2fe1',0x00956428),
 ('Plant','hasFloweredThisSeason',0x00956468,0x00F95528,'OBJC_IVAR_$_Plant.hasFloweredThisSeason',84,
  'numberWithBool:',0x009561A0,'33ff2fe1',0x00956434,0x00956458,0x009561C4,'3cff2fe1',0x00956428),
 ('Plant','flowering',0x00956460,0x00F95538,'OBJC_IVAR_$_Plant.flowering',85,
  'numberWithBool:',0x00956200,'33ff2fe1',0x00956434,0x00956458,0x00956224,'3cff2fe1',0x00956428),
 ('Plant','frozen',0x00956454,0x00F95548,'OBJC_IVAR_$_Plant.frozen',76,
  'numberWithBool:',0x00956260,'33ff2fe1',0x00956434,0x00956458,0x00956284,'3cff2fe1',0x00956428),
 ('Plant','maxAgeGene',0x0095644C,0x00F95558,'OBJC_IVAR_$_Plant.maxAgeGene',54,
  'numberWithInt:',0x009562C0,'33ff2fe1',0x00956434,0x00956444,0x009562E4,'3cff2fe1',0x00956428),
 ('Plant','growthRateGene',0x00956440,0x00F95568,'OBJC_IVAR_$_Plant.growthRateGene',56,
  'numberWithInt:',0x00956320,'33ff2fe1',0x00956434,0x00956444,0x00956344,'3cff2fe1',0x00956428),
 ('Plant','maxAge',0x00956438,0x00F95588,'OBJC_IVAR_$_Plant.maxAge',88,
  'numberWithFloat:',0x00956380,'3eff2fe1',0x00956434,0x0095642C,0x009563A4,'3cff2fe1',0x00956428),
 ('Plant','growthRate',0x00956420,0x00F95598,'OBJC_IVAR_$_Plant.growthRate',92,
  'numberWithFloat:',0x009563E0,'3eff2fe1',0x00956434,0x0095642C,0x00956404,'3cff2fe1',0x00956428),
]

# site gates that are not per-key: raw-buffer path, world-clock path, byte loads.
EXTRA_GATES = [
 ('CaveTroll', 'state_len_movw_0x24', 0x00D54A0C, '241000e3'),
 ('CaveTroll', 'dead_ldrb', 0x00D54AF4, '0030d3e5'),
 ('CaveTroll', 'dead_sxtb', 0x00D54B08, '7320afe6'),
 ('CaveTroll', 'defend_x_word_ldr', 0x00D54B54, '003093e5'),
 ('CaveTroll', 'defend_y_word_ldr4', 0x00D54BB4, '043093e5'),
 ('CaveTroll', 'chasing_ldrb', 0x00D54C94, '0000d0e5'),
 ('CaveTroll', 'chasing_sxtb', 0x00D54CAC, '7aa0afe6'),
 ('CaveTroll', 'lknp_x_word_ldr', 0x00D54D20, '003093e5'),
 ('CaveTroll', 'lknp_y_word_ldr4', 0x00D54D80, '043093e5'),
 ('Plant', 'worldtime_msg_site', 0x00956000, '32ff2fe1'),
 ('Plant', 'worldtime_vmov_d0', 0x00956004, '100b41ec'),
 ('Plant', 'hasflowered_ldrb', 0x00956184, '0030d3e5'),
 ('Plant', 'hasflowered_sxtb', 0x00956198, '7320afe6'),
 ('Plant', 'flowering_ldrb', 0x009561E4, '0030d3e5'),
 ('Plant', 'flowering_sxtb', 0x009561F8, '7320afe6'),
 ('Plant', 'frozen_ldrb', 0x00956244, '0030d3e5'),
 ('Plant', 'frozen_sxtb', 0x00956258, '7320afe6'),
]


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


def recover(path):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA:
        raise ValueError('original ELF SHA mismatch')
    m = ELFMemory(path)

    def rw(a):
        off = m.offset(a, 4)
        if off is None:
            raise ValueError(f'unmapped {a:#x}')
        return int.from_bytes(m.data[off:off + 4], 'little')

    def cstr(a):
        off = m.offset(a, 1)
        end = m.data.find(b'\0', off, off + 96)
        return m.data[off:end].decode('ascii')

    def rebase(c):
        return (BASE + signed(rw(c))) & 0xFFFFFFFF

    def word_eq(a, wh):
        return rw(a).to_bytes(4, 'little').hex() == wh

    elf = ELFFile(io.BytesIO(raw))
    abs32 = {}
    for section in elf.iter_sections():
        if isinstance(section, RelocationSection):
            syms = elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_info_type'] == 2 and rel['r_info_sym']:
                    abs32[rel['r_offset']] = syms.get_symbol(rel['r_info_sym']).name
    dynsym = elf.get_section_by_name('.dynsym')
    ivar_by_name = {s.name: s['st_value'] for s in dynsym.iter_symbols()
                    if s['st_value'] and s.name.startswith('OBJC_IVAR_$_')}

    tsv = (NATIVE / 'libApplication_objc_methods.tsv').read_text().splitlines()[1:]
    rows = sorted((l.split('\t') for l in tsv), key=lambda l: int(l[0], 16))
    imps = [int(r[0], 16) for r in rows]
    by_imp = {int(r[0], 16): r for r in rows}

    def class_name(struct):
        return cstr(rw(rw(struct + 0x10) + 0x10))

    results = {}
    for cls, (imp, boundary, site, gotc, selc, crc) in SUPER.items():
        row = by_imp.get(imp)
        if row is None or row[1] != cls or row[3] != 'getSaveDict':
            raise ValueError(f'{cls}: method-map drift')
        if min(i for i in imps if i > imp) != boundary:
            raise ValueError(f'{cls}: boundary drift')
        if not word_eq(site, '3cff2fe1'):
            raise ValueError(f'{cls}: super site word drift')
        if rebase(gotc) != MSGSEND_SUPER2 or rw(MSGSEND_SUPER2) != 0:
            raise ValueError(f'{cls}: super2 GOT drift')
        if cstr(rw(rebase(selc))) != 'getSaveDict':
            raise ValueError(f'{cls}: super selref drift')
        struct = rw(rebase(crc))
        if class_name(struct) != cls:
            raise ValueError(f'{cls}: super classref name-walk drift')
        results[cls] = {'class': cls, 'imp': f'0x{imp:08x}',
                        'boundary': f'0x{boundary:08x}',
                        'code_words': (boundary - imp) // 4,
                        'style': 'super_plus_own_keys',
                        'super_site': f'0x{site:08x}',
                        'super_class_struct': f'0x{struct:08x}', 'keys': []}

    for cls, key, kcell, obj, isym, off, conv, cs, cw, ncell, csr, ss, sw, ssc in KEYS:
        if abs32.get(obj) != '__CFConstantStringClassReference':
            raise ValueError(f'{cls}.{key}: CFString isa drift')
        if cstr(rw(obj + 8)) != key or rw(obj + 12) != len(key.encode()):
            raise ValueError(f'{cls}.{key}: CFString payload drift')
        if rebase(kcell) != obj:
            raise ValueError(f'{cls}.{key}: key cell drift')
        entry = {'key': key, 'cfstring_object': f'0x{obj:08x}',
                 'set_object_site': f'0x{ss:08x}'}
        if isym is not None:
            stor = ivar_by_name.get(isym)
            if stor is None or rw(stor) != off:
                raise ValueError(f'{cls}.{key}: ivar drift')
            entry['ivar'] = isym
            entry['ivar_offset'] = off
        else:
            entry['ivar'] = None
        if not word_eq(ss, sw):
            raise ValueError(f'{cls}.{key}: set word drift')
        if cstr(rw(rebase(ssc))) != 'setObject:forKey:':
            raise ValueError(f'{cls}.{key}: setObject selref drift')
        if conv == 'dataWithBytes:length:':
            # raw-buffer path: the conv site is the msgSend call (blx ip);
            # the selector loads from selref cell 0xd54e0c and the receiver
            # is the NSData classref cell 0xd54e14; the movw #0x24 length
            # gate holds (EXTRA_GATES).
            if not word_eq(cs, cw):
                raise ValueError(f'{cls}.{key}: dataWithBytes call word drift')
            if cstr(rw(rebase(csr))) != 'dataWithBytes:length:':
                raise ValueError(f'{cls}.{key}: dataWithBytes selref drift')
            if abs32.get(rebase(0x00D54E14)) != 'OBJC_CLASS_$_NSData' or rw(rebase(0x00D54E14)) != 0:
                raise ValueError(f'{cls}.{key}: NSData classref drift')
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            entry['value_source'] = 'raw_buffer'
            entry['raw_length'] = 0x24
        elif conv is None:
            entry['conversion'] = 'direct_object'
        else:
            entry['conversion'] = conv
            entry['conversion_site'] = f'0x{cs:08x}'
            if isym is None:
                entry['value_source'] = 'world_selector'
            if cw is not None:
                if not word_eq(cs, cw):
                    raise ValueError(f'{cls}.{key}: conv word drift')
            if cstr(rw(rebase(csr))) != conv:
                raise ValueError(f'{cls}.{key}: conv selref drift')
            if abs32.get(rebase(ncell)) != 'OBJC_CLASS_$_NSNumber' or rw(rebase(ncell)) != 0:
                raise ValueError(f'{cls}.{key}: NSNumber classref drift')
        results[cls]['keys'].append(entry)

    gate_notes = {}
    for cls, name, site, wh in EXTRA_GATES:
        if not word_eq(site, wh):
            raise ValueError(f'{cls}.{name}: gate word drift @0x{site:08x}')
        gate_notes.setdefault(cls, []).append(f'{name}@0x{site:08x}')
    for cls, notes in gate_notes.items():
        results[cls]['site_gates'] = notes

    return {
        'schema': 1, 'elf_sha256': SHA, 'pic_base': f'0x{BASE:08x}',
        'method': 'getSaveDict key pairings (batch 2l)',
        'classes': [results[c] for c in ('CaveTroll', 'Plant')],
        'claim': ('CaveTroll serializes state@208 as 36 raw bytes via '
                  '[NSData dataWithBytes:length:] (first raw-buffer key), '
                  'saves the INHERITED NPC.dead@56 bool, dotted '
                  'defendSquare.x/.y@356 and lastKnownNPCPosition.x/.y@392 '
                  'word pairs, and attackingNPC from the chasingNPC@388 '
                  'signed byte; Plant saves saveTime as the FIRST '
                  'numberWithDouble of the world-fed [self.world '
                  'worldTime] clock (not an ivar), plus '
                  'seasonOffset@68/gatherProgress@80/maxAgeGene@54/'
                  'growthRateGene@56 ints, age@72/maxAge@88/'
                  'growthRate@92 floats, and the ADJACENT BYTE bools '
                  'hasFloweredThisSeason@84/flowering@85 plus frozen@76; '
                  '5 overrides remain (Action, Tree, InteractionObject, '
                  'TrainCar, Workbench), read-back/roundtrip unresolved'),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('elf', type=Path)
    p.add_argument('--check', action='store_true')
    p.add_argument('--output', type=Path, default=NATIVE / 'subclass_savedict_keys_b2l.json')
    a = p.parse_args()
    text = json.dumps(recover(a.elf), indent=2, sort_keys=True) + '\n'
    if a.check:
        if a.output.read_text() != text:
            raise SystemExit('stale subclass_savedict_keys_b2l.json')
    else:
        a.output.write_text(text)
    print('b2l classes=2 keys=18')


if __name__ == '__main__':
    main()
