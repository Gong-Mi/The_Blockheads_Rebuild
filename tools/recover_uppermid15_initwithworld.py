#!/usr/bin/env python3
"""Hash-gated read-back evidence for batch b3l: FIFTEEN upper-mid-tier
`initWithWorld:…` loaders (214-408 words, 4,518 words total), the tier that
closes the loader CHAIN NODES: DynamicObject (the ROOT loader, 273w) and
InteractionObject (the mid-chain node, 352w) — every other loader front
class forwards into one of these two (or into Tree/Plant/TrainCar/Sign/NPC,
all previously covered).

Table-driven like b3k: all key/ivar/selector/super facts come from the
literal-pool scan, exact-gated per class; word gates pin only the prologue
and the epilogue pair (located by scan).

Special structures in this tier (all decoded from the pools):
  * DynamicObject is the ROOT — its super is the ObjC root class (nil
    in-file superclass beyond NSObject), and it does NOT forward any
    initWithWorld variant: it READS {pos_x, pos_y, floatPos, uniqueID},
    then runs [self initDerivedStuff:loadPhysicalBlockIfNeeded:] and
    [NSArray objectAtIndex:] — the base class loader that every chain
    ends in. Its GOT still has objc_msgSendSuper2 (for [super init]).
  * A THIRD selector variant appears: initWithWorld:dynamicWorld:
    saveDict:cache:parentObject: (5-arg) — in the pools of GlowBlock,
    FireObject, NormalPlant, TradePortal, Torch. These classes CONSTRUCT
    child light objects (alloc + the 5-arg variant) after loading their
    own keys: the lightDict key feeds a Light object creation.
  * DropBear reads saveTime + [world worldTime] (third site of the b3a
    gate pattern), plus removeFromMacroBlock / release / maxAge / [NPC age].
  * CaveTroll parses a byte blob: keys dead/state/defendSquare.x/.y plus
    NSData bytes/length selectors, and a NEW hook name:
    initSubDerivedStuffStuff.
  * TrainCar reads FORMATTED keys: 'currentBlockheadIndex_%d' via
    stringWithFormat: — per-rider slots, maxNumberOfRiders iterations.
  * OwnershipSign reads {h, w} (land claim radii) and hooks updateText +
    autorelease; its super is Sign (b3k-covered).
"""
import argparse
import copy
import hashlib
import io
import json
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
SEL_EXACT = 'initWithWorld:dynamicWorld:saveDict:cache:'
SEL_LONG = ('initWithWorld:dynamicWorld:saveDict:cache:'
            'treeDensityNoiseFunction:seasonOffsetNoiseFunction:')
SEL_PARENT = 'initWithWorld:dynamicWorld:saveDict:cache:parentObject:'

PUSH = 'e92d4df0'
ADD_FP = 'e28db018'
RET_SUB = 'e24bd018'
POP = 'e8bd8df0'


def signed(v):
    return v - (1 << 32) if v & 0x80000000 else v


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

    def words(self, imp, boundary):
        return [self.rw(a) or 0 for a in range(imp, boundary, 4)]

    def super_class_of(self, class_object):
        ptr = self.rw(class_object + 4)
        name = self.classes.get(ptr)
        return name.replace('OBJC_CLASS_$_', '') if name else None

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
            cls_rel = [n for ty, n in rel_t
                       if ty == 2 and n.startswith('OBJC_CLASS_$_')]
            if cls_rel:
                classes[lit] = (t, cls_rel[0])
                continue
            wv = self.rw(t)
            if wv is not None and wv in self.ivar_slots:
                ivars[lit] = (t, self.ivar_slots[wv][0], self.rw(wv))
                continue
            wv2 = self.rw(t)
            if wv2 is not None and wv2 in self.classes:
                classes[lit] = (t, self.classes[wv2])
                continue
            sel = self.m.selectors.get(wv2) if wv2 is not None else None
            if sel and sel.isprintable() and '\x7f' not in sel:
                selrefs[lit] = (t, sel)
                continue
            other[lit] = (t, wv2)
        return {'keys': keys, 'selrefs': selrefs, 'ivars': ivars,
                'classes': classes, 'got': got, 'other': other}


# child-object-construction class refs (beyond the own-class superref):
# the five light constructors alloc ArtificialLight children from their
# lightDict key; TrainCar builds NSStrings for its formatted keys;
# TradePortal also builds an NSMutableDictionary (localPriceOffsets).
EXTRA_CLASSREFS = {
    'GlowBlock': {'OBJC_CLASS_$_ArtificialLight'},
    'FireObject': {'OBJC_CLASS_$_ArtificialLight'},
    'NormalPlant': {'OBJC_CLASS_$_ArtificialLight'},
    'TradePortal': {'OBJC_CLASS_$_ArtificialLight',
                    'OBJC_CLASS_$_NSMutableDictionary'},
    'Torch': {'OBJC_CLASS_$_ArtificialLight'},
    'TrainCar': {'OBJC_CLASS_$_NSString'},
}


# cls, imp, words, variant, runtime_super (None = root), own_keys, own_ivars,
# own_sels (beyond the forwarded selector; SEL_PARENT counted where the
# class constructs child light objects)
CLASSES = [
    ('ElevatorShaft', 0x00CAD2CC, 214, SEL_EXACT, 'DynamicObject',
     ['itemType', 'lastKnownMotorPos.x', 'lastKnownMotorPos.y', 'ownerID',
      'paintColor'],
     ['OBJC_IVAR_$_DynamicObject.ownerID', 'OBJC_IVAR_$_ElevatorShaft.itemType',
      'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos',
      'OBJC_IVAR_$_ElevatorShaft.paintColor'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:', 'retain',
      'unsignedIntValue']),
    ('GlowBlock', 0x00CA8920, 214, SEL_EXACT, 'DynamicObject',
     ['lightDict', 'tileType'],
     ['OBJC_IVAR_$_DynamicObject.cache', 'OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.pos', 'OBJC_IVAR_$_DynamicObject.world',
      'OBJC_IVAR_$_GlowBlock.light', 'OBJC_IVAR_$_GlowBlock.tileType'],
     ['alloc', 'initSubDerivedItems', SEL_PARENT, 'intValue', 'macroTiles',
      'objectForKey:']),
    ('ElevatorMotor', 0x0070046C, 218, SEL_EXACT, 'DynamicObject',
     ['availableElectricity', 'itemType', 'maxY', 'minY', 'ownerID'],
     ['OBJC_IVAR_$_DynamicObject.ownerID',
      'OBJC_IVAR_$_ElevatorMotor.availableElectricity',
      'OBJC_IVAR_$_ElevatorMotor.itemType', 'OBJC_IVAR_$_ElevatorMotor.maxY',
      'OBJC_IVAR_$_ElevatorMotor.minY'],
     ['initSubDerivedItems', 'intValue', 'objectForKey:', 'retain',
      'unsignedIntValue']),
    ('TradingPost', 0x005E5718, 223, SEL_EXACT, 'InteractionObject',
     ['coinCount', 'priceTier', 'sellerClientID', 'sellerClientName'],
     ['OBJC_IVAR_$_DynamicObject.ownerID', 'OBJC_IVAR_$_TradingPost.coinCount',
      'OBJC_IVAR_$_TradingPost.priceTier',
      'OBJC_IVAR_$_TradingPost.sellerClientName'],
     ['initSlotsWithSaveDict:', 'initSubDerivedItems', 'integerValue',
      'objectForKey:', 'retain']),
    ('FireObject', 0x00674AF4, 259, SEL_EXACT, 'DynamicObject',
     ['burnTimer', 'lightDict', 'spreadTimer_0', 'spreadTimer_1',
      'spreadTimer_2', 'spreadTimer_3'],
     ['OBJC_IVAR_$_DynamicObject.cache', 'OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.pos', 'OBJC_IVAR_$_DynamicObject.world',
      'OBJC_IVAR_$_FireObject.burnTimer', 'OBJC_IVAR_$_FireObject.light',
      'OBJC_IVAR_$_FireObject.spreadTimers'],
     ['alloc', 'floatValue', 'initSubDerivedItems', SEL_PARENT, 'macroTiles',
      'objectForKey:']),
    ('DynamicObject', 0x00839F7C, 273, SEL_EXACT, None,
     ['floatPos', 'pos_x', 'pos_y', 'uniqueID'],
     ['OBJC_IVAR_$_DynamicObject.cache',
      'OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.floatPos', 'OBJC_IVAR_$_DynamicObject.pos',
      'OBJC_IVAR_$_DynamicObject.uniqueID', 'OBJC_IVAR_$_DynamicObject.world'],
     ['floatValue', 'init', 'initDerivedStuff:loadPhysicalBlockIfNeeded:',
      'intValue', 'objectAtIndex:', 'objectForKey:', 'unsignedLongValue']),
    ('NormalPlant', 0x00A66614, 281, SEL_LONG, 'Plant',
     ['availableFood', 'lightDict'],
     ['OBJC_IVAR_$_DynamicObject.cache', 'OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.pos', 'OBJC_IVAR_$_DynamicObject.world',
      'OBJC_IVAR_$_NormalPlant.availableFood', 'OBJC_IVAR_$_NormalPlant.light',
      'OBJC_IVAR_$_Plant.flowering'],
     ['alloc', 'emitsLight', 'floatValue', 'initSubDerivedItems', SEL_PARENT,
      SEL_LONG, 'macroTiles', 'objectForKey:', 'tileIsKindOfSelf:']),
    ('TradePortal', 0x00D382FC, 281, SEL_EXACT, 'InteractionObject',
     ['level', 'lightDict', 'localPriceOffsets'],
     ['OBJC_IVAR_$_DynamicObject.cache', 'OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.pos', 'OBJC_IVAR_$_DynamicObject.world',
      'OBJC_IVAR_$_TradePortal.level', 'OBJC_IVAR_$_TradePortal.light',
      'OBJC_IVAR_$_TradePortal.localPriceOffsets'],
     ['alloc', 'init', 'initSubDerivedItems', SEL_PARENT, 'intValue',
      'loadPriceOffsets:', 'macroTiles', 'objectForKey:']),
    ('Torch', 0x004B5D38, 318, SEL_EXACT, 'DynamicObject',
     ['connectionType', 'dataA', 'dataB', 'itemType', 'lightDict', 'ownerID'],
     ['OBJC_IVAR_$_DynamicObject.cache',
      'OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.ownerID', 'OBJC_IVAR_$_DynamicObject.world',
      'OBJC_IVAR_$_Torch.connectionType', 'OBJC_IVAR_$_Torch.dataA',
      'OBJC_IVAR_$_Torch.dataB', 'OBJC_IVAR_$_Torch.itemType',
      'OBJC_IVAR_$_Torch.light'],
     ['alloc', 'initSubDerivedItems', SEL_PARENT, 'intValue', 'objectForKey:',
      'retain']),
    ('InteractionObject', 0x005F4634, 352, SEL_EXACT, 'DynamicObject',
     ['currentBlockheadIndex', 'flipped', 'isInUse', 'ownerID', 'ownerName',
      'paintColor'],
     ['OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.ownerID',
      'OBJC_IVAR_$_InteractionObject.flipped',
      'OBJC_IVAR_$_InteractionObject.isInUse',
      'OBJC_IVAR_$_InteractionObject.ownerName',
      'OBJC_IVAR_$_InteractionObject.paintColor',
      'OBJC_IVAR_$_InteractionObject.savedBlockheadIndex'],
     ['boolValue', 'getOwnerNameForObjectOwnerID:', 'intValue', 'isServer',
      'objectForKey:', 'retain', 'unsignedIntValue']),
    ('OwnershipSign', 0x00A34B18, 352, SEL_EXACT, 'Sign',
     ['h', 'landOwnerID', 'landOwnerName', 'w'],
     ['OBJC_IVAR_$_OwnershipSign.heightRadius',
      'OBJC_IVAR_$_OwnershipSign.landOwnerID',
      'OBJC_IVAR_$_OwnershipSign.landOwnerName',
      'OBJC_IVAR_$_OwnershipSign.widthRadius'],
     ['autorelease', 'intValue', 'objectForKey:', 'retain', 'updateText']),
    ('Painting', 0x00AA81E8, 358, SEL_EXACT, 'DynamicObject',
     ['hasVerifiedImageData', 'itemType', 'outputImageData', 'ownerID',
      'ownerName'],
     ['OBJC_IVAR_$_DynamicObject.dynamicWorld',
      'OBJC_IVAR_$_DynamicObject.ownerID',
      'OBJC_IVAR_$_Painting.hasVerifiedImageData',
      'OBJC_IVAR_$_Painting.hiddenDueToServerBan',
      'OBJC_IVAR_$_Painting.imageData', 'OBJC_IVAR_$_Painting.itemType',
      'OBJC_IVAR_$_Painting.ownerName'],
     ['boolValue', 'getOwnerNameForObjectOwnerID:', 'initSubDerivedItems',
      'intValue', 'isServer', 'objectForKey:', 'playerIsBannedWithID:',
      'retain']),
    ('TrainCar', 0x00A3892C, 363, SEL_EXACT, 'DynamicObject',
     ['currentBlockheadIndex_%d', 'engineCarID', 'engineIsRight', 'leftCarID',
      'ownerID', 'rightCarID'],
     ['OBJC_IVAR_$_DynamicObject.ownerID',
      'OBJC_IVAR_$_TrainCar.engineIsRight',
      'OBJC_IVAR_$_TrainCar.remoteEngineCarID',
      'OBJC_IVAR_$_TrainCar.remoteLeftCarID',
      'OBJC_IVAR_$_TrainCar.remoteRightCarID',
      'OBJC_IVAR_$_TrainCar.savedBlockheadIndex'],
     ['boolValue', 'loadDerivedStuff', 'maxNumberOfRiders', 'objectForKey:',
      'retain', 'stringWithFormat:', 'unsignedLongLongValue']),
    ('DropBear', 0x0079D538, 404, SEL_EXACT, 'NPC',
     ['courageMeter', 'dropPos.x', 'dropPos.y', 'dropSpeed', 'dropping',
      'goalTreeDirection', 'onGround', 'provokeMeter', 'saveTime'],
     ['OBJC_IVAR_$_DropBear.courageMeter', 'OBJC_IVAR_$_DropBear.dropPos',
      'OBJC_IVAR_$_DropBear.dropSpeed', 'OBJC_IVAR_$_DropBear.dropping',
      'OBJC_IVAR_$_DropBear.goalTreeDirection', 'OBJC_IVAR_$_DropBear.onGround',
      'OBJC_IVAR_$_DropBear.provokeMeter', 'OBJC_IVAR_$_DynamicObject.world',
      'OBJC_IVAR_$_NPC.age'],
     ['boolValue', 'floatValue', 'intValue', 'loadDerivedStuff', 'maxAge',
      'objectForKey:', 'release', 'removeFromMacroBlock', 'worldTime']),
    ('CaveTroll', 0x00D538CC, 408, SEL_EXACT, 'NPC',
     ['dead', 'defendSquare.x', 'defendSquare.y', 'state'],
     ['OBJC_IVAR_$_CaveTroll.defendSquare', 'OBJC_IVAR_$_CaveTroll.fromSquare',
      'OBJC_IVAR_$_CaveTroll.fromTile',
      'OBJC_IVAR_$_CaveTroll.interactingTile', 'OBJC_IVAR_$_CaveTroll.state',
      'OBJC_IVAR_$_CaveTroll.toSquare', 'OBJC_IVAR_$_CaveTroll.toTile',
      'OBJC_IVAR_$_CaveTroll.travelFraction',
      'OBJC_IVAR_$_CaveTroll.travelSpeed',
      'OBJC_IVAR_$_DynamicObject.floatPos', 'OBJC_IVAR_$_DynamicObject.pos',
      'OBJC_IVAR_$_DynamicObject.world', 'OBJC_IVAR_$_NPC.dead'],
     ['boolValue', 'bytes', 'initSubDerivedStuffStuff', 'intValue', 'length',
      'objectForKey:']),
]


def recover(elf):
    out = []
    for cls, imp, words_n, sel, sup_want, own_keys, own_ivars, own_sels \
            in CLASSES:
        row = elf.rows.get(imp)
        if row is None or row[1] != cls or row[3] != sel:
            raise ValueError(f'{cls}: method-map drift')
        boundary = min(i for i in elf.imps if i > imp)
        words = elf.words(imp, boundary)
        if len(words) != words_n:
            raise ValueError(f'{cls}: body length drift {len(words)}')
        if f'{words[0]:08x}' != PUSH or f'{words[1]:08x}' != ADD_FP:
            raise ValueError(f'{cls}: prologue drift')
        frame = [f'{w:08x}' for w in words]
        try:
            epi = frame.index(RET_SUB)
        except ValueError:
            raise ValueError(f'{cls}: epilogue drift (no RET_SUB)')  # noqa: B904
        if frame[epi + 1] != POP:
            raise ValueError(f'{cls}: epilogue drift (no POP)')
        cells = elf.literal_cells(imp, boundary)
        found_keys = {v[1] for v in cells['keys'].values()}
        if found_keys != set(own_keys):
            raise ValueError(f'{cls}: CFString key set drift '
                             f'{sorted(found_keys)} != {sorted(own_keys)}')
        found_ivars = {v[1] for v in cells['ivars'].values()}
        if found_ivars != set(own_ivars):
            raise ValueError(f'{cls}: ivar slot set drift '
                             f'{sorted(found_ivars)} != {sorted(own_ivars)}')
        sels = {n for _, n in cells['selrefs'].values()}
        want_sels = set(own_sels)
        if cls != 'DynamicObject':
            # non-root classes forward one of the selector variants; the
            # forwarded selector may ALSO appear in own_sels when the
            # method's own signature IS the forwarded variant (NormalPlant:
            # long method forwarding the long variant). Gate: the pool must
            # contain at least one of the two variants, and everything in
            # the pool must be accounted for by own_sels + that variant.
            variants = sels & {SEL_EXACT, SEL_LONG}
            if not variants:
                raise ValueError(f'{cls}: selref set drift {sorted(sels)} '
                                 f'(no forwarded selector variant)')
            if not (sels - variants) <= want_sels:
                raise ValueError(f'{cls}: selref set drift {sorted(sels)} '
                                 f'(unexpected '
                                 f'{sorted((sels - variants) - want_sels)})')
        if not want_sels <= sels:
            raise ValueError(f'{cls}: selref set drift {sorted(sels)} '
                             f'(missing own {sorted(want_sels - sels)})')
        got = {n for _, n in cells['got'].values()}
        if got != {'objc_msgSend', 'objc_msgSendSuper2'}:
            raise ValueError(f'{cls}: GOT drift {sorted(got)}')
        cls_names = {n for _, n in cells['classes'].values()}
        want_cls = {f'OBJC_CLASS_$_{cls}'} | EXTRA_CLASSREFS.get(cls, set())
        if cls_names != want_cls:
            raise ValueError(f'{cls}: superref class drift {sorted(cls_names)} '
                             f'!= {sorted(want_cls)}')
        sup_slot = next(iter(cells['classes'].values()))[0]
        runtime_super = elf.super_class_of(elf.rw(sup_slot) or 0)
        if runtime_super != sup_want:
            raise ValueError(f'{cls}: runtime super drift {runtime_super}')
        if not cells['other']:
            raise ValueError(f'{cls}: PIC-base cell missing')
        sel_cells = {n: f'0x{t:08x}' for t, n in cells['selrefs'].values()}
        got_cells = {n: f'0x{t:08x}' for t, n in cells['got'].values()}
        out.append({
            'class': cls, 'imp': f'0x{imp:08x}',
            'boundary': f'0x{boundary:08x}',
            'code_words': len(words), 'selector': sel,
            'runtime_superclass': runtime_super,
            'literal_cells': {
                'super2_got': got_cells['objc_msgSendSuper2'],
                'msgsend_got': got_cells['objc_msgSend'],
                'superref_slot': f'0x{sup_slot:08x}',
                'class_object': f'OBJC_CLASS_$_{cls}',
                'pic_cells': len(cells['other']),
            },
            'own_keys': sorted(own_keys),
            'claim': ('root loader: reads base keys and runs '
                      'initDerivedStuff:loadPhysicalBlockIfNeeded:'
                      if cls == 'DynamicObject' else
                      'super-forwards via objc_msgSendSuper2 (nil guard → '
                      'nil), then reads its own save keys via objectForKey: '
                      'into its own ivar slots; exact '
                      'key/ivar/selector/super sets gated from the pool'),
        })
    return {
        'schema': 1, 'batch': 'b3l', 'elf_sha256': SHA,
        'pic_base': f'0x{BASE:08x}',
        'method': ('fifteen upper-mid-tier initWithWorld loaders incl. the '
                   'chain nodes (batch b3l)'),
        'census': {'front_methods': 60, 'front_words': 13820,
                   'covered_after_b3l': 55,
                   'covered_words_after_b3l': 4521 + 4518,
                   'remaining_methods': 5, 'remaining_words': 4781},
        'classes': out,
        'claim': (
            'Fifteen upper-mid-tier loaders (214-408w, 4,518 words, 71 '
            'own-key reads) including the two chain nodes: DynamicObject '
            '(273w, the ROOT loader — reads pos_x/pos_y/floatPos/uniqueID '
            'and runs initDerivedStuff:loadPhysicalBlockIfNeeded:, no '
            'forward) and InteractionObject (352w — reads '
            'currentBlockheadIndex/flipped/isInUse/ownerID/ownerName/'
            'paintColor, resolves ownerName via '
            'getOwnerNameForObjectOwnerID: with an isServer gate). A THIRD '
            'selector variant initWithWorld:…:parentObject: appears in '
            'GlowBlock/FireObject/NormalPlant/TradePortal/Torch pools — '
            'these construct child LIGHT objects (alloc + the 5-arg '
            'variant) from their lightDict key. TrainCar reads FORMATTED '
            'keys currentBlockheadIndex_%d via stringWithFormat: (per-rider '
            'slots). DropBear is the third saveTime+worldTime site. '
            'CaveTroll parses a byte blob (bytes/length) with a new hook '
            'initSubDerivedStuffStuff. Static level-A evidence only'),
    }


MUTATIONS = [
    ('b3l_shaft_push', 0x00CAD2CC + 0 * 4,
     bytes.fromhex('e92d4df1'), 'ElevatorShaft: prologue drift'),
    ('b3l_glow_push', 0x00CA8920 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'GlowBlock: prologue drift'),
    ('b3l_dynobj_push', 0x00839F7C + 0 * 4,
     bytes.fromhex('e92d4df1'), 'DynamicObject: prologue drift'),
    ('b3l_interact_push', 0x005F4634 + 0 * 4,
     bytes.fromhex('e92d4df1'), 'InteractionObject: prologue drift'),
    ('b3l_traincar_push', 0x00A3892C + 0 * 4,
     bytes.fromhex('e92d4df1'), 'TrainCar: prologue drift'),
    ('b3l_cavetroll_push', 0x00D538CC + 0 * 4,
     bytes.fromhex('e92d4df1'), 'CaveTroll: prologue drift'),
]


def self_test(elf):
    failures = []
    for name, vaddr, patch, expect in MUTATIONS:
        try:
            recover(elf.mutate(vaddr, patch))
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
    print(f'b3l self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--output', type=Path,
                    default=NATIVE / 'uppermid15_initwithworld.json')
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
    print('b3l fifteen upper-mid-tier loaders gated')


if __name__ == '__main__':
    main()
