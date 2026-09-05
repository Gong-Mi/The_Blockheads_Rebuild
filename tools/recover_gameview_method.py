#!/usr/bin/env python3
"""Complete method-to-source map, built from hash-verified original evidence."""
import argparse
import json
import struct
from pathlib import Path
from recover_gameview_update_boundary import recover as recover_update
from trace_objc_dispatch import ELFMemory

PHASES = (
    (0x9259c0,0x925c6c,'entry/time/mode','updateGameView'),
    (0x925c6c,0x926278,'scroll and horizontal query effects','scroll'),
    (0x926278,0x9263e0,'pinch return','pinch + stepPinchReturn'),
    (0x9263e0,0x9266d0,'pinch inertia','pinch'),
    (0x9266d0,0x926a4c,'vertical return','returnTranslation + stepTranslationReturn'),
    (0x926a4c,0x926acc,'initial cap','updateGameView'),
    (0x926acc,0x927ed8,'post-cap settle','settle + stepZoomSettle'),
    (0x927ed8,0x928030,'World forwarding/return/pool','updateGameView'),
)
BINDINGS = {
    'standardUserDefaults':'FrameRuntime::standardUserDefaults',
    'setDouble:forKey:':'FrameDefaults::setDouble',
    'setFloat:forKey:':'saveScale -> FrameDefaults::setFloat',
    'loadComplete':'FrameWorld::loadComplete',
    'isSimulating':'FrameWorld::isSimulating',
    'translatingToGoal':'goal -> FrameWorld::translatingToGoal',
    'takingPhoto':'photo -> FrameWorld::takingPhoto',
    'translation':'translation -> FrameWorld::translation or nil zero',
    'setTranslation:':'FrameWorld::setTranslation',
    'worldWidthMacro':'widthMacro -> FrameWorld::worldWidthMacro',
    'pinchScaleChanged':'FrameRuntime::pinchScaleChanged -> buildProjection',
    'update:accurateDT:pinchScale:dragInProgress:':'FrameWorld::update',
}
HELPERS = {
    'sym.imp.__wrap_fmodf':'FrameRuntime::fmodFloat',
    'sym.imp.memset':'nil zero FrameVector2',
    'method.Vector2.operator_float_':'float vector scalar products',
    'method.Vector2.lengthSquared___const':'float mul/mul/add length squared',
    'method.Vector2.operator__Vector2_':'float vector subtraction',
    'method.Vector2.operator_float__':'local Vector2 component access; discarded wraps keep queries',
}


def recover(path):
    original = recover_update(path)
    mem = ELFMemory(path)
    base = (0x9259d8 + mem.word(0x9268e8)) & 0xffffffff
    key = (base + mem.word(0x9268f8)) & 0xffffffff
    ptr, length = mem.word(key+8), mem.word(key+12)
    off = mem.offset(ptr,length)
    if off is None or mem.data[off:off+length] != b'totalGamePlayTimePassed':
        raise ValueError('time defaults key mismatch')
    divisor = struct.unpack('<f',mem.word(0x925e1c).to_bytes(4,'little'))[0]
    if divisor != 3600.0:
        raise ValueError('fmod divisor mismatch')
    calls=[]
    for c in original['calls']:
        va=int(c['call'],16)
        phase=[p for p in PHASES if p[0]<=va<p[1]]
        if len(phase)!=1:
            raise ValueError('call without unique source phase')
        selector=c['selector_reviewed']
        if selector:
            binding=BINDINGS[selector]
        else:
            label=c.get('disassembly_target_label','').split(' ; ')[0]
            binding=HELPERS[label] # reject unknown/unmapped dependencies
        calls.append({'call':c['call'],'original_selector':selector,
                      'source_owner':phase[0][3],'execution_binding':binding})
    if len(calls)!=80 or len({c['call'] for c in calls})!=80:
        raise ValueError('incomplete original method call inventory')
    if original['reviewed_selector_route_count']!=53:
        raise ValueError('not all ObjC routes recovered')
    return {'original_method':'GameView.update:accurateDT:',
            'verified_original_words':original['verified_words'],
            'phases':[{'start':hex(a),'end_exclusive':hex(b),'scope':n,'source':s}
                      for a,b,n,s in PHASES],
            'objc_calls':53,'non_objc_calls':27,'calls':calls,
            'time_defaults_key':'totalGamePlayTimePassed','fmod_divisor':divisor,
            'source':'reconstruction/recovered/gameview_update.cpp',
            'build_target':'blockheads_recovered_view',
            'executable_dependencies':['pinch_return.cpp','translation_return.cpp','zoom_settle.cpp','projection_update.cpp'],
            'external_interfaces':['FrameWorld','FrameDefaults','FrameRuntime'],
            'game_adapter_integrated':False,'original_runtime_differential_verified':False,
            'contract':'Single-threaded typed method; synchronous callback mutation supported; object lifetimes held by adapter; original ObjC binary ABI and platform libm bit parity not claimed.'}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('elf',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    result=recover(a.elf)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('verified_original_words','objc_calls','non_objc_calls','build_target','game_adapter_integrated')}))


if __name__=='__main__':
    main()
