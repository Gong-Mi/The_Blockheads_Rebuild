#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The World renderer: the 29808w draw giant (92 glVertexAttribPointer, 56
glBindTexture, the depth-mask stack) plus the load/zoom/screenshot family: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 33840 instruction words, from the pinned original libApplication.so
(1.7.6, armeabi-v7a).  Every instruction word is re-verified; tool refuses to
emit on drift.

Verification rules (each one is a claim this file makes about its own evidence):
  * coverage    - the checked-in listing must cover [start, end) exactly once per word,
                  and every word is re-read from the pinned ELF.
  * PIC base    - recomputed from the `add rX, pc, rY` anchor and its pool literal;
                  must equal 0x0105faf4.
  * cells       - selector cells: the slot is base + signed(pool value) and the C string
                  it points at must be the named selector.  Import cells: the slot must be
                  a PLT/GOT slot whose relocation names the import, or - for functions
                  reached through an ABS32 relocation - a relocation whose symbol names
                  it (the route used is recorded per cell).  Ivar cells: the slot
                  holds a pointer to OBJC_IVAR_$_<Class>.<name> in .dynsym plus the
                  offset word.  Class cells: the slot either holds the OBJC_CLASS_$_
                  symbol value (.dynsym) or - for classes imported from the system
                  frameworks - carries an ABS32 relocation whose symbol is the class;
                  both routes are checked, the relocation route is named when used.
  * calls       - the set of bl/blx rows inside the body must equal the spec's set, and
                  every `bl <name>` route's computed target must match ROUTE_TARGETS.
  * branches    - the set of conditional/unconditional b* rows whose destination lands
                  inside the body must equal the spec's set.  Rows outside the body are
                  literal-pool words that mask as branches; they are recorded in
                  `disjoint_branch_rows` instead of being silently dropped.
  * anchors     - the listed instruction texts must match the listing byte for byte.

Machine-generated spec tables + hand-written semantics; see
reconstruction/reverse-v3/native/WORLD_RENDER.md for the prose and boundaries.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl 0x564c54': 0x00564c54,
    'bl 0x582eb4': 0x00582eb4,
    'bl 0x58353c': 0x0058353c,
    'bl 0x58bbd8': 0x0058bbd8,
    'bl 0x5aa3b0': 0x005aa3b0,
    'bl 0x5aa554': 0x005aa554,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.operator_float_': 0x004da9cc,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator__Vector2_': 0x004d04b4,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_': 0x005dd340,
    'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.erase_std::__1::__hash_const_iterator_std::__1::__hash_node_PhysicalBlock__void__const__': 0x005dbdcc,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::__tree_std::__1::pair_int__unsigned_char___std::__1::__map_value_compare_int__unsigned_char__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__unsigned_char_____.clear__': 0x005dc3f8,
    'bl method.std::__1::map_int__unsigned_char__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__unsigned_char_____.operator___int_const_': 0x005a99b8,
    'bl method.std::__1::vector_BlockParticleEmitter__std::__1::allocator_BlockParticleEmitter___.at_unsigned_long_': 0x005aa4d8,
    'bl sym.GLKMathUnproject': 0x0020ca1c,
    'bl sym.UIImagePNGRepresentation': 0x00264ce4,
    'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_': 0x00a14f28,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.drawShaderQuad': 0x007c43dc,
    'bl sym.drawShaderQuadNoTexture': 0x007c4790,
    'bl sym.freezingLevelForWorldX_int__float__float__float__World_': 0x00a151d0,
    'bl sym.getStarPoints__': 0x005aa394,
    'bl sym.imp.CGColorSpaceCreateDeviceRGB': 0x001c311c,
    'bl sym.imp.CGColorSpaceRelease': 0x001c2f18,
    'bl sym.imp.CGDataProviderCreateWithData': 0x001c3428,
    'bl sym.imp.CGDataProviderRelease': 0x001c3fbc,
    'bl sym.imp.CGImageCreate': 0x001c3434,
    'bl sym.imp.NSSearchPathForDirectoriesInDomains': 0x001c3f20,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.__wrap_glActiveTexture': 0x001c2dc8,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glBlendFunc': 0x001c3fa4,
    'bl sym.imp.__wrap_glClear': 0x001c2a74,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glDrawArrays': 0x001c2ccc,
    'bl sym.imp.__wrap_glDrawElements': 0x001c2df8,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glPixelStorei': 0x001c3fd4,
    'bl sym.imp.__wrap_glReadPixels': 0x001c3fe0,
    'bl sym.imp.__wrap_glUniform1f': 0x001c3fb0,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.__wrap_glVertexAttribPointer': 0x001c2dec,
    'bl sym.imp.__wrap_glViewport': 0x001c2a8c,
    'bl sym.imp.__wrap_malloc': 0x001c2e58,
    'bl sym.imp.__wrap_powf': 0x001c3f98,
    'bl sym.imp.floor': 0x001c323c,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.imp.tanf': 0x001c3dc4,
    'bl sym.linearInterpolate_float__float__float_': 0x00582a14,
    'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_': 0x00a1770c,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.popDepthTestState': 0x007c5438,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.pushDepthTestState': 0x007c5238,
    'bl sym.reverseLinearInterpolate_float__float__float_': 0x005ac12c,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='wd_00',
        method='World -[render:cameraZ:projectionMatrix:pinchScale:]',
        types='v84@0:4f8f12(_GLKMatrix4={?=ffffffffffffffff}[16f])16f80',
        start=5818360,
        end=5937592,
        disasm='disasm_worldtileloader_wd_00.txt',
        base_add=5818460,
        base_literal=5821952,
        boundary='ARM.exidx end 0x005a99b8 (listing bound); next ObjC IMP 0x005aa5c8 World -[zoomUIToOnscreen:dimensions:]',
        selectors={
                 0x58d60c: (15197172, 'doPortalScreenshot'),
                 0x58d610: (15197176, 'cameraZOffset'),
                 0x58d614: (15196444, 'activeBlockhead'),
                 0x58de50: (15195604, 'count'),
                 0x58e120: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x58e124: (15195628, 'paused'),
                 0x58e128: (15195624, 'objectForKey:'),
                 0x58e12c: (15195616, 'gameBlockingUIDisplayed'),
                 0x58e140: (15197180, 'setSoundPaused:'),
                 0x58e5a8: (15197184, 'mapDisplayed'),
                 0x58eb04: (15197188, 'preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:'),
                 0x58eb10: (15197192, 'reloadDrawBlock:world:waterAnimationIndex:slowAnimationIndex:mapPixelData:skyPixelData:'),
                 0x58eb30: (15197196, 'operationCount'),
                 0x58eb40: (15197220, 'addOperationWithBlock:'),
                 0x58eb58: (15197224, 'preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x58fc78: (15197228, 'program'),
                 0x58fc84: (15195848, 'intValue'),
                 0x58fc88: (15195800, 'objectAtIndex:'),
                 0x58fc8c: (15197232, 'uniformLocations'),
                 0x58fc90: (15196044, 'name'),
                 0x59113c: (15195848, 'intValue'),
                 0x591140: (15195800, 'objectAtIndex:'),
                 0x591144: (15197232, 'uniformLocations'),
                 0x591e10: (15196044, 'name'),
                 0x592824: (15197068, 'getWeatherFractionForPos:atWorldTime:ignoreSandFraction:'),
                 0x592834: (15197236, 'renderCloudWithMatrix:translation:dt:weatherFraction:futureWeatherFraction:timeOfDayFraction:'),
                 0x592b44: (15197228, 'program'),
                 0x593180: (15195848, 'intValue'),
                 0x593184: (15195800, 'objectAtIndex:'),
                 0x593188: (15197232, 'uniformLocations'),
                 0x593190: (15197240, 'windStrength'),
                 0x593b98: (15195544, 'instance'),
                 0x593b9c: (15197032, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0x593ba8: (15196044, 'name'),
                 0x593bc8: (15197232, 'uniformLocations'),
                 0x593bcc: (15195800, 'objectAtIndex:'),
                 0x593bd0: (15195848, 'intValue'),
                 0x595974: (15195800, 'objectAtIndex:'),
                 0x595978: (15195848, 'intValue'),
                 0x595e3c: (15197232, 'uniformLocations'),
                 0x596914: (15197228, 'program'),
                 0x596924: (15196044, 'name'),
                 0x597e5c: (15195848, 'intValue'),
                 0x597e60: (15195800, 'objectAtIndex:'),
                 0x597e64: (15197232, 'uniformLocations'),
                 0x5986a4: (15197228, 'program'),
                 0x5992c8: (15196044, 'name'),
                 0x599454: (15197232, 'uniformLocations'),
                 0x599458: (15195800, 'objectAtIndex:'),
                 0x59945c: (15195848, 'intValue'),
                 0x59aee8: (15197232, 'uniformLocations'),
                 0x59aeec: (15195800, 'objectAtIndex:'),
                 0x59aef0: (15195848, 'intValue'),
                 0x59bed0: (15197228, 'program'),
                 0x59bef8: (15197244, 'drawOpaqueObjects:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:'),
                 0x59befc: (15197248, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:'),
                 0x59dab4: (15197252, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x59dabc: (15195848, 'intValue'),
                 0x59dac0: (15195800, 'objectAtIndex:'),
                 0x59dac4: (15197232, 'uniformLocations'),
                 0x59e74c: (15196044, 'name'),
                 0x59e79c: (15195848, 'intValue'),
                 0x59e7a0: (15195800, 'objectAtIndex:'),
                 0x59e7a4: (15197232, 'uniformLocations'),
                 0x5a0c70: (15195848, 'intValue'),
                 0x5a0c74: (15195800, 'objectAtIndex:'),
                 0x5a0c78: (15197232, 'uniformLocations'),
                 0x5a1290: (15197256, 'drawFreeBlocks:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:'),
                 0x5a1294: (15197228, 'program'),
                 0x5a12a0: (15196044, 'name'),
                 0x5a29c0: (15197240, 'windStrength'),
                 0x5a3310: (15197260, 'renderWithMatrix:pinchScale:withDayColor:rainFraction:snowFraction:snowLevel:'),
                 0x5a331c: (15195544, 'instance'),
                 0x5a3330: (15197264, 'windMovement'),
                 0x5a3334: (15197268, 'renderAndUpdate:pinchScale:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:windMovement:'),
                 0x5a3dfc: (15197228, 'program'),
                 0x5a3e04: (15195848, 'intValue'),
                 0x5a3e08: (15195800, 'objectAtIndex:'),
                 0x5a3e0c: (15197232, 'uniformLocations'),
                 0x5a3e10: (15196044, 'name'),
                 0x5a6260: (15197272, 'drawInFrontOfBlocksObjects:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:'),
                 0x5a6290: (15197228, 'program'),
                 0x5a6298: (15195848, 'intValue'),
                 0x5a629c: (15195800, 'objectAtIndex:'),
                 0x5a62a0: (15197232, 'uniformLocations'),
                 0x5a62a4: (15196044, 'name'),
                 0x5a7410: (15197276, 'render:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:ownershipSignPositions:hideUIType:'),
                 0x5a8a04: (15195848, 'intValue'),
                 0x5a8a08: (15195800, 'objectAtIndex:'),
                 0x5a8a0c: (15197232, 'uniformLocations'),
                 0x5a8a30: (15197280, 'drawBlockheadBoxes:projectionMatrix:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x5a8a34: (15197228, 'program'),
                 0x5a9978: (15196044, 'name'),
                 0x5a997c: (15195848, 'intValue'),
                 0x5a9980: (15195800, 'objectAtIndex:'),
                 0x5a9984: (15197232, 'uniformLocations'),
                 0x5a9988: (15197228, 'program'),
                 0x5a9994: (15197288, 'maxT'),
                 0x5a999c: (15197284, 'maxS'),
                 0x5a99b0: (15197292, 'render:projectionMatrix:cameraZ:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:pinchScale:mapAlpha:'),
                 0x5a99b4: (15197296, 'exportCurrentFrame'),
        },
        imports={
                 0x58d608: (17151904, 'objc_msgSend'),
                 0x58eb50: (17151928, '_NSConcreteStackBlock'),
                 0x58eb54: (17151904, 'objc_msgSend'),
                 0x5906cc: (17151904, 'objc_msgSend'),
                 0x592b40: (17151904, 'objc_msgSend'),
                 0x595e44: (17151904, 'objc_msgSend'),
                 0x597e58: (17151904, 'objc_msgSend'),
                 0x59becc: (17151904, 'objc_msgSend'),
                 0x59dab8: (17151904, 'objc_msgSend'),
                 0x59e798: (17151904, 'objc_msgSend'),
                 0x5a0c6c: (17151904, 'objc_msgSend'),
                 0x5a29bc: (17151904, 'objc_msgSend'),
                 0x5a4518: (17151904, 'objc_msgSend'),
                 0x5a628c: (17151904, 'objc_msgSend'),
                 0x5a8a00: (17151904, 'objc_msgSend'),
                 0x5a9954: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x58d604: (17156500, 'OBJC_IVAR_$_World.needsToDoPortalScreenshot', 3073),
                 0x58d618: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x58d61c: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x58d620: (17156596, 'OBJC_IVAR_$_World.smoothedCameraZOffset', 3320),
                 0x58de40: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x58de44: (17156600, 'OBJC_IVAR_$_World.tapModelviewMatrix', 320),
                 0x58de48: (17156604, 'OBJC_IVAR_$_World.tapProjectionMatrix', 256),
                 0x58de4c: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x58de54: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x58e0fc: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x58e130: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x58e134: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x58e138: (17155984, 'OBJC_IVAR_$_World.serverReportsAllPaused', 3088),
                 0x58e13c: (17156456, 'OBJC_IVAR_$_World.connectionToServerLost', 968),
                 0x58e144: (17156144, 'OBJC_IVAR_$_World.weather', 156),
                 0x58e5a4: (17155960, 'OBJC_IVAR_$_World.fastForward', 934),
                 0x58e5ac: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x58e5b0: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x58e928: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x58e92c: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x58ea68: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x58eb08: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x58eb0c: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x58eb14: (17156224, 'OBJC_IVAR_$_World.skyPixelData', 912),
                 0x58eb18: (17156228, 'OBJC_IVAR_$_World.mapPixelData', 3184),
                 0x58eb1c: (17156580, 'OBJC_IVAR_$_World.slowAnimationIndex', 1016),
                 0x58eb20: (17156572, 'OBJC_IVAR_$_World.waterAnimationIndex', 1008),
                 0x58eb28: (17156624, 'OBJC_IVAR_$_World.latestMapData', 3192),
                 0x58eb2c: (17156628, 'OBJC_IVAR_$_World.mapUpdateTimer', 944),
                 0x58eb34: (17156308, 'OBJC_IVAR_$_World.saveQueue', 3188),
                 0x58eb5c: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x58eb60: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x58eb64: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x58eb68: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x58eb6c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x58eb70: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x58fbd8: (17156520, 'OBJC_IVAR_$_World.backgroundYOffset', 884),
                 0x58fc7c: (17156124, 'OBJC_IVAR_$_World.skyShader', 568),
                 0x58fc80: (17156552, 'OBJC_IVAR_$_World.timeOfDayFraction', 880),
                 0x58fc94: (17156116, 'OBJC_IVAR_$_World.skyTexture', 528),
                 0x58fc98: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x5906c0: (17156540, 'OBJC_IVAR_$_World.cloudFraction', 928),
                 0x5906c4: (17156528, 'OBJC_IVAR_$_World.relativeSunDirection', 676),
                 0x5906d0: (17156200, 'OBJC_IVAR_$_World.starShader', 600),
                 0x5906d4: (17156548, 'OBJC_IVAR_$_World.starsMvpMatrix', 816),
                 0x59112c: (17156208, 'OBJC_IVAR_$_World.standardObjectColoredShader', 584),
                 0x591130: (17156584, 'OBJC_IVAR_$_World.sunMvpMatrix', 688),
                 0x591134: (17156184, 'OBJC_IVAR_$_World.sunTexture', 540),
                 0x591138: (17156588, 'OBJC_IVAR_$_World.moonMvpMatrix', 752),
                 0x591e14: (17156180, 'OBJC_IVAR_$_World.moonTexture', 544),
                 0x591e18: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x591e1c: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x591e24: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x592820: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x592828: (17156144, 'OBJC_IVAR_$_World.weather', 156),
                 0x59282c: (17156544, 'OBJC_IVAR_$_World.weatherFraction', 916),
                 0x592830: (17156552, 'OBJC_IVAR_$_World.timeOfDayFraction', 880),
                 0x592b48: (17156212, 'OBJC_IVAR_$_World.blackCubeShader', 596),
                 0x592b4c: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x592b50: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x592b54: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x592b58: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x592da8: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x592dac: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x59318c: (17156248, 'OBJC_IVAR_$_World.drawBlockIndices', 500),
                 0x593ba0: (17156172, 'OBJC_IVAR_$_World.blockShader', 572),
                 0x593ba4: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x593bac: (17156136, 'OBJC_IVAR_$_World.tileMapTexture', 524),
                 0x593bb0: (17156188, 'OBJC_IVAR_$_World.tileDestructTexture', 564),
                 0x593bb4: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x593bbc: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x593bc0: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x593bd4: (17156248, 'OBJC_IVAR_$_World.drawBlockIndices', 500),
                 0x59596c: (17156172, 'OBJC_IVAR_$_World.blockShader', 572),
                 0x59597c: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x595e34: (17156248, 'OBJC_IVAR_$_World.drawBlockIndices', 500),
                 0x596908: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x59690c: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x596910: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x596918: (17156164, 'OBJC_IVAR_$_World.staticDrawCubeShader', 604),
                 0x59691c: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x596920: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x596928: (17156136, 'OBJC_IVAR_$_World.tileMapTexture', 524),
                 0x59692c: (17156188, 'OBJC_IVAR_$_World.tileDestructTexture', 564),
                 0x596930: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x596934: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x596938: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x59693c: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x596944: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x596950: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x596954: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x59695c: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x59869c: (17156164, 'OBJC_IVAR_$_World.staticDrawCubeShader', 604),
                 0x5986a0: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5986a8: (17156168, 'OBJC_IVAR_$_World.blockTransparentShader', 576),
                 0x5986ac: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x5992cc: (17156136, 'OBJC_IVAR_$_World.tileMapTexture', 524),
                 0x59942c: (17156188, 'OBJC_IVAR_$_World.tileDestructTexture', 564),
                 0x599430: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x599434: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x599438: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x59943c: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x599440: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x599444: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x599448: (17156248, 'OBJC_IVAR_$_World.drawBlockIndices', 500),
                 0x599450: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x599460: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x599468: (17156168, 'OBJC_IVAR_$_World.blockTransparentShader', 576),
                 0x59aedc: (17156248, 'OBJC_IVAR_$_World.drawBlockIndices', 500),
                 0x59aee0: (17156168, 'OBJC_IVAR_$_World.blockTransparentShader', 576),
                 0x59aef4: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x59b9ec: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x59b9f0: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x59b9f4: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x59b9f8: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x59be9c: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x59bec0: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x59bec8: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x59bed4: (17156164, 'OBJC_IVAR_$_World.staticDrawCubeShader', 604),
                 0x59bed8: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x59bee0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x59bee4: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x59bee8: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x59beec: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x59bef0: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x59bef4: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x59dab0: (17156252, 'OBJC_IVAR_$_World.projectileManager', 3204),
                 0x59dac8: (17156164, 'OBJC_IVAR_$_World.staticDrawCubeShader', 604),
                 0x59e4bc: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x59e750: (17156192, 'OBJC_IVAR_$_World.itemsTexture', 548),
                 0x59e754: (17156128, 'OBJC_IVAR_$_World.itemNormalsTexture', 552),
                 0x59e758: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x59e75c: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x59e760: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x59e764: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x59e768: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x59e774: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x59e778: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x59e780: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x59e784: (17156136, 'OBJC_IVAR_$_World.tileMapTexture', 524),
                 0x59e788: (17156188, 'OBJC_IVAR_$_World.tileDestructTexture', 564),
                 0x59e7a8: (17156164, 'OBJC_IVAR_$_World.staticDrawCubeShader', 604),
                 0x5a0220: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5a0228: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5a0c7c: (17156164, 'OBJC_IVAR_$_World.staticDrawCubeShader', 604),
                 0x5a1274: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5a127c: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x5a1280: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x5a1284: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x5a1288: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x5a128c: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x5a1298: (17156168, 'OBJC_IVAR_$_World.blockTransparentShader', 576),
                 0x5a129c: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x5a12a4: (17156136, 'OBJC_IVAR_$_World.tileMapTexture', 524),
                 0x5a12ac: (17156188, 'OBJC_IVAR_$_World.tileDestructTexture', 564),
                 0x5a1c24: (17156160, 'OBJC_IVAR_$_World.dodoEggShader', 608),
                 0x5a1e84: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x5a1e88: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x5a1e8c: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x5a1e90: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x5a1e94: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5a1ea0: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x5a1ea4: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5a1eac: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5a29b8: (17156536, 'OBJC_IVAR_$_World.rainFraction', 920),
                 0x5a29c4: (17156144, 'OBJC_IVAR_$_World.weather', 156),
                 0x5a29c8: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
                 0x5a29d0: (17156552, 'OBJC_IVAR_$_World.timeOfDayFraction', 880),
                 0x5a29d4: (17156544, 'OBJC_IVAR_$_World.weatherFraction', 916),
                 0x5a330c: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x5a3320: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x5a3324: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x5a3328: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x5a332c: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x5a3e00: (17156168, 'OBJC_IVAR_$_World.blockTransparentShader', 576),
                 0x5a3e14: (17156136, 'OBJC_IVAR_$_World.tileMapTexture', 524),
                 0x5a3e18: (17156188, 'OBJC_IVAR_$_World.tileDestructTexture', 564),
                 0x5a3e1c: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x5a3e20: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x5a3e24: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x5a3e28: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x5a3e2c: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5a3e30: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x5a3e34: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5a4514: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5a451c: (17156248, 'OBJC_IVAR_$_World.drawBlockIndices', 500),
                 0x5a4520: (17156164, 'OBJC_IVAR_$_World.staticDrawCubeShader', 604),
                 0x5a5a5c: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5a5a64: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5a5a68: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x5a5a6c: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x5a5a70: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x5a5a74: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x5a6254: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x5a6258: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x5a625c: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x5a6284: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x5a6288: (17156552, 'OBJC_IVAR_$_World.timeOfDayFraction', 880),
                 0x5a6294: (17156156, 'OBJC_IVAR_$_World.lightsShader', 612),
                 0x5a62a8: (17156176, 'OBJC_IVAR_$_World.lightTexture', 556),
                 0x5a62ac: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x5a62b0: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x5a62b4: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x5a62b8: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x5a69bc: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5a69c8: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x5a69d0: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5a7240: (17156372, 'OBJC_IVAR_$_World.ownershipAreaRenderer', 3332),
                 0x5a740c: (17155948, 'OBJC_IVAR_$_World.ownershipSignPositions', 3324),
                 0x5a7414: (17156220, 'OBJC_IVAR_$_World.buttonShader', 580),
                 0x5a7418: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5a7bf8: (17156248, 'OBJC_IVAR_$_World.drawBlockIndices', 500),
                 0x5a7bfc: (17156216, 'OBJC_IVAR_$_World.blackTileShader', 592),
                 0x5a828c: (17156608, 'OBJC_IVAR_$_World.cameraMinYMacro', 3036),
                 0x5a8290: (17156620, 'OBJC_IVAR_$_World.cameraMaxYMacro', 3040),
                 0x5a8294: (17156612, 'OBJC_IVAR_$_World.cameraMinXMacro', 3028),
                 0x5a8298: (17156616, 'OBJC_IVAR_$_World.cameraMaxXMacro', 3032),
                 0x5a8a10: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x5a8a14: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5a8a1c: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5a8a20: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x5a8a24: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x5a8a28: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x5a8a2c: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x5a8a38: (17156212, 'OBJC_IVAR_$_World.blackCubeShader', 596),
                 0x5a8a3c: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5a8a40: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
                 0x5a9958: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5a995c: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5a9960: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5a9964: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x5a9968: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x5a996c: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x5a9970: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x5a9974: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x5a998c: (17156648, 'OBJC_IVAR_$_World.repairMode', 3413),
                 0x5a9990: (17156652, 'OBJC_IVAR_$_World.renderRepairModeConfirm', 3414),
                 0x5a9998: (17156120, 'OBJC_IVAR_$_World.repairBoxTexture', 560),
                 0x5a99a0: (17156204, 'OBJC_IVAR_$_World.standardObjectShader', 588),
                 0x5a99a8: (17156656, 'OBJC_IVAR_$_World.repairModeConfirmPos', 3416),
        },
        classes={
                 0x58eb24: (15245460, 'OBJC_CLASS_$_WorldHelper'),
                 0x593b90: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
                 0x5a3314: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(5818360, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5937588, 'invalid')],
        calls=[(5819112, 'blx r2'), (5819400, 'blx r2'), (5819424, 'blx r2'), (5819488, 'bl sym.clamp_float__float__float_'), (5819996, 'bl sym.clamp_float__float__float_'), (5820100, 'bl sym.imp.memcpy'), (5820164, 'bl method.Vector2.operator_float__'), (5820220, 'bl method.Vector2.operator_float__'), (5820324, 'bl method.Vector2.operator_float__'), (5820380, 'bl method.Vector2.operator_float__'), (5820472, 'bl 0x582eb4'), (5820548, 'bl sym.imp.memcpy'), (5820700, 'blx r2'), (5820840, 'bl sym.imp.memset'), (5820944, 'blx lr'), (5821108, 'bl sym.imp.objc_enumerationMutation'), (5821264, 'blx ip'), (5821304, 'blx r3'), (5821484, 'blx ip'), (5821608, 'blx r2'), (5821924, 'blx lr'), (5822144, 'blx r2'), (5822200, 'blx r3'), (5822508, 'bl sym.clamp_float__float__float_'), (5822652, 'bl sym.clamp_float__float__float_'), (5822720, 'bl method.Vector2.operator_float__'), (5822768, 'bl sym.imp.floor'), (5822840, 'bl method.Vector2.operator_float__'), (5822884, 'bl sym.imp.floor'), (5822972, 'bl method.Vector2.operator_float__'), (5823016, 'bl sym.imp.floor'), (5823088, 'bl method.Vector2.operator_float__'), (5823132, 'bl sym.imp.floor'), (5823732, 'bl loc.imp.objc_msgSend'), (5824528, 'blx ip'), (5824608, 'bl method.std::__1::map_int__unsigned_char__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__unsigned_char_____.operator___int_const_'), (5824656, 'bl sym.imp.__wrap_free'), (5824716, 'bl method.std::__1::map_int__unsigned_char__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__unsigned_char_____.operator___int_const_'), (5825016, 'blx r2'), (5825676, 'bl sym.imp.__modsi3'), (5825720, 'bl sym.imp.__aeabi_idiv'), (5825884, 'blx r6'), (5825936, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (5826020, 'bl method.std::__1::__tree_std::__1::pair_int__unsigned_char___std::__1::__map_value_compare_int__unsigned_char__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__unsigned_char_____.clear__'), (5826032, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5826040, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5826048, 'bl sym.imp.__wrap_glDisable'), (5826060, 'bl sym.pushDepthMaskState'), (5826292, 'blx lr'), (5826416, 'bl method.Vector2.operator_float__'), (5826532, 'bl sym.clamp_float__float__float_'), (5826580, 'bl method.Vector2.operator_float__'), (5827008, 'bl sym.imp.__wrap_powf'), (5827524, 'bl sym.imp.__wrap_powf'), (5827768, 'bl 0x582eb4'), (5828880, 'bl 0x58bbd8'), (5829000, 'blx r2'), (5829004, 'bl sym.imp.__wrap_glUseProgram'), (5829192, 'blx r3'), (5829224, 'blx r3'), (5829248, 'blx r2'), (5829300, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5829476, 'blx r6'), (5829508, 'blx r3'), (5829532, 'blx r2'), (5829544, 'bl sym.imp.__wrap_glUniform1i'), (5829644, 'blx r3'), (5829676, 'bl sym.imp.__wrap_glBindTexture'), (5829720, 'bl method.Vector.Vector_float__float__float_'), (5829864, 'bl method.Vector.operator_float__'), (5829968, 'bl method.Vector.operator_float__'), (5830072, 'bl method.Vector.operator_float__'), (5830120, 'bl method.Vector.operator_float_'), (5830340, 'blx r5'), (5830372, 'blx r3'), (5830396, 'blx r2'), (5830420, 'bl method.Vector.operator_float__'), (5830448, 'bl method.Vector.operator_float__'), (5830476, 'bl method.Vector.operator_float__'), (5830708, 'bl sym.imp.__wrap_glUniform4f'), (5830876, 'bl sym.drawShaderQuad'), (5830996, 'bl sym.clamp_float__float__float_'), (5831184, 'bl sym.clamp_float__float__float_'), (5831384, 'bl sym.clamp_float__float__float_'), (5831916, 'bl sym.pushDepthMaskState'), (5831924, 'bl sym.imp.__wrap_glEnable'), (5831948, 'bl sym.imp.__wrap_glBlendFunc'), (5832032, 'blx r2'), (5832036, 'bl sym.imp.__wrap_glUseProgram'), (5832224, 'blx ip'), (5832256, 'blx r3'), (5832280, 'blx r2'), (5832352, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5832504, 'blx r5'), (5832536, 'blx r3'), (5832560, 'blx r2'), (5832580, 'bl sym.imp.__wrap_glUniform1f'), (5832584, 'bl sym.getStarPoints__'), (5832648, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5832676, 'bl sym.imp.__wrap_glDrawArrays'), (5832688, 'bl sym.imp.__wrap_glBlendFunc'), (5832696, 'bl sym.imp.__wrap_glDisable'), (5832700, 'bl sym.popDepthMaskState'), (5832784, 'blx r2'), (5832788, 'bl sym.imp.__wrap_glUseProgram'), (5832976, 'blx r3'), (5833008, 'blx r3'), (5833032, 'blx r2'), (5833084, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5833260, 'blx r6'), (5833292, 'blx r3'), (5833316, 'blx r2'), (5833328, 'bl sym.imp.__wrap_glUniform1i'), (5833428, 'blx r3'), (5833460, 'bl sym.imp.__wrap_glBindTexture'), (5833504, 'bl method.Vector.Vector_float__float__float_'), (5833688, 'bl method.Vector.operator_float__'), (5833792, 'bl method.Vector.operator_float__'), (5833896, 'bl method.Vector.operator_float__'), (5833944, 'bl method.Vector.operator_float_'), (5834164, 'blx r5'), (5834196, 'blx r3'), (5834220, 'blx r2'), (5834244, 'bl method.Vector.operator_float__'), (5834272, 'bl method.Vector.operator_float__'), (5834300, 'bl method.Vector.operator_float__'), (5834580, 'bl sym.imp.__wrap_glUniform4f'), (5834780, 'bl sym.drawShaderQuad'), (5834816, 'bl sym.imp.__wrap_glEnable'), (5834840, 'bl sym.imp.__wrap_glBlendFunc'), (5834924, 'blx r2'), (5834928, 'bl sym.imp.__wrap_glUseProgram'), (5835140, 'blx ip'), (5835172, 'blx r3'), (5835196, 'blx r2'), (5835268, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5835448, 'blx r6'), (5835480, 'blx r3'), (5835504, 'blx r2'), (5835528, 'bl method.Vector.operator_float__'), (5835572, 'bl method.Vector.operator_float__'), (5835616, 'bl method.Vector.operator_float__'), (5835688, 'bl sym.imp.__wrap_glUniform4f'), (5835788, 'blx r3'), (5835820, 'bl sym.imp.__wrap_glBindTexture'), (5835944, 'bl sym.drawShaderQuad'), (5836164, 'blx ip'), (5836196, 'blx r3'), (5836220, 'blx r2'), (5836292, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5836472, 'blx r6'), (5836504, 'blx r3'), (5836528, 'blx r2'), (5836552, 'bl method.Vector.operator_float__'), (5836596, 'bl method.Vector.operator_float__'), (5836640, 'bl method.Vector.operator_float__'), (5836712, 'bl sym.imp.__wrap_glUniform4f'), (5836812, 'blx r3'), (5836844, 'bl sym.imp.__wrap_glBindTexture'), (5836968, 'bl sym.drawShaderQuad'), (5836980, 'bl sym.imp.__wrap_glBlendFunc'), (5837488, 'bl 0x5aa3b0'), (5837536, 'bl method.Vector2.operator_float__'), (5837584, 'bl method.Vector2.operator_float__'), (5837684, 'bl method.Vector2.operator_float__'), (5837728, 'bl method.Vector2.operator_float__'), (5837820, 'bl 0x582eb4'), (5838932, 'bl 0x58bbd8'), (5838972, 'bl method.Vector2.operator_float__'), (5839024, 'bl method.Vector2.operator_float__'), (5839056, 'bl sym.makeIntpair_int__int_'), (5839164, 'bl loc.imp.objc_msgSend'), (5839888, 'bl loc.imp.objc_msgSend'), (5839900, 'bl sym.imp.__wrap_glDisable'), (5839912, 'bl sym.pushDepthTestState'), (5839996, 'blx r2'), (5840000, 'bl sym.imp.__wrap_glUseProgram'), (5840008, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5840016, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5840024, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5840032, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5840804, 'bl method.Vector2.operator_float__'), (5840864, 'bl method.Vector2.operator_float__'), (5840984, 'bl method.Vector2.operator_float__'), (5841044, 'bl method.Vector2.operator_float__'), (5841156, 'bl 0x582eb4'), (5842268, 'bl 0x58bbd8'), (5842456, 'blx r3'), (5842488, 'blx r3'), (5842512, 'blx r2'), (5842564, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5842628, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5842724, 'bl sym.imp.__wrap_glDrawElements'), (5842776, 'bl sym.imp.__aeabi_idiv'), (5842880, 'bl sym.imp.__aeabi_idiv'), (5842900, 'bl 0x564c54'), (5843052, 'bl sym.imp.__modsi3'), (5843112, 'bl method.std::__1::vector_BlockParticleEmitter__std::__1::allocator_BlockParticleEmitter___.at_unsigned_long_'), (5843148, 'bl sym.imp.memcpy'), (5843284, 'blx r2'), (5843360, 'bl 0x564c54'), (5843580, 'blx r2'), (5843720, 'bl 0x564c54'), (5843728, 'bl sym.imp.__modsi3'), (5843960, 'bl sym.makeIntpair_int__int_'), (5844024, 'bl method.Vector.Vector__'), (5844048, 'bl method.Vector.Vector__'), (5844080, 'bl 0x564c54'), (5844164, 'bl 0x564c54'), (5844240, 'bl method.Vector.Vector_float__float__float_'), (5844336, 'bl method.Vector.Vector_float__float__float_'), (5844424, 'bl 0x564c54'), (5844476, 'bl 0x564c54'), (5844528, 'bl 0x564c54'), (5844604, 'bl method.Vector.Vector_float__float__float_'), (5844700, 'bl method.Vector.Vector_float__float__float_'), (5844788, 'bl loc.imp.objc_msgSend'), (5844924, 'bl 0x564c54'), (5845240, 'bl loc.imp.objc_msgSend'), (5845480, 'blx r2'), (5845484, 'bl sym.imp.__wrap_glUseProgram'), (5845660, 'blx r6'), (5845692, 'blx r3'), (5845716, 'blx r2'), (5845728, 'bl sym.imp.__wrap_glUniform1i'), (5845904, 'blx r6'), (5845936, 'blx r3'), (5845960, 'blx r2'), (5845972, 'bl sym.imp.__wrap_glUniform1i'), (5846148, 'blx r6'), (5846180, 'blx r3'), (5846204, 'blx r2'), (5846216, 'bl sym.imp.__wrap_glUniform1i'), (5846368, 'blx r2'), (5846400, 'blx r3'), (5846424, 'blx r2'), (5846468, 'bl method.Vector.operator_float__'), (5846524, 'bl method.Vector.operator_float__'), (5846580, 'bl method.Vector.operator_float__'), (5846636, 'bl method.Vector.operator_float__'), (5846696, 'bl sym.imp.__wrap_glUniform4f'), (5846704, 'bl sym.imp.__wrap_glActiveTexture'), (5846804, 'blx r3'), (5846836, 'bl sym.imp.__wrap_glBindTexture'), (5846844, 'bl sym.imp.__wrap_glActiveTexture'), (5846944, 'blx r3'), (5846976, 'bl sym.imp.__wrap_glBindTexture'), (5846984, 'bl sym.imp.__wrap_glActiveTexture'), (5846992, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5847000, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5847008, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5847016, 'bl sym.imp.__wrap_glDisable'), (5847220, 'bl method.Vector.Vector_float__float__float_'), (5847312, 'bl method.Vector.Vector_float__float__float_'), (5847412, 'bl method.Vector.Vector_float__float__float_'), (5847528, 'bl method.Vector.Vector_float__float__float_'), (5848324, 'bl sym.imp.__wrap_glBindTexture'), (5848428, 'bl method.Vector2.operator_float__'), (5848488, 'bl method.Vector2.operator_float__'), (5848608, 'bl method.Vector2.operator_float__'), (5848668, 'bl method.Vector2.operator_float__'), (5848792, 'bl 0x582eb4'), (5849916, 'bl 0x58bbd8'), (5849964, 'bl loc.imp.objc_msgSend'), (5849992, 'bl loc.imp.objc_msgSend'), (5850012, 'bl loc.imp.objc_msgSend'), (5850036, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5850208, 'bl loc.imp.objc_msgSend'), (5850244, 'bl loc.imp.objc_msgSend'), (5850264, 'bl loc.imp.objc_msgSend'), (5850296, 'bl method.Vector.operator_float__'), (5850376, 'bl method.Vector2.operator_float__'), (5850424, 'bl method.Vector.operator_float__'), (5850488, 'bl method.Vector2.operator_float__'), (5850536, 'bl method.Vector.operator_float__'), (5850588, 'bl sym.imp.__wrap_glUniform4f'), (5850680, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5850776, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5850856, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5850936, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5851028, 'bl sym.imp.__wrap_glDrawElements'), (5851212, 'bl loc.imp.objc_msgSend'), (5851248, 'bl loc.imp.objc_msgSend'), (5851268, 'bl loc.imp.objc_msgSend'), (5851348, 'bl method.Vector2.operator_float__'), (5851392, 'bl method.Vector.operator_float__'), (5851456, 'bl method.Vector2.operator_float__'), (5851532, 'bl sym.imp.__wrap_glUniform4f'), (5851624, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5851720, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5851800, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5851880, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5851972, 'bl sym.imp.__wrap_glDrawElements'), (5852156, 'bl loc.imp.objc_msgSend'), (5852192, 'bl loc.imp.objc_msgSend'), (5852212, 'bl loc.imp.objc_msgSend'), (5852292, 'bl method.Vector2.operator_float__'), (5852336, 'bl method.Vector.operator_float__'), (5852400, 'bl method.Vector2.operator_float__'), (5852476, 'bl sym.imp.__wrap_glUniform4f'), (5852568, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5852664, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5852744, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5852824, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5852916, 'bl sym.imp.__wrap_glDrawElements'), (5853048, 'bl sym.imp.__wrap_glActiveTexture'), (5853104, 'bl loc.imp.objc_msgSend'), (5853140, 'bl loc.imp.objc_msgSend'), (5853160, 'bl loc.imp.objc_msgSend'), (5853192, 'bl method.Vector.operator_float__'), (5853272, 'bl method.Vector2.operator_float__'), (5853320, 'bl method.Vector.operator_float__'), (5853388, 'bl method.Vector2.operator_float__'), (5853436, 'bl method.Vector.operator_float__'), (5853496, 'bl sym.imp.__wrap_glUniform4f'), (5853588, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5853684, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5853764, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5853844, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5853936, 'bl sym.imp.__wrap_glDrawElements'), (5853944, 'bl sym.imp.__wrap_glActiveTexture'), (5854128, 'bl loc.imp.objc_msgSend'), (5854164, 'bl loc.imp.objc_msgSend'), (5854184, 'bl loc.imp.objc_msgSend'), (5854216, 'bl method.Vector.operator_float__'), (5854296, 'bl method.Vector2.operator_float__'), (5854344, 'bl method.Vector.operator_float__'), (5854416, 'bl method.Vector2.operator_float__'), (5854492, 'bl sym.imp.__wrap_glUniform4f'), (5854584, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5854680, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5854760, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5854840, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5854932, 'bl sym.imp.__wrap_glDrawElements'), (5855180, 'blx r6'), (5855212, 'blx r3'), (5855236, 'blx r2'), (5855260, 'bl method.Vector.operator_float__'), (5855336, 'bl method.Vector2.operator_float__'), (5855388, 'bl method.Vector.operator_float__'), (5855464, 'bl method.Vector2.operator_float__'), (5855516, 'bl method.Vector.operator_float__'), (5855588, 'bl sym.imp.__wrap_glUniform4f'), (5855792, 'blx r6'), (5855824, 'blx r3'), (5855848, 'blx r2'), (5855872, 'bl method.Vector.operator_float__'), (5855948, 'bl method.Vector2.operator_float__'), (5856000, 'bl method.Vector.operator_float__'), (5856076, 'bl method.Vector2.operator_float__'), (5856128, 'bl method.Vector.operator_float__'), (5856200, 'bl sym.imp.__wrap_glUniform4f'), (5856376, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5856472, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5856552, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5856632, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5856724, 'bl sym.imp.__wrap_glDrawElements'), (5856844, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5856852, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5856860, 'bl sym.imp.__wrap_glActiveTexture'), (5856872, 'bl sym.imp.__wrap_glBindTexture'), (5856880, 'bl sym.imp.__wrap_glActiveTexture'), (5856892, 'bl sym.imp.__wrap_glBindTexture'), (5856900, 'bl sym.imp.__wrap_glActiveTexture'), (5856912, 'bl sym.imp.__wrap_glBindTexture'), (5856952, 'bl method.Vector2.operator_float__'), (5857028, 'bl sym.imp.floor'), (5857096, 'bl method.Vector2.operator_float__'), (5857196, 'bl sym.imp.floor'), (5857276, 'bl method.Vector2.operator_float__'), (5857352, 'bl sym.imp.floor'), (5857420, 'bl method.Vector2.operator_float__'), (5857552, 'bl sym.imp.floor'), (5857656, 'blx lr'), (5857660, 'bl sym.imp.__wrap_glUseProgram'), (5857836, 'blx r6'), (5857868, 'blx r3'), (5857892, 'blx r2'), (5857904, 'bl sym.imp.__wrap_glUniform1i'), (5858080, 'blx r6'), (5858112, 'blx r3'), (5858136, 'blx r2'), (5858148, 'bl sym.imp.__wrap_glUniform1i'), (5858324, 'blx r6'), (5858356, 'blx r3'), (5858380, 'blx r2'), (5858392, 'bl sym.imp.__wrap_glUniform1i'), (5858544, 'blx r2'), (5858576, 'blx r3'), (5858600, 'blx r2'), (5858644, 'bl method.Vector.operator_float__'), (5858700, 'bl method.Vector.operator_float__'), (5858756, 'bl method.Vector.operator_float__'), (5858812, 'bl method.Vector.operator_float__'), (5858872, 'bl sym.imp.__wrap_glUniform4f'), (5858880, 'bl sym.imp.__wrap_glActiveTexture'), (5858980, 'blx r3'), (5859012, 'bl sym.imp.__wrap_glBindTexture'), (5859020, 'bl sym.imp.__wrap_glActiveTexture'), (5859120, 'blx r3'), (5859152, 'bl sym.imp.__wrap_glBindTexture'), (5859160, 'bl sym.imp.__wrap_glActiveTexture'), (5859168, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5859176, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5860024, 'bl sym.imp.__wrap_glBindTexture'), (5860080, 'bl method.Vector2.operator_float__'), (5860140, 'bl method.Vector2.operator_float__'), (5860240, 'bl method.Vector2.operator_float__'), (5860300, 'bl method.Vector2.operator_float__'), (5860392, 'bl 0x582eb4'), (5861504, 'bl 0x58bbd8'), (5861692, 'blx r3'), (5861724, 'blx r3'), (5861748, 'blx r2'), (5861800, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5861952, 'blx r2'), (5861984, 'blx r3'), (5862008, 'blx r2'), (5862052, 'bl method.Vector2.operator_float__'), (5862124, 'bl method.Vector2.operator_float__'), (5862208, 'bl sym.imp.__wrap_glUniform4f'), (5862260, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5862316, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5862372, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5862428, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5862464, 'bl sym.imp.__wrap_glDrawArrays'), (5862544, 'bl sym.imp.__wrap_glBindTexture'), (5862600, 'bl method.Vector2.operator_float__'), (5862660, 'bl method.Vector2.operator_float__'), (5862760, 'bl method.Vector2.operator_float__'), (5862820, 'bl method.Vector2.operator_float__'), (5862912, 'bl 0x582eb4'), (5864024, 'bl 0x58bbd8'), (5864212, 'blx r3'), (5864244, 'blx r3'), (5864268, 'blx r2'), (5864320, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5864472, 'blx r2'), (5864504, 'blx r3'), (5864528, 'blx r2'), (5864572, 'bl method.Vector2.operator_float__'), (5864644, 'bl method.Vector2.operator_float__'), (5864728, 'bl sym.imp.__wrap_glUniform4f'), (5864780, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5864836, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5864892, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5864948, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5864984, 'bl sym.imp.__wrap_glDrawArrays'), (5865080, 'bl sym.imp.__wrap_glBindTexture'), (5865088, 'bl sym.imp.__wrap_glActiveTexture'), (5865100, 'bl sym.imp.__wrap_glBindTexture'), (5865108, 'bl sym.imp.__wrap_glActiveTexture'), (5865192, 'blx r2'), (5865196, 'bl sym.imp.__wrap_glUseProgram'), (5865372, 'blx r6'), (5865404, 'blx r3'), (5865428, 'blx r2'), (5865440, 'bl sym.imp.__wrap_glUniform1i'), (5865616, 'blx r6'), (5865648, 'blx r3'), (5865672, 'blx r2'), (5865684, 'bl sym.imp.__wrap_glUniform1i'), (5865860, 'blx r6'), (5865892, 'blx r3'), (5865916, 'blx r2'), (5865928, 'bl sym.imp.__wrap_glUniform1i'), (5866080, 'blx r2'), (5866112, 'blx r3'), (5866136, 'blx r2'), (5866180, 'bl method.Vector.operator_float__'), (5866236, 'bl method.Vector.operator_float__'), (5866292, 'bl method.Vector.operator_float__'), (5866348, 'bl method.Vector.operator_float__'), (5866408, 'bl sym.imp.__wrap_glUniform4f'), (5866416, 'bl sym.imp.__wrap_glActiveTexture'), (5866516, 'blx r3'), (5866548, 'bl sym.imp.__wrap_glBindTexture'), (5866556, 'bl sym.imp.__wrap_glActiveTexture'), (5866656, 'blx r3'), (5866688, 'bl sym.imp.__wrap_glBindTexture'), (5866696, 'bl sym.imp.__wrap_glActiveTexture'), (5866704, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5866712, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5866720, 'bl sym.imp.__wrap_glEnable'), (5866796, 'bl sym.pushDepthMaskState'), (5866812, 'bl sym.pushDepthMaskState'), (5867588, 'bl sym.imp.__wrap_glBindTexture'), (5867692, 'bl method.Vector2.operator_float__'), (5867752, 'bl method.Vector2.operator_float__'), (5867872, 'bl method.Vector2.operator_float__'), (5867932, 'bl method.Vector2.operator_float__'), (5868064, 'bl 0x582eb4'), (5869188, 'bl 0x58bbd8'), (5869256, 'bl loc.imp.objc_msgSend'), (5869296, 'bl loc.imp.objc_msgSend'), (5869328, 'bl loc.imp.objc_msgSend'), (5869360, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5869412, 'bl loc.imp.objc_msgSend'), (5869440, 'bl loc.imp.objc_msgSend'), (5869464, 'bl loc.imp.objc_msgSend'), (5869496, 'bl method.Vector.operator_float__'), (5869560, 'bl method.Vector2.operator_float__'), (5869608, 'bl method.Vector.operator_float__'), (5869672, 'bl method.Vector2.operator_float__'), (5869720, 'bl method.Vector.operator_float__'), (5869776, 'bl sym.imp.__wrap_glUniform4f'), (5869880, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5869964, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5870044, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5870124, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5870216, 'bl sym.imp.__wrap_glDrawElements'), (5871216, 'bl sym.imp.__wrap_glBindTexture'), (5871320, 'bl method.Vector2.operator_float__'), (5871380, 'bl method.Vector2.operator_float__'), (5871500, 'bl method.Vector2.operator_float__'), (5871560, 'bl method.Vector2.operator_float__'), (5871688, 'bl 0x582eb4'), (5872816, 'bl 0x58bbd8'), (5872864, 'bl loc.imp.objc_msgSend'), (5872892, 'bl loc.imp.objc_msgSend'), (5872912, 'bl loc.imp.objc_msgSend'), (5872936, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5873116, 'bl loc.imp.objc_msgSend'), (5873140, 'bl loc.imp.objc_msgSend'), (5873160, 'bl loc.imp.objc_msgSend'), (5873240, 'bl method.Vector2.operator_float__'), (5873284, 'bl method.Vector.operator_float__'), (5873348, 'bl method.Vector2.operator_float__'), (5873424, 'bl sym.imp.__wrap_glUniform4f'), (5873536, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5873640, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5873728, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5873816, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5873920, 'bl sym.imp.__wrap_glDrawElements'), (5874112, 'bl loc.imp.objc_msgSend'), (5874136, 'bl loc.imp.objc_msgSend'), (5874156, 'bl loc.imp.objc_msgSend'), (5874236, 'bl method.Vector2.operator_float__'), (5874280, 'bl method.Vector.operator_float__'), (5874344, 'bl method.Vector2.operator_float__'), (5874420, 'bl sym.imp.__wrap_glUniform4f'), (5874532, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5874636, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5874724, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5874812, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5874916, 'bl sym.imp.__wrap_glDrawElements'), (5875108, 'bl loc.imp.objc_msgSend'), (5875132, 'bl loc.imp.objc_msgSend'), (5875152, 'bl loc.imp.objc_msgSend'), (5875184, 'bl method.Vector.operator_float__'), (5875264, 'bl method.Vector2.operator_float__'), (5875312, 'bl method.Vector.operator_float__'), (5875380, 'bl method.Vector2.operator_float__'), (5875428, 'bl method.Vector.operator_float__'), (5875488, 'bl sym.imp.__wrap_glUniform4f'), (5875600, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5875704, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5875792, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5875880, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5875984, 'bl sym.imp.__wrap_glDrawElements'), (5876176, 'bl loc.imp.objc_msgSend'), (5876200, 'bl loc.imp.objc_msgSend'), (5876220, 'bl loc.imp.objc_msgSend'), (5876252, 'bl method.Vector.operator_float__'), (5876332, 'bl method.Vector2.operator_float__'), (5876380, 'bl method.Vector.operator_float__'), (5876452, 'bl method.Vector2.operator_float__'), (5876528, 'bl sym.imp.__wrap_glUniform4f'), (5876640, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5876744, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5876832, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5876920, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5877024, 'bl sym.imp.__wrap_glDrawElements'), (5877832, 'bl sym.imp.__wrap_glBindTexture'), (5877936, 'bl method.Vector2.operator_float__'), (5877996, 'bl method.Vector2.operator_float__'), (5878116, 'bl method.Vector2.operator_float__'), (5878176, 'bl method.Vector2.operator_float__'), (5878284, 'bl 0x582eb4'), (5879392, 'bl 0x58bbd8'), (5879576, 'blx r3'), (5879608, 'blx r3'), (5879632, 'blx r2'), (5879684, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5879884, 'blx r6'), (5879916, 'blx r3'), (5879940, 'blx r2'), (5879964, 'bl method.Vector.operator_float__'), (5880040, 'bl method.Vector2.operator_float__'), (5880092, 'bl method.Vector.operator_float__'), (5880168, 'bl method.Vector2.operator_float__'), (5880220, 'bl method.Vector.operator_float__'), (5880292, 'bl sym.imp.__wrap_glUniform4f'), (5880492, 'blx r6'), (5880524, 'blx r3'), (5880548, 'blx r2'), (5880572, 'bl method.Vector.operator_float__'), (5880648, 'bl method.Vector2.operator_float__'), (5880700, 'bl method.Vector.operator_float__'), (5880776, 'bl method.Vector2.operator_float__'), (5880828, 'bl method.Vector.operator_float__'), (5880900, 'bl sym.imp.__wrap_glUniform4f'), (5881084, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5881188, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5881276, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5881364, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5881468, 'bl sym.imp.__wrap_glDrawElements'), (5881688, 'bl sym.pushDepthMaskState'), (5881696, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5881704, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5881732, 'bl sym.imp.__wrap_glBindTexture'), (5881740, 'bl sym.imp.__wrap_glActiveTexture'), (5881760, 'bl sym.imp.__wrap_glBindTexture'), (5881768, 'bl sym.imp.__wrap_glActiveTexture'), (5881824, 'bl method.Vector2.operator_float__'), (5881872, 'bl method.Vector2.operator_float__'), (5881972, 'bl method.Vector2.operator_float__'), (5882016, 'bl method.Vector2.operator_float__'), (5882104, 'bl 0x582eb4'), (5883936, 'bl loc.imp.objc_msgSend'), (5885380, 'bl loc.imp.objc_msgSend'), (5886760, 'bl loc.imp.objc_msgSend'), (5886824, 'blx ip'), (5886828, 'bl sym.imp.__wrap_glUseProgram'), (5887004, 'blx r6'), (5887036, 'blx r3'), (5887060, 'blx r2'), (5887072, 'bl sym.imp.__wrap_glUniform1i'), (5887248, 'blx r6'), (5887280, 'blx r3'), (5887304, 'blx r2'), (5887316, 'bl sym.imp.__wrap_glUniform1i'), (5887492, 'blx r6'), (5887524, 'blx r3'), (5887548, 'blx r2'), (5887560, 'bl sym.imp.__wrap_glUniform1i'), (5887688, 'blx r2'), (5887708, 'blx r3'), (5887724, 'blx r2'), (5887760, 'bl method.Vector.operator_float__'), (5887816, 'bl method.Vector.operator_float__'), (5887872, 'bl method.Vector.operator_float__'), (5887928, 'bl method.Vector.operator_float__'), (5887984, 'bl sym.imp.__wrap_glUniform4f'), (5887992, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5888000, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5888008, 'bl sym.imp.__wrap_glEnable'), (5888012, 'bl sym.popDepthMaskState'), (5888020, 'bl sym.imp.__wrap_glActiveTexture'), (5888108, 'blx r3'), (5888128, 'bl sym.imp.__wrap_glBindTexture'), (5888136, 'bl sym.imp.__wrap_glActiveTexture'), (5888224, 'blx r3'), (5888244, 'bl sym.imp.__wrap_glBindTexture'), (5888252, 'bl sym.imp.__wrap_glActiveTexture'), (5888264, 'bl sym.pushDepthMaskState'), (5889132, 'bl sym.imp.__wrap_glBindTexture'), (5889180, 'bl method.Vector2.operator_float__'), (5889236, 'bl method.Vector2.operator_float__'), (5889324, 'bl method.Vector2.operator_float__'), (5889380, 'bl method.Vector2.operator_float__'), (5889468, 'bl 0x582eb4'), (5890372, 'bl 0x58bbd8'), (5890528, 'blx r3'), (5890548, 'blx r3'), (5890564, 'blx r2'), (5890596, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5890724, 'blx r2'), (5890744, 'blx r3'), (5890760, 'blx r2'), (5890796, 'bl method.Vector2.operator_float__'), (5890868, 'bl method.Vector2.operator_float__'), (5890940, 'bl sym.imp.__wrap_glUniform4f'), (5890992, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5891048, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5891104, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5891160, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5891196, 'bl sym.imp.__wrap_glDrawArrays'), (5891268, 'bl sym.popDepthMaskState'), (5891276, 'bl sym.imp.__wrap_glActiveTexture'), (5891364, 'blx r3'), (5891384, 'bl sym.imp.__wrap_glBindTexture'), (5891392, 'bl sym.imp.__wrap_glActiveTexture'), (5891480, 'blx r3'), (5891500, 'bl sym.imp.__wrap_glBindTexture'), (5891508, 'bl sym.imp.__wrap_glActiveTexture'), (5892352, 'bl sym.imp.__wrap_glBindTexture'), (5892400, 'bl method.Vector2.operator_float__'), (5892456, 'bl method.Vector2.operator_float__'), (5892544, 'bl method.Vector2.operator_float__'), (5892600, 'bl method.Vector2.operator_float__'), (5892684, 'bl 0x582eb4'), (5893584, 'bl 0x58bbd8'), (5893736, 'blx r3'), (5893756, 'blx r3'), (5893772, 'blx r2'), (5893804, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5893932, 'blx r2'), (5893952, 'blx r3'), (5893968, 'blx r2'), (5894004, 'bl method.Vector2.operator_float__'), (5894076, 'bl method.Vector2.operator_float__'), (5894148, 'bl sym.imp.__wrap_glUniform4f'), (5894200, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5894256, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5894312, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5894368, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5894380, 'bl sym.pushDepthMaskState'), (5894416, 'bl sym.imp.__wrap_glDrawArrays'), (5894420, 'bl sym.popDepthMaskState'), (5894504, 'bl sym.imp.__wrap_glBindTexture'), (5894552, 'bl method.Vector2.operator_float__'), (5894608, 'bl method.Vector2.operator_float__'), (5894696, 'bl method.Vector2.operator_float__'), (5894752, 'bl method.Vector2.operator_float__'), (5894836, 'bl 0x582eb4'), (5895736, 'bl 0x58bbd8'), (5895888, 'blx r3'), (5895908, 'blx r3'), (5895924, 'blx r2'), (5895956, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5896084, 'blx r2'), (5896104, 'blx r3'), (5896120, 'blx r2'), (5896156, 'bl method.Vector2.operator_float__'), (5896228, 'bl method.Vector2.operator_float__'), (5896300, 'bl sym.imp.__wrap_glUniform4f'), (5896352, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5896408, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5896464, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5896520, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5896532, 'bl sym.pushDepthMaskState'), (5896568, 'bl sym.imp.__wrap_glDrawArrays'), (5896572, 'bl sym.popDepthMaskState'), (5896652, 'bl sym.imp.__wrap_glBindTexture'), (5896700, 'bl method.Vector2.operator_float__'), (5896756, 'bl method.Vector2.operator_float__'), (5896844, 'bl method.Vector2.operator_float__'), (5896900, 'bl method.Vector2.operator_float__'), (5896984, 'bl 0x582eb4'), (5897884, 'bl 0x58bbd8'), (5898036, 'blx r3'), (5898056, 'blx r3'), (5898072, 'blx r2'), (5898104, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5898232, 'blx r2'), (5898252, 'blx r3'), (5898268, 'blx r2'), (5898304, 'bl method.Vector2.operator_float__'), (5898376, 'bl method.Vector2.operator_float__'), (5898448, 'bl sym.imp.__wrap_glUniform4f'), (5898500, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5898556, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5898612, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5898668, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5898680, 'bl sym.pushDepthMaskState'), (5898716, 'bl sym.imp.__wrap_glDrawArrays'), (5898720, 'bl sym.popDepthMaskState'), (5898816, 'bl sym.imp.__wrap_glEnable'), (5898824, 'bl sym.pushDepthMaskState'), (5898832, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5898840, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5898860, 'bl sym.imp.__wrap_glBindTexture'), (5898868, 'bl sym.imp.__wrap_glActiveTexture'), (5898880, 'bl sym.imp.__wrap_glBindTexture'), (5898888, 'bl sym.imp.__wrap_glActiveTexture'), (5900060, 'bl loc.imp.objc_msgSend'), (5900068, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5900076, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5900152, 'blx r2'), (5900156, 'bl sym.imp.__wrap_glUseProgram'), (5900300, 'blx r6'), (5900320, 'blx r3'), (5900336, 'blx r2'), (5900344, 'bl sym.imp.__wrap_glUniform1i'), (5900488, 'blx r6'), (5900508, 'blx r3'), (5900524, 'blx r2'), (5900532, 'bl sym.imp.__wrap_glUniform1i'), (5900676, 'blx r6'), (5900696, 'blx r3'), (5900712, 'blx r2'), (5900720, 'bl sym.imp.__wrap_glUniform1i'), (5900848, 'blx r2'), (5900868, 'blx r3'), (5900884, 'blx r2'), (5900920, 'bl method.Vector.operator_float__'), (5900976, 'bl method.Vector.operator_float__'), (5901032, 'bl method.Vector.operator_float__'), (5901088, 'bl method.Vector.operator_float__'), (5901144, 'bl sym.imp.__wrap_glUniform4f'), (5901148, 'bl sym.popDepthMaskState'), (5901156, 'bl sym.imp.__wrap_glActiveTexture'), (5901244, 'blx r3'), (5901264, 'bl sym.imp.__wrap_glBindTexture'), (5901272, 'bl sym.imp.__wrap_glActiveTexture'), (5901360, 'blx r3'), (5901380, 'bl sym.imp.__wrap_glBindTexture'), (5901388, 'bl sym.imp.__wrap_glActiveTexture'), (5901392, 'bl sym.popDepthMaskState'), (5901460, 'bl sym.imp.__wrap_glEnable'), (5901472, 'bl sym.pushDepthMaskState'), (5901548, 'blx r2'), (5901552, 'bl sym.imp.__wrap_glUseProgram'), (5901696, 'blx r6'), (5901716, 'blx r3'), (5901732, 'blx r2'), (5901740, 'bl sym.imp.__wrap_glUniform1i'), (5901884, 'blx r6'), (5901904, 'blx r3'), (5901920, 'blx r2'), (5901928, 'bl sym.imp.__wrap_glUniform1i'), (5902072, 'blx r6'), (5902092, 'blx r3'), (5902108, 'blx r2'), (5902116, 'bl sym.imp.__wrap_glUniform1i'), (5902244, 'blx r2'), (5902264, 'blx r3'), (5902280, 'blx r2'), (5902316, 'bl method.Vector.operator_float__'), (5902372, 'bl method.Vector.operator_float__'), (5902428, 'bl method.Vector.operator_float__'), (5902484, 'bl method.Vector.operator_float__'), (5902540, 'bl sym.imp.__wrap_glUniform4f'), (5903372, 'bl sym.imp.__wrap_glBindTexture'), (5903420, 'bl method.Vector2.operator_float__'), (5903476, 'bl method.Vector2.operator_float__'), (5903564, 'bl method.Vector2.operator_float__'), (5903620, 'bl method.Vector2.operator_float__'), (5903708, 'bl 0x582eb4'), (5904612, 'bl 0x58bbd8'), (5904768, 'blx r3'), (5904788, 'blx r3'), (5904804, 'blx r2'), (5904836, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5904964, 'blx r2'), (5904984, 'blx r3'), (5905000, 'blx r2'), (5905036, 'bl method.Vector2.operator_float__'), (5905108, 'bl method.Vector2.operator_float__'), (5905180, 'bl sym.imp.__wrap_glUniform4f'), (5905232, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5905288, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5905344, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5905380, 'bl sym.imp.__wrap_glDrawArrays'), (5905448, 'bl sym.popDepthMaskState'), (5905456, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5905464, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5905472, 'bl sym.imp.__wrap_glActiveTexture'), (5905484, 'bl sym.imp.__wrap_glBindTexture'), (5905492, 'bl sym.imp.__wrap_glActiveTexture'), (5905504, 'bl sym.imp.__wrap_glBindTexture'), (5905512, 'bl sym.imp.__wrap_glActiveTexture'), (5905524, 'bl sym.imp.__wrap_glBindTexture'), (5905668, 'blx r2'), (5905700, 'bl sym.imp.__wrap_glEnable'), (5906452, 'bl sym.seasonForWorldX_int__double__World_'), (5906492, 'bl sym.makeIntpair_int__int_'), (5906596, 'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_'), (5906668, 'bl sym.freezingLevelForWorldX_int__float__float__float__World_'), (5906736, 'bl sym.clamp_float__float__float_'), (5906784, 'bl sym.clamp_float__float__float_'), (5906832, 'bl sym.imp.__wrap_glBindTexture'), (5906920, 'bl method.Vector2.operator_float__'), (5906976, 'bl method.Vector2.operator_float__'), (5907084, 'bl method.Vector2.operator_float__'), (5907140, 'bl method.Vector2.operator_float__'), (5907252, 'bl 0x582eb4'), (5908156, 'bl 0x58bbd8'), (5908856, 'bl loc.imp.objc_msgSend'), (5908956, 'bl sym.imp.__wrap_glDisable'), (5908976, 'bl sym.imp.__wrap_glDisable'), (5909012, 'bl loc.imp.objc_msgSend'), (5909464, 'bl loc.imp.objc_msgSend'), (5910224, 'bl loc.imp.objc_msgSend'), (5910232, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5910240, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5910316, 'blx r2'), (5910320, 'bl sym.imp.__wrap_glUseProgram'), (5910464, 'blx r6'), (5910484, 'blx r3'), (5910500, 'blx r2'), (5910508, 'bl sym.imp.__wrap_glUniform1i'), (5910652, 'blx r6'), (5910672, 'blx r3'), (5910688, 'blx r2'), (5910696, 'bl sym.imp.__wrap_glUniform1i'), (5910704, 'bl sym.imp.__wrap_glActiveTexture'), (5910792, 'blx r3'), (5910812, 'bl sym.imp.__wrap_glBindTexture'), (5910820, 'bl sym.imp.__wrap_glActiveTexture'), (5910908, 'blx r3'), (5910928, 'bl sym.imp.__wrap_glBindTexture'), (5910936, 'bl sym.imp.__wrap_glActiveTexture'), (5910948, 'bl sym.pushDepthMaskState'), (5910956, 'bl sym.imp.__wrap_glEnable'), (5911652, 'bl sym.imp.__wrap_glBindTexture'), (5911748, 'bl method.Vector2.operator_float__'), (5911804, 'bl method.Vector2.operator_float__'), (5911916, 'bl method.Vector2.operator_float__'), (5911972, 'bl method.Vector2.operator_float__'), (5912084, 'bl 0x582eb4'), (5912988, 'bl 0x58bbd8'), (5913144, 'blx r3'), (5913164, 'blx r3'), (5913180, 'blx r2'), (5913212, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5913360, 'blx r6'), (5913380, 'blx r3'), (5913396, 'blx r2'), (5913412, 'bl method.Vector.operator_float__'), (5913488, 'bl method.Vector2.operator_float__'), (5913540, 'bl method.Vector.operator_float__'), (5913616, 'bl method.Vector2.operator_float__'), (5913668, 'bl method.Vector.operator_float__'), (5913732, 'bl sym.imp.__wrap_glUniform4f'), (5913784, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5913840, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5913896, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5913952, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5914040, 'bl sym.imp.__wrap_glDrawElements'), (5914244, 'blx r2'), (5914248, 'bl sym.imp.__wrap_glUseProgram'), (5914392, 'blx r6'), (5914412, 'blx r3'), (5914428, 'blx r2'), (5914436, 'bl sym.imp.__wrap_glUniform1i'), (5914580, 'blx r6'), (5914600, 'blx r3'), (5914616, 'blx r2'), (5914624, 'bl sym.imp.__wrap_glUniform1i'), (5914768, 'blx r6'), (5914788, 'blx r3'), (5914804, 'blx r2'), (5914812, 'bl sym.imp.__wrap_glUniform1i'), (5914940, 'blx r2'), (5914960, 'blx r3'), (5914976, 'blx r2'), (5915012, 'bl method.Vector.operator_float__'), (5915068, 'bl method.Vector.operator_float__'), (5915124, 'bl method.Vector.operator_float__'), (5915180, 'bl method.Vector.operator_float__'), (5915236, 'bl sym.imp.__wrap_glUniform4f'), (5915244, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5915252, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5915260, 'bl sym.imp.__wrap_glEnable'), (5915268, 'bl sym.imp.__wrap_glActiveTexture'), (5915356, 'blx r3'), (5915376, 'bl sym.imp.__wrap_glBindTexture'), (5915384, 'bl sym.imp.__wrap_glActiveTexture'), (5915472, 'blx r3'), (5915492, 'bl sym.imp.__wrap_glBindTexture'), (5915500, 'bl sym.imp.__wrap_glActiveTexture'), (5916292, 'bl sym.imp.__wrap_glBindTexture'), (5916340, 'bl method.Vector2.operator_float__'), (5916396, 'bl method.Vector2.operator_float__'), (5916484, 'bl method.Vector2.operator_float__'), (5916540, 'bl method.Vector2.operator_float__'), (5916628, 'bl 0x582eb4'), (5917532, 'bl 0x58bbd8'), (5917688, 'blx r3'), (5917708, 'blx r3'), (5917724, 'blx r2'), (5917756, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5917884, 'blx r2'), (5917904, 'blx r3'), (5917920, 'blx r2'), (5917956, 'bl method.Vector2.operator_float__'), (5918028, 'bl method.Vector2.operator_float__'), (5918100, 'bl sym.imp.__wrap_glUniform4f'), (5918152, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5918208, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5918264, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5918320, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5918356, 'bl sym.imp.__wrap_glDrawArrays'), (5918444, 'bl sym.popDepthMaskState'), (5918452, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5918460, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5918480, 'bl sym.imp.__wrap_glBindTexture'), (5918488, 'bl sym.imp.__wrap_glActiveTexture'), (5918500, 'bl sym.imp.__wrap_glBindTexture'), (5918508, 'bl sym.imp.__wrap_glActiveTexture'), (5918556, 'bl method.Vector2.operator_float__'), (5918596, 'bl method.Vector2.operator_float__'), (5918684, 'bl method.Vector2.operator_float__'), (5918724, 'bl method.Vector2.operator_float__'), (5918804, 'bl 0x582eb4'), (5920100, 'bl loc.imp.objc_msgSend'), (5920108, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5920116, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5920124, 'bl sym.imp.__wrap_glEnable'), (5920132, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5920144, 'bl sym.imp.__wrap_glBindTexture'), (5920152, 'bl sym.imp.__wrap_glActiveTexture'), (5920164, 'bl sym.imp.__wrap_glBindTexture'), (5920172, 'bl sym.imp.__wrap_glActiveTexture'), (5920184, 'bl sym.imp.__wrap_glBindTexture'), (5920192, 'bl sym.imp.__wrap_glActiveTexture'), (5920204, 'bl sym.imp.__wrap_glBindTexture'), (5920208, 'bl sym.popDepthTestState'), (5920336, 'bl sym.clamp_float__float__float_'), (5920360, 'bl sym.imp.__wrap_glEnable'), (5920436, 'blx r2'), (5920440, 'bl sym.imp.__wrap_glUseProgram'), (5920584, 'blx r6'), (5920604, 'blx r3'), (5920620, 'blx r2'), (5920628, 'bl sym.imp.__wrap_glUniform1i'), (5920752, 'blx r5'), (5920772, 'blx r3'), (5920788, 'blx r2'), (5920808, 'bl sym.imp.__wrap_glUniform1f'), (5920816, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5920824, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5920832, 'bl sym.imp.__wrap_glActiveTexture'), (5920920, 'blx r3'), (5920940, 'bl sym.imp.__wrap_glBindTexture'), (5921764, 'bl method.Vector2.operator_float__'), (5921820, 'bl method.Vector2.operator_float__'), (5921908, 'bl method.Vector2.operator_float__'), (5921964, 'bl method.Vector2.operator_float__'), (5922052, 'bl 0x582eb4'), (5922956, 'bl 0x58bbd8'), (5923112, 'blx r3'), (5923132, 'blx r3'), (5923148, 'blx r2'), (5923180, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5923232, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5923288, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5923344, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5923380, 'bl sym.imp.__wrap_glDrawArrays'), (5923524, 'bl sym.imp.__wrap_glBlendFunc'), (5923596, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5923604, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5923624, 'bl sym.imp.__wrap_glBindTexture'), (5923632, 'bl sym.imp.__wrap_glActiveTexture'), (5923644, 'bl sym.imp.__wrap_glBindTexture'), (5923652, 'bl sym.imp.__wrap_glActiveTexture'), (5924860, 'bl loc.imp.objc_msgSend'), (5924868, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5924876, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5924952, 'blx r2'), (5924956, 'bl sym.imp.__wrap_glUseProgram'), (5925704, 'bl method.Vector2.operator_float__'), (5925760, 'bl method.Vector2.operator_float__'), (5925872, 'bl method.Vector2.operator_float__'), (5925928, 'bl method.Vector2.operator_float__'), (5926040, 'bl 0x582eb4'), (5926944, 'bl 0x58bbd8'), (5927100, 'blx r3'), (5927120, 'blx r3'), (5927136, 'blx r2'), (5927168, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5927220, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5927276, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5927332, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5927420, 'bl sym.imp.__wrap_glDrawElements'), (5927500, 'bl sym.imp.__wrap_glDisable'), (5927508, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5927516, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5927592, 'blx r2'), (5927596, 'bl sym.imp.__wrap_glUseProgram'), (5928340, 'bl method.Vector2.operator_float__'), (5928392, 'bl method.Vector2.operator_float__'), (5928488, 'bl method.Vector2.operator_float__'), (5928540, 'bl method.Vector2.operator_float__'), (5928636, 'bl 0x582eb4'), (5929540, 'bl 0x58bbd8'), (5929696, 'blx r3'), (5929716, 'blx r3'), (5929732, 'blx r2'), (5929764, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5929820, 'bl sym.imp.__wrap_glVertexAttribPointer'), (5929908, 'bl sym.imp.__wrap_glDrawElements'), (5931192, 'bl loc.imp.objc_msgSend'), (5931204, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5931212, 'bl sym.imp.__wrap_glDisable'), (5931288, 'blx r2'), (5931292, 'bl sym.imp.__wrap_glUseProgram'), (5931300, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5931308, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5932028, 'bl method.Vector2.operator_float__'), (5932080, 'bl method.Vector2.operator_float__'), (5932176, 'bl method.Vector2.operator_float__'), (5932228, 'bl method.Vector2.operator_float__'), (5932324, 'bl 0x582eb4'), (5933228, 'bl 0x58bbd8'), (5933384, 'blx r3'), (5933404, 'blx r3'), (5933420, 'blx r2'), (5933452, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5933504, 'bl sym.drawShaderQuadNoTexture'), (5933752, 'bl sym.imp.__wrap_glEnable'), (5933804, 'bl loc.imp.objc_msgSend'), (5933808, 'bl sym.imp.__wrap_glUseProgram'), (5933816, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (5933920, 'bl method.Vector2.operator_float__'), (5933960, 'bl method.Vector2.operator_float__'), (5934044, 'bl method.Vector2.operator_float__'), (5934080, 'bl method.Vector2.operator_float__'), (5934156, 'bl 0x582eb4'), (5934244, 'bl 0x5aa554'), (5935136, 'bl 0x58bbd8'), (5936036, 'bl 0x58bbd8'), (5936188, 'blx r3'), (5936208, 'blx r3'), (5936224, 'blx r2'), (5936256, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (5936344, 'blx r3'), (5936364, 'bl sym.imp.__wrap_glBindTexture'), (5936500, 'blx lr'), (5936560, 'blx ip'), (5936632, 'bl sym.drawShaderQuad'), (5936640, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5936648, 'bl sym.imp.__wrap_glDisable'), (5936688, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5936696, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (5936704, 'bl sym.imp.__wrap_glClear'), (5936708, 'bl sym.popDepthMaskState'), (5937388, 'bl loc.imp.objc_msgSend'), (5937480, 'blx r2')],
        branches=[(5819048, 'beq', 5819116), (5819188, 'bpl', 5819216), (5819212, 'b', 5819236), (5819536, 'bpl', 5819728), (5819632, 'bpl', 5819680), (5819656, 'b', 5819700), (5820616, 'beq', 5821528), (5820708, 'bls', 5821528), (5820960, 'beq', 5821520), (5821096, 'beq', 5821112), (5821316, 'bne', 5821340), (5821336, 'b', 5821524), (5821340, 'b', 5821344), (5821384, 'blo', 5821036), (5821516, 'bne', 5821036), (5821520, 'b', 5821524), (5821524, 'b', 5821528), (5821620, 'beq', 5822004), (5821636, 'beq', 5822004), (5821688, 'beq', 5821788), (5821736, 'bne', 5821788), (5821784, 'beq', 5822004), (5821948, 'b', 5822284), (5822240, 'beq', 5822280), (5822280, 'b', 5822284), (5823832, 'bge', 5824840), (5823852, 'blt', 5824772), (5823872, 'bge', 5824772), (5823976, 'bge', 5824768), (5824004, 'bge', 5824088), (5824060, 'b', 5824196), (5824136, 'blt', 5824192), (5824192, 'b', 5824196), (5824316, 'beq', 5824736), (5824560, 'beq', 5824732), (5824640, 'beq', 5824660), (5824732, 'b', 5824736), (5824736, 'b', 5824740), (5824760, 'b', 5823928), (5824768, 'b', 5824772), (5824772, 'b', 5824776), (5824796, 'b', 5823784), (5824932, 'ble', 5826028), (5825024, 'bne', 5826024), (5825396, 'beq', 5825976), (5825952, 'b', 5825172), (5826024, 'b', 5826028), (5826328, 'bmi', 5826380), (5826376, 'bne', 5931200), (5826672, 'bpl', 5826700), (5826696, 'b', 5826720), (5826828, 'bpl', 5826880), (5826852, 'b', 5826900), (5827148, 'bpl', 5827180), (5827172, 'b', 5827200), (5827304, 'bpl', 5827472), (5827328, 'b', 5827492), (5829776, 'beq', 5830088), (5830580, 'bpl', 5830612), (5830604, 'b', 5830632), (5831528, 'ble', 5831884), (5831608, 'bpl', 5831664), (5831632, 'b', 5831684), (5831772, 'bpl', 5831836), (5831796, 'b', 5831856), (5831904, 'ble', 5832704), (5833600, 'beq', 5833912), (5834404, 'bpl', 5834484), (5834428, 'b', 5834504), (5834952, 'ble', 5835956), (5835948, 'b', 5835956), (5835976, 'ble', 5836972), (5837072, 'bpl', 5837136), (5837096, 'b', 5837156), (5837268, 'ble', 5837360), (5840080, 'b', 5840096), (5840144, 'bge', 5845400), (5840164, 'blt', 5845348), (5840184, 'bge', 5845348), (5840304, 'bge', 5845344), (5840332, 'bge', 5840424), (5840396, 'b', 5840548), (5840480, 'blt', 5840544), (5840544, 'b', 5840548), (5840676, 'beq', 5845316), (5840700, 'ble', 5842728), (5842800, 'ble', 5845312), (5842828, 'ble', 5845312), (5842896, 'bgt', 5845308), (5842948, 'bge', 5843000), (5842972, 'b', 5843020), (5843080, 'bge', 5845280), (5843168, 'beq', 5843192), (5843188, 'bne', 5843720), (5843312, 'ble', 5843716), (5843340, 'bne', 5843360), (5843436, 'ble', 5843712), (5843712, 'b', 5843716), (5843716, 'b', 5843852), (5843752, 'bge', 5843828), (5843772, 'b', 5843848), (5843848, 'b', 5843852), (5843868, 'ble', 5845276), (5844012, 'bge', 5845272), (5844076, 'bne', 5844424), (5844388, 'b', 5844752), (5845264, 'b', 5843984), (5845272, 'b', 5845276), (5845276, 'b', 5845280), (5845280, 'b', 5845284), (5845304, 'b', 5842852), (5845308, 'b', 5845312), (5845312, 'b', 5845316), (5845316, 'b', 5845320), (5845340, 'b', 5840248), (5845344, 'b', 5845348), (5845348, 'b', 5845352), (5845372, 'b', 5840096), (5847576, 'bge', 5856840), (5847696, 'bge', 5856792), (5847716, 'blt', 5856764), (5847736, 'bge', 5856764), (5847856, 'bge', 5856760), (5847884, 'bge', 5848032), (5847948, 'b', 5848156), (5848088, 'blt', 5848152), (5848152, 'b', 5848156), (5848284, 'beq', 5856732), (5850072, 'ble', 5851032), (5851076, 'ble', 5851976), (5852020, 'ble', 5852920), (5852964, 'ble', 5853948), (5853992, 'ble', 5854936), (5854980, 'ble', 5856728), (5855000, 'bne', 5855616), (5855592, 'b', 5856204), (5856728, 'b', 5856732), (5856732, 'b', 5856736), (5856756, 'b', 5847800), (5856760, 'b', 5856764), (5856764, 'b', 5856768), (5856788, 'b', 5847640), (5856792, 'b', 5856796), (5856816, 'b', 5847560), (5859272, 'bge', 5865072), (5859292, 'blt', 5865020), (5859312, 'bge', 5865020), (5859432, 'bge', 5865016), (5859480, 'bge', 5859680), (5859588, 'b', 5859848), (5859736, 'blt', 5859844), (5859844, 'b', 5859848), (5859976, 'beq', 5862476), (5860000, 'ble', 5862476), (5862468, 'b', 5862476), (5862496, 'beq', 5864988), (5862520, 'ble', 5864988), (5864988, 'b', 5864992), (5865012, 'b', 5859376), (5865016, 'b', 5865020), (5865020, 'b', 5865024), (5865044, 'b', 5859224), (5866764, 'bge', 5901440), (5866784, 'beq', 5866804), (5866800, 'b', 5866816), (5866908, 'bge', 5870288), (5866928, 'blt', 5870252), (5866948, 'bge', 5870252), (5867068, 'bge', 5870248), (5867096, 'bge', 5867184), (5867160, 'b', 5867308), (5867240, 'blt', 5867304), (5867304, 'b', 5867308), (5867436, 'beq', 5870220), (5867484, 'ble', 5870220), (5870220, 'b', 5870224), (5870244, 'b', 5867012), (5870248, 'b', 5870252), (5870252, 'b', 5870256), (5870276, 'b', 5866860), (5870380, 'bge', 5877096), (5870400, 'blt', 5877064), (5870420, 'bge', 5877064), (5870540, 'bge', 5877060), (5870568, 'bge', 5870700), (5870632, 'b', 5870824), (5870756, 'blt', 5870820), (5870820, 'b', 5870824), (5870952, 'beq', 5877032), (5871008, 'bgt', 5871180), (5871064, 'bgt', 5871180), (5871120, 'bgt', 5871180), (5871176, 'ble', 5877032), (5872980, 'ble', 5873924), (5873976, 'ble', 5874920), (5874972, 'ble', 5875988), (5876040, 'ble', 5877028), (5877028, 'b', 5877032), (5877032, 'b', 5877036), (5877056, 'b', 5870484), (5877060, 'b', 5877064), (5877064, 'b', 5877068), (5877088, 'b', 5870332), (5877112, 'bge', 5881604), (5877208, 'bge', 5881600), (5877228, 'blt', 5881508), (5877248, 'bge', 5881508), (5877368, 'bge', 5881504), (5877396, 'bge', 5877500), (5877460, 'b', 5877624), (5877556, 'blt', 5877620), (5877620, 'b', 5877624), (5877752, 'beq', 5881472), (5877808, 'ble', 5881472), (5879704, 'bne', 5880316), (5880296, 'b', 5880904), (5881472, 'b', 5881476), (5881496, 'b', 5877312), (5881504, 'b', 5881508), (5881508, 'b', 5881512), (5881532, 'b', 5877160), (5881600, 'b', 5881604), (5881620, 'bne', 5901392), (5888360, 'bge', 5891268), (5888380, 'blt', 5891232), (5888400, 'bge', 5891232), (5888520, 'bge', 5891228), (5888572, 'bge', 5888720), (5888684, 'b', 5888892), (5888776, 'blt', 5888888), (5888888, 'b', 5888892), (5889020, 'beq', 5889064), (5889044, 'ble', 5889064), (5889084, 'beq', 5891200), (5889108, 'ble', 5891200), (5891200, 'b', 5891204), (5891224, 'b', 5888464), (5891228, 'b', 5891232), (5891232, 'b', 5891236), (5891256, 'b', 5888312), (5891604, 'bge', 5898800), (5891624, 'blt', 5898756), (5891644, 'bge', 5898756), (5891764, 'bge', 5898752), (5891808, 'bge', 5892012), (5891912, 'b', 5892176), (5892068, 'blt', 5892172), (5892172, 'b', 5892176), (5892304, 'beq', 5894436), (5892328, 'ble', 5894436), (5894424, 'b', 5894436), (5894456, 'beq', 5896584), (5894480, 'ble', 5896584), (5896576, 'b', 5896584), (5896604, 'beq', 5898724), (5896628, 'ble', 5898724), (5898724, 'b', 5898728), (5898748, 'b', 5891708), (5898752, 'b', 5898756), (5898756, 'b', 5898760), (5898780, 'b', 5891556), (5901416, 'b', 5866748), (5901452, 'beq', 5905452), (5902636, 'bge', 5905448), (5902656, 'blt', 5905416), (5902676, 'bge', 5905416), (5902796, 'bge', 5905412), (5902848, 'bge', 5903024), (5902960, 'b', 5903196), (5903080, 'blt', 5903192), (5903192, 'b', 5903196), (5903324, 'beq', 5905384), (5903348, 'ble', 5905384), (5905384, 'b', 5905388), (5905408, 'b', 5902740), (5905412, 'b', 5905416), (5905416, 'b', 5905420), (5905440, 'b', 5902588), (5905580, 'bgt', 5905696), (5905692, 'ble', 5908960), (5905796, 'bge', 5908952), (5905816, 'blt', 5908892), (5905836, 'bge', 5908892), (5905956, 'bge', 5908888), (5905984, 'bge', 5906104), (5906048, 'b', 5906228), (5906160, 'blt', 5906224), (5906224, 'b', 5906228), (5906356, 'beq', 5908860), (5908860, 'b', 5908864), (5908884, 'b', 5905900), (5908888, 'b', 5908892), (5908892, 'b', 5908896), (5908916, 'b', 5905748), (5911052, 'bge', 5914172), (5911072, 'blt', 5914080), (5911092, 'bge', 5914080), (5911212, 'bge', 5914076), (5911240, 'bge', 5911352), (5911304, 'b', 5911476), (5911408, 'blt', 5911472), (5911472, 'b', 5911476), (5911604, 'beq', 5914048), (5911628, 'ble', 5914044), (5914044, 'b', 5914048), (5914048, 'b', 5914052), (5914072, 'b', 5911156), (5914076, 'b', 5914080), (5914080, 'b', 5914084), (5914104, 'b', 5911004), (5915596, 'bge', 5918436), (5915616, 'blt', 5918392), (5915636, 'bge', 5918392), (5915756, 'bge', 5918388), (5915808, 'bge', 5915944), (5915920, 'b', 5916116), (5916000, 'blt', 5916112), (5916112, 'b', 5916116), (5916244, 'beq', 5918360), (5916268, 'ble', 5918360), (5918360, 'b', 5918364), (5918384, 'b', 5915700), (5918388, 'b', 5918392), (5918392, 'b', 5918396), (5918416, 'b', 5915548), (5920988, 'b', 5921012), (5921060, 'bge', 5923516), (5921080, 'blt', 5923432), (5921100, 'bge', 5923432), (5921220, 'bge', 5923428), (5921264, 'bge', 5921400), (5921368, 'b', 5921564), (5921456, 'blt', 5921560), (5921560, 'b', 5921564), (5921692, 'beq', 5923384), (5921716, 'ble', 5923384), (5923384, 'b', 5923388), (5923408, 'b', 5921164), (5923428, 'b', 5923432), (5923432, 'b', 5923436), (5923456, 'b', 5921012), (5923576, 'beq', 5924880), (5925052, 'bge', 5927496), (5925072, 'blt', 5927460), (5925092, 'bge', 5927460), (5925212, 'bge', 5927456), (5925240, 'bge', 5925332), (5925304, 'b', 5925456), (5925388, 'blt', 5925452), (5925452, 'b', 5925456), (5925584, 'beq', 5927428), (5925608, 'ble', 5927424), (5927424, 'b', 5927428), (5927428, 'b', 5927432), (5927452, 'b', 5925156), (5927456, 'b', 5927460), (5927460, 'b', 5927464), (5927484, 'b', 5925004), (5927692, 'bge', 5929984), (5927712, 'blt', 5929948), (5927732, 'bge', 5929948), (5927852, 'bge', 5929944), (5927880, 'bge', 5927968), (5927944, 'b', 5928092), (5928024, 'blt', 5928088), (5928088, 'b', 5928092), (5928220, 'beq', 5929916), (5928244, 'ble', 5929912), (5929912, 'b', 5929916), (5929916, 'b', 5929920), (5929940, 'b', 5927796), (5929944, 'b', 5929948), (5929948, 'b', 5929952), (5929972, 'b', 5927644), (5930028, 'bne', 5931196), (5931196, 'b', 5931200), (5931404, 'bge', 5933652), (5931424, 'blt', 5933540), (5931444, 'bge', 5933540), (5931564, 'bge', 5933536), (5931592, 'bge', 5931680), (5931656, 'b', 5931804), (5931736, 'blt', 5931800), (5931800, 'b', 5931804), (5931932, 'bne', 5933508), (5933508, 'b', 5933512), (5933532, 'b', 5931508), (5933536, 'b', 5933540), (5933540, 'b', 5933544), (5933564, 'b', 5931356), (5933696, 'beq', 5936660), (5933744, 'beq', 5936660), (5936652, 'b', 5936660), (5937424, 'bne', 5937484)],
        semantics=("[World render:cameraZ:projectionMatrix:pinchScale:] (imp 0x0058c7f8, **29808w** - the largest body of the entire binary's World class): **the world renderer**. Census: operator float* x154 + operator float* (Vector) x81 + **`glVertexAttribPointer` x92** (the batched-vertex pipeline!) + **`glBindTexture` x56** + **`glActiveTexture` x46** + `glUniform4f` x34 + `glEnableVertexAttribArray` x27 + `glUniform1i` x26 + `glUniformMatrix4fv` x24 + `glDisableVertexAttribArray` x22 + `glUseProgram` x18 + **`glDrawElements` x16 + `glDrawArrays` x10** + **`pushDepthMaskState`/`popDepthMaskState` x12/x11** (the depth-state stack!) + `glEnable` x12 + `clamp_float` x11 + `glDisable` x9 + `floor` x8 + `drawShaderQuad` x5 + `glBlendFunc` x5 + memcpy x3 + __modsi3/__aeabi_idiv x3 + makeIntpair x3 + objc x57 + 3 out-of-window helpers; the GL constant set: **0xbe2 (GL_BLEND)/0xde1 (GL_TEXTURE_2D)/0x1406 (GL_FLOAT)/0x1401 (GL_UNSIGNED_BYTE)/0x1403 (GL_UNSIGNED_SHORT)/0x84c0/0x84c1/0x84c2 (GL_TEXTURE0-2)/0x303 (GL_ONE_MINUS_SRC_ALPHA)/0x800 (2048)/0x432 (1074 draw range)/0x100 (256)** + float pool 0x3f80/0x3f00/0xcccd + the data cells 0xffff1dbc/0xff54a270/0xc2000000 (-32.0f!). The draw call sequence drives the whole visible world: tiles, contents, dynamic objects, sky - batched through the attrib-pointer array then drawn via elements/arrays with the depth-mask stack bracketing.\n"),
    ),
    dict(
        name='wd_01',
        method='World -[zoomUIToOnscreen:dimensions:]',
        types='v24@0:4{Vector2=[2f]}8{Vector2=[2f]}16',
        start=5940680,
        end=5943724,
        disasm='disasm_worldtileloader_wd_01.txt',
        base_add=5940696,
        base_literal=5943720,
        boundary='ARM.exidx end 0x005ab1ac (listing bound); next ObjC IMP 0x005ab1ac World -[cancelAllActionsAtPos:orWithInteractionObjectID:]',
        selectors={
                 0x5ab154: (15197184, 'mapDisplayed'),
        },
        imports={
                 0x5ab150: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5ab158: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5ab15c: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x5ab160: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
                 0x5ab168: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5ab178: (17155884, 'OBJC_IVAR_$_World.translationGoal', 632),
                 0x5ab17c: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5ab190: (17156484, 'OBJC_IVAR_$_World.followingBlockhead', 3345),
                 0x5ab194: (17156488, 'OBJC_IVAR_$_World.translatingToGoal', 640),
        },
        classes={},
        instructions=[(5940680, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5943720, 'adceq r5, fp, r4, lsl r5')],
        calls=[(5940780, 'blx r5'), (5940936, 'bl method.Vector2.operator_float__'), (5940972, 'bl method.Vector2.operator_float__'), (5941024, 'bl sym.imp.__aeabi_idiv'), (5941128, 'bl method.Vector2.operator_float__'), (5941204, 'bl method.Vector2.operator_float__'), (5941240, 'bl method.Vector2.operator_float__'), (5941296, 'bl sym.imp.__aeabi_idiv'), (5941400, 'bl method.Vector2.operator_float__'), (5941576, 'bl method.Vector2.operator__Vector2_'), (5941584, 'bl method.Vector2.operator_float__'), (5941628, 'bl sym.imp.__aeabi_idiv'), (5941712, 'bl method.Vector2.operator_float__'), (5941764, 'bl method.Vector2.operator_float__'), (5941816, 'bl sym.imp.__aeabi_idiv'), (5941900, 'bl method.Vector2.operator_float__'), (5942076, 'bl method.Vector2.Vector2_float__float_'), (5942092, 'bl method.Vector2.operator_float__'), (5942192, 'bl method.Vector2.operator_float__'), (5942356, 'bl method.Vector2.operator_float__'), (5942380, 'bl method.Vector2.operator_float__'), (5942448, 'bl method.Vector2.operator_float__'), (5942492, 'bl method.Vector2.operator_float__'), (5942520, 'bl method.Vector2.operator_float__'), (5942540, 'bl method.Vector2.operator_float__'), (5942608, 'bl method.Vector2.operator_float__'), (5942652, 'bl method.Vector2.operator_float__'), (5942680, 'bl method.Vector2.operator_float__'), (5942704, 'bl method.Vector2.operator_float__'), (5942772, 'bl method.Vector2.operator_float__'), (5942816, 'bl method.Vector2.operator_float__'), (5942852, 'bl method.Vector2.operator_float__'), (5942872, 'bl method.Vector2.operator_float__'), (5942940, 'bl method.Vector2.operator_float__'), (5942984, 'bl method.Vector2.operator_float__'), (5943072, 'bl method.Vector2.operator_float__'), (5943108, 'bl method.Vector2.operator_float__'), (5943160, 'bl sym.imp.__aeabi_idiv'), (5943264, 'bl method.Vector2.operator_float__'), (5943340, 'bl method.Vector2.operator_float__'), (5943376, 'bl method.Vector2.operator_float__'), (5943432, 'bl sym.imp.__aeabi_idiv'), (5943536, 'bl method.Vector2.operator_float__')],
        branches=[(5940792, 'beq', 5940800), (5940796, 'b', 5943624), (5940852, 'bpl', 5941488), (5941048, 'ble', 5941152), (5941148, 'b', 5941424), (5941320, 'bpl', 5941420), (5941420, 'b', 5941424), (5941484, 'b', 5943624), (5941652, 'ble', 5941740), (5941732, 'b', 5941924), (5941840, 'bpl', 5941920), (5941920, 'b', 5941924), (5942420, 'ble', 5942516), (5942512, 'b', 5942676), (5942580, 'bpl', 5942672), (5942672, 'b', 5942676), (5942744, 'ble', 5942848), (5942836, 'b', 5943008), (5942912, 'bpl', 5943004), (5943004, 'b', 5943008), (5943016, 'beq', 5943620), (5943184, 'ble', 5943288), (5943284, 'b', 5943560), (5943456, 'bpl', 5943556), (5943556, 'b', 5943560), (5943620, 'b', 5943624)],
        semantics=('[World zoomUIToOnscreen:dimensions:] (imp 0x005aa5c8, 761w): the UI zoom-to-onscreen - calls x43 (4 unclassified below window).\n'),
    ),
    dict(
        name='wd_02',
        method='World -[scrollToTap:]',
        types='v16@0:4{CGPoint=ff}8',
        start=5944764,
        end=5947692,
        disasm='disasm_worldtileloader_wd_02.txt',
        base_add=5944784,
        base_literal=5947688,
        boundary='ARM.exidx end 0x005ac12c (listing bound); next ObjC IMP 0x005ac1a4 World -[pauseUpdates]',
        selectors={},
        imports={},
        ivars={
                 0x5ac0ec: (17156600, 'OBJC_IVAR_$_World.tapModelviewMatrix', 320),
                 0x5ac0f0: (17156604, 'OBJC_IVAR_$_World.tapProjectionMatrix', 256),
                 0x5ac0f4: (17156140, 'OBJC_IVAR_$_World.tapViewport', 384),
                 0x5ac100: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5ac108: (17155884, 'OBJC_IVAR_$_World.translationGoal', 632),
                 0x5ac110: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
                 0x5ac120: (17156484, 'OBJC_IVAR_$_World.followingBlockhead', 3345),
                 0x5ac124: (17156488, 'OBJC_IVAR_$_World.translatingToGoal', 640),
        },
        classes={},
        instructions=[(5944764, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5947688, 'adceq r4, fp, ip, lsl r5')],
        calls=[(5944884, 'bl 0x58353c'), (5945740, 'bl sym.GLKMathUnproject'), (5945836, 'bl 0x58353c'), (5946692, 'bl sym.GLKMathUnproject'), (5946748, 'bl sym.reverseLinearInterpolate_float__float__float_'), (5946784, 'bl sym.linearInterpolate_float__float__float_'), (5946820, 'bl sym.linearInterpolate_float__float__float_'), (5947016, 'bl method.Vector2.Vector2_float__float_'), (5947064, 'bl method.Vector2.operator_float__'), (5947100, 'bl method.Vector2.operator_float__'), (5947152, 'bl sym.imp.__aeabi_idiv'), (5947256, 'bl method.Vector2.operator_float__'), (5947332, 'bl method.Vector2.operator_float__'), (5947368, 'bl method.Vector2.operator_float__'), (5947424, 'bl sym.imp.__aeabi_idiv'), (5947528, 'bl method.Vector2.operator_float__')],
        branches=[(5945752, 'bne', 5945760), (5945756, 'b', 5947612), (5946704, 'bne', 5946712), (5946708, 'b', 5947612), (5946844, 'bpl', 5946912), (5946908, 'b', 5946920), (5947176, 'ble', 5947280), (5947276, 'b', 5947552), (5947448, 'bpl', 5947548), (5947548, 'b', 5947552)],
        semantics=('[World scrollToTap:] (imp 0x005ab5bc, 732w): the tap scroll - calls x16 + 9 unclassified (the 0xffffc9bc shared cell).\n'),
    ),
    dict(
        name='wd_03',
        method='World -[loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:]',
        types='v16@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8c12',
        start=5979768,
        end=5980080,
        disasm='disasm_worldtileloader_wd_03.txt',
        base_add=5979784,
        base_literal=5980076,
        boundary='ARM.exidx end 0x005b3fb0 (listing bound); next ObjC IMP 0x005b3fb0 World -[loadLightBlockForClientLightBlockIndex:intoPhysicalBlock:]',
        selectors={
                 0x5b3f98: (15195892, 'init'),
                 0x5b3f9c: (15195752, 'alloc'),
                 0x5b3fa4: (15197508, 'loadDynamicObjectsForMacroTile:includeSurfaceBlocks:'),
        },
        imports={
                 0x5b3f94: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b3fa8: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x5b3fa0: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(5979768, 'push {fp, lr}'), (5980076, 'adceq fp, sl, r4, ror 24')],
        calls=[(5979936, 'blx r3'), (5979952, 'blx r2'), (5980040, 'blx ip')],
        branches=[(5979820, 'bne', 5980044), (5979840, 'beq', 5980044), (5979872, 'bne', 5979964)],
        semantics=('[World loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:] (imp 0x005b3e78, 78w): the dynamic-object lazy loader (objc x3).\n'),
    ),
    dict(
        name='wd_04',
        method='World -[loadLightBlockForClientLightBlockIndex:intoPhysicalBlock:]',
        types='v16@0:4i8^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}12',
        start=5980080,
        end=5980932,
        disasm='disasm_worldtileloader_wd_04.txt',
        base_add=5980096,
        base_literal=5980928,
        boundary='ARM.exidx end 0x005b4304 (listing bound); next ObjC IMP 0x005b4304 World -[saveLightBlockForClientLightBlockIndex:physicalBlock:sendNow:]',
        selectors={
                 0x5b42ec: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5b42f4: (15196544, 'lightBlockIndex'),
                 0x5b42f8: (15195624, 'objectForKey:'),
                 0x5b42fc: (15197512, 'loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:'),
        },
        imports={
                 0x5b42e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b42e0: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x5b42e4: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5b42f0: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
        },
        classes={},
        instructions=[(5980080, 'push {r4, r5, r6, r7, fp, lr}'), (5980928, 'adceq fp, sl, ip, lsr 22')],
        calls=[(5980324, 'bl sym.imp.memset'), (5980388, 'blx lr'), (5980488, 'bl sym.imp.objc_enumerationMutation'), (5980608, 'blx ip'), (5980624, 'blx r2'), (5980752, 'blx ip'), (5980880, 'blx ip')],
        branches=[(5980152, 'beq', 5980888), (5980192, 'beq', 5980888), (5980208, 'beq', 5980888), (5980220, 'beq', 5980888), (5980400, 'beq', 5980776), (5980480, 'beq', 5980492), (5980636, 'bne', 5980652), (5980648, 'b', 5980780), (5980652, 'b', 5980656), (5980680, 'blo', 5980444), (5980772, 'bne', 5980444), (5980776, 'b', 5980780), (5980792, 'beq', 5980884), (5980884, 'b', 5980888)],
        semantics=('[World loadLightBlockForClientLightBlockIndex:intoPhysicalBlock:] (imp 0x005b3fb0, 213w): the light-block loader - calls x7 + br x14 (the light channel wiring).\n'),
    ),
    dict(
        name='wd_05',
        method='World -[physicalBlockToLoadByClientTileLoaderForMacroTile:]',
        types='^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}12@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8',
        start=5981804,
        end=5982720,
        disasm='disasm_worldtileloader_wd_05.txt',
        base_add=5981820,
        base_literal=5982716,
        boundary='ARM.exidx end 0x005b4a00 (listing bound); next ObjC IMP 0x005b4a00 World -[loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:]',
        selectors={
                 0x5b49f4: (15195844, 'timeIntervalSinceReferenceDate'),
        },
        imports={
                 0x5b49f0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b49e0: (17156368, 'OBJC_IVAR_$_World.freePhysicalBlocks', 476),
                 0x5b49e8: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x5b49ec: (17168140, 'OBJC_IVAR_$_ServerClient.timeSinceLastHeartbeatRequest', 60),
        },
        classes={
                 0x5b49f8: (15245312, 'OBJC_CLASS_$_NSDate'),
        },
        instructions=[(5981804, 'push {r4, r5, fp, lr}'), (5982716, 'adceq fp, sl, r0, ror r4')],
        calls=[(5981948, 'bl sym.imp.__wrap_calloc'), (5982004, 'bl sym.imp.__wrap_calloc'), (5982064, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_'), (5982364, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.__insert_unique_PhysicalBlock_const_'), (5982516, 'bl method.std::__1::__hash_table_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.erase_std::__1::__hash_const_iterator_std::__1::__hash_node_PhysicalBlock__void__const__'), (5982648, 'blx r2')],
        branches=[(5981864, 'bne', 5982584), (5981936, 'bne', 5982164), (5981968, 'bne', 5981984), (5981980, 'b', 5982676), (5982160, 'b', 5982564), (5982596, 'beq', 5982668)],
        semantics=('[World physicalBlockToLoadByClientTileLoaderForMacroTile:] (imp 0x005b466c, 229w): the physical-block selector (objc x1 + calls x6).\n'),
    ),
    dict(
        name='wd_06',
        method='World -[fullyLoadAndUpdateIfNeededForMacroBlock:includingPos:clientLightBlockIndex:forBlockhead:]',
        types='v28@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8{?=ii}12i20@24',
        start=5990040,
        end=5990432,
        disasm='disasm_worldtileloader_wd_06.txt',
        base_add=5990056,
        base_literal=5990428,
        boundary='ARM.exidx end 0x005b6820 (listing bound); next ObjC IMP 0x005b6820 World -[fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:]',
        selectors={
                 0x5b6810: (15197140, 'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:'),
                 0x5b6814: (15197576, 'recalculateLightingForPhysicalBlockIfNeeded:world:clientLightBlockIndex:forBlockhead:'),
        },
        imports={
                 0x5b680c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b6808: (17155972, 'OBJC_IVAR_$_World.client', 960),
        },
        classes={
                 0x5b6818: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(5990040, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5990428, 'adceq sb, sl, r4, asr 8')],
        calls=[(5990152, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5990320, 'blx r4'), (5990352, 'blx ip')],
        branches=[(5990116, 'beq', 5990400), (5990136, 'bne', 5990160), (5990196, 'bne', 5990396), (5990372, 'beq', 5990392), (5990392, 'b', 5990396), (5990396, 'b', 5990400)],
        semantics=('[World fullyLoadAndUpdateIfNeededForMacroBlock:includingPos:clientLightBlockIndex:forBlockhead:] (imp 0x005b6698, 98w): the macro-block full-load cascade.\n'),
    ),
    dict(
        name='wd_07',
        method='World -[fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:]',
        types='v24@0:4{?=ii}8i16@20',
        start=5990432,
        end=5992360,
        disasm='disasm_worldtileloader_wd_07.txt',
        base_add=5990448,
        base_literal=5992356,
        boundary='ARM.exidx end 0x005b6fa8 (listing bound); next ObjC IMP 0x005b6fa8 World -[craftItemFinished:atWorkbench:allFinished:blockhead:]',
        selectors={
                 0x5b6f8c: (15197580, 'fullyLoadAndUpdateIfNeededForMacroBlock:includingPos:clientLightBlockIndex:forBlockhead:'),
        },
        imports={},
        ivars={
                 0x5b6f84: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={},
        instructions=[(5990432, 'push {r4, r5, r6, r7, fp, lr}'), (5992356, 'invalid')],
        calls=[(5990556, 'bl sym.makeIntpair_int__int_'), (5990584, 'bl sym.makeIntpair_int__int_'), (5990648, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5990692, 'bl sym.makeIntpair_int__int_'), (5990760, 'bl loc.imp.objc_msgSend'), (5990800, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5990844, 'bl sym.makeIntpair_int__int_'), (5990904, 'bl loc.imp.objc_msgSend'), (5990944, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5990988, 'bl sym.makeIntpair_int__int_'), (5991048, 'bl loc.imp.objc_msgSend'), (5991088, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5991132, 'bl sym.makeIntpair_int__int_'), (5991192, 'bl loc.imp.objc_msgSend'), (5991228, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5991304, 'bl sym.makeIntpair_int__int_'), (5991368, 'bl loc.imp.objc_msgSend'), (5991424, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5991500, 'bl sym.makeIntpair_int__int_'), (5991564, 'bl loc.imp.objc_msgSend'), (5991620, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5991728, 'bl sym.makeIntpair_int__int_'), (5991792, 'bl loc.imp.objc_msgSend'), (5991848, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5991956, 'bl sym.makeIntpair_int__int_'), (5992020, 'bl loc.imp.objc_msgSend'), (5992076, 'bl sym.macroTileAtWorldPostion_int__int__MacroTile__World_'), (5992248, 'bl sym.makeIntpair_int__int_'), (5992312, 'bl loc.imp.objc_msgSend')],
        branches=[(5991248, 'beq', 5991372), (5991264, 'beq', 5991372), (5991444, 'beq', 5991568), (5991460, 'beq', 5991568), (5991640, 'beq', 5991796), (5991656, 'beq', 5991796), (5991672, 'beq', 5991796), (5991688, 'beq', 5991796), (5991868, 'beq', 5992024), (5991884, 'beq', 5992024), (5991900, 'beq', 5992024), (5991916, 'beq', 5992024), (5992096, 'beq', 5992316), (5992112, 'beq', 5992316), (5992128, 'beq', 5992316), (5992144, 'beq', 5992316), (5992160, 'beq', 5992316), (5992176, 'beq', 5992316), (5992192, 'beq', 5992316), (5992208, 'beq', 5992316)],
        semantics=('[World fullyLoadIfNeededAroundPos:clientLightBlockIndex:forBlockhead:] (imp 0x005b6820, 482w): the around-pos full loader - calls x29 + br x20 (the 3x3 macro sweep).\n'),
    ),
    dict(
        name='wd_08',
        method='World -[doPortalScreenshot]',
        types='v8@0:4',
        start=6040000,
        end=6042232,
        disasm='disasm_worldtileloader_wd_08.txt',
        base_add=6040020,
        base_literal=6042228,
        boundary='ARM.exidx end 0x005c3278 (listing bound); next ObjC IMP 0x005c3278 World -[doCameraScreenshot]',
        selectors={
                 0x5c3250: (15197844, 'render:cameraZ:projectionMatrix:pinchScale:'),
                 0x5c3258: (15197572, 'exitWorld'),
                 0x5c3264: (15195732, 'retain'),
                 0x5c3268: (15195768, 'release'),
                 0x5c326c: (15195552, 'dataWithBytes:length:'),
        },
        imports={
                 0x5c3254: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c3230: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5c3234: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
                 0x5c3238: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
                 0x5c323c: (17156500, 'OBJC_IVAR_$_World.needsToDoPortalScreenshot', 3073),
                 0x5c3248: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x5c324c: (17155888, 'OBJC_IVAR_$_World.roundedTranslation', 616),
                 0x5c3260: (17156000, 'OBJC_IVAR_$_World.portalScreenshotData', 3076),
        },
        classes={
                 0x5c3270: (15245320, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(6040000, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6042228, 'adceq sp, sb, r8, lsl r1')],
        calls=[(6040140, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6040236, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6040332, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6040428, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6040648, 'bl 0x5aa3b0'), (6040692, 'bl sym.imp.tanf'), (6041032, 'bl method.Vector2.Vector2_float__float_'), (6041096, 'bl sym.imp.__wrap_glViewport'), (6041472, 'bl loc.imp.objc_msgSend'), (6041552, 'bl sym.imp.__wrap_malloc'), (6041576, 'bl sym.imp.__wrap_glPixelStorei'), (6041668, 'bl sym.imp.__wrap_glReadPixels'), (6041736, 'blx ip'), (6041748, 'bl sym.imp.__wrap_free'), (6041828, 'blx r2'), (6041848, 'blx r2'), (6041936, 'blx r2'), (6042016, 'bl sym.imp.memcpy'), (6042108, 'bl sym.imp.__wrap_glViewport')],
        branches=[(6040068, 'beq', 6040460), (6040160, 'bne', 6040168), (6040164, 'b', 6042152), (6040256, 'bne', 6040264), (6040260, 'b', 6042152), (6040352, 'bne', 6040360), (6040356, 'b', 6042152), (6040448, 'bne', 6040456), (6040452, 'b', 6042152), (6040456, 'b', 6040460), (6040492, 'beq', 6040504), (6040496, 'b', 6042152), (6041592, 'beq', 6041876), (6041872, 'b', 6041940)],
        semantics=('[World doPortalScreenshot] (imp 0x005c29c0, 558w): the portal screenshot capture (objc x5 + 0xffffc9bc/0xffed2e68 cells).\n'),
    ),
    dict(
        name='wd_09',
        method='World -[exportCurrentFrame]',
        types='v8@0:4',
        start=6043648,
        end=6044964,
        disasm='disasm_worldtileloader_wd_09.txt',
        base_add=6043664,
        base_literal=6044960,
        boundary='ARM.exidx end 0x005c3d24 (listing bound); next ObjC IMP 0x005c3d24 World -[startUsingCamera]',
        selectors={
                 0x5c3cd4: (15195808, 'fileExistsAtPath:'),
                 0x5c3cd8: (15195804, 'defaultManager'),
                 0x5c3ce4: (15195708, 'stringWithFormat:'),
                 0x5c3ce8: (15195800, 'objectAtIndex:'),
                 0x5c3cf0: (15197860, 'rotate:'),
                 0x5c3cf4: (15197200, 'imageWithCGImage:'),
                 0x5c3d0c: (15195948, 'createDirectoryAtPath:withIntermediateDirectories:attributes:error:'),
                 0x5c3d10: (15197204, 'writeToFile:atomically:'),
                 0x5c3d14: (15196032, 'stringByAppendingPathComponent:'),
        },
        imports={
                 0x5c3cd0: (17151904, 'objc_msgSend'),
                 0x5c3ce0: (16232840, '__CFConstantStringClassReference'),
                 0x5c3d18: (16232856, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5c3cfc: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x5c3d1c: (17156712, 'OBJC_IVAR_$_World.frameCounter', 3104),
        },
        classes={
                 0x5c3cdc: (15245324, 'OBJC_CLASS_$_NSFileManager'),
                 0x5c3cec: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5c3cf8: (15245476, 'OBJC_CLASS_$_UIImage'),
        },
        instructions=[(6043648, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6044960, 'invalid')],
        calls=[(6043800, 'bl sym.imp.__wrap_malloc'), (6043852, 'bl sym.imp.__wrap_glReadPixels'), (6043880, 'bl sym.imp.CGDataProviderCreateWithData'), (6043916, 'bl sym.imp.CGColorSpaceCreateDeviceRGB'), (6044036, 'bl sym.imp.CGImageCreate'), (6044128, 'blx r4'), (6044164, 'blx r3'), (6044176, 'bl sym.UIImagePNGRepresentation'), (6044228, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (6044368, 'blx sl'), (6044404, 'blx ip'), (6044440, 'blx r3'), (6044460, 'blx r3'), (6044556, 'blx r2'), (6044596, 'blx lr'), (6044768, 'blx r5'), (6044800, 'blx r3'), (6044836, 'blx ip'), (6044852, 'bl sym.imp.CGColorSpaceRelease'), (6044860, 'bl sym.imp.CGDataProviderRelease'), (6044868, 'bl sym.imp.__wrap_free')],
        branches=[(6044472, 'bne', 6044604)],
        semantics=('[World exportCurrentFrame] (imp 0x005c3800, 329w): the frame exporter - objc x9 + imp x3.\n'),
    ),
    dict(
        name='wd_10',
        method='World -[zoomToPoint:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=6053088,
        end=6053800,
        disasm='disasm_worldtileloader_wd_10.txt',
        base_add=6053104,
        base_literal=6053796,
        boundary='ARM.exidx end 0x005c5fa8 (listing bound); next ObjC IMP 0x005c5fa8 World -[zoomToPos:pinchZoom:]',
        selectors={},
        imports={},
        ivars={
                 0x5c5f80: (17155884, 'OBJC_IVAR_$_World.translationGoal', 632),
                 0x5c5f88: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
                 0x5c5f8c: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5c5f9c: (17156484, 'OBJC_IVAR_$_World.followingBlockhead', 3345),
                 0x5c5fa0: (17156488, 'OBJC_IVAR_$_World.translatingToGoal', 640),
        },
        classes={},
        instructions=[(6053088, 'push {r4, r5, r6, r7, fp, lr}'), (6053796, 'invalid')],
        calls=[(6053204, 'bl method.Vector2.operator_float__'), (6053240, 'bl method.Vector2.operator_float__'), (6053292, 'bl sym.imp.__aeabi_idiv'), (6053396, 'bl method.Vector2.operator_float__'), (6053472, 'bl method.Vector2.operator_float__'), (6053508, 'bl method.Vector2.operator_float__'), (6053564, 'bl sym.imp.__aeabi_idiv'), (6053668, 'bl method.Vector2.operator_float__')],
        branches=[(6053316, 'ble', 6053420), (6053416, 'b', 6053692), (6053588, 'bpl', 6053688), (6053688, 'b', 6053692)],
        semantics=('[World zoomToPoint:] (imp 0x005c5ce0, 178w): the zoom-to-point (calls x8).\n'),
    ),
    dict(
        name='wd_11',
        method='World -[zoomToPos:pinchZoom:]',
        types='v20@0:4{?=ii}8c16',
        start=6053800,
        end=6054060,
        disasm='disasm_worldtileloader_wd_11.txt',
        base_add=6053816,
        base_literal=6054056,
        boundary='ARM.exidx end 0x005c60ac (listing bound); next ObjC IMP 0x005c60ac World -[activeBlockheadPos]',
        selectors={
                 0x5c6098: (15197952, 'pinchZoomToScale:'),
                 0x5c60a0: (15197956, 'zoomToPoint:'),
        },
        imports={
                 0x5c6094: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6053800, 'push {fp, lr}'), (6054056, 'adceq sb, sb, r4, lsr fp')],
        calls=[(6053940, 'blx r3'), (6053992, 'bl method.Vector2.Vector2_float__float_'), (6054024, 'bl loc.imp.objc_msgSend')],
        branches=[(6053856, 'beq', 6053944)],
        semantics=('[World zoomToPos:pinchZoom:] (imp 0x005c5fa8, 65w): the zoom-to-pos wrapper.\n'),
    ),
    dict(
        name='wd_12',
        method='World -[markCircumNavigateX:]',
        types='v12@0:4i8',
        start=6054932,
        end=6056088,
        disasm='disasm_worldtileloader_wd_12.txt',
        base_add=6054948,
        base_literal=6056084,
        boundary='ARM.exidx end 0x005c6898 (listing bound); next ObjC IMP 0x005c6898 World -[showDoubleTimePromptIfGoodTime]',
        selectors={
                 0x5c6870: (15196752, 'containsIndex:'),
                 0x5c687c: (15196176, 'addIndex:'),
                 0x5c6888: (15195604, 'count'),
                 0x5c6890: (15197604, 'reportAchievementWithIdentifier:'),
        },
        imports={
                 0x5c686c: (17151904, 'objc_msgSend'),
                 0x5c688c: (16232952, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5c685c: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5c6874: (17156048, 'OBJC_IVAR_$_World.circumNavigateBooleans', 3084),
        },
        classes={},
        instructions=[(6054932, 'push {r4, r5, r6, sl, fp, lr}'), (6056084, 'adceq sb, sb, r8, asr 13')],
        calls=[(6055212, 'blx r3'), (6055320, 'bl loc.imp.objc_msgSend'), (6055380, 'bl sym.imp.__modsi3'), (6055412, 'blx r3'), (6055512, 'blx r3'), (6055612, 'blx r3'), (6055728, 'bl sym.imp.__modsi3'), (6055760, 'blx r3'), (6055840, 'blx r3'), (6055908, 'bl loc.imp.objc_msgSend'), (6056012, 'blx ip')],
        branches=[(6054976, 'bge', 6055036), (6055032, 'b', 6055144), (6055084, 'blt', 6055140), (6055140, 'b', 6055144), (6055224, 'bne', 6056020), (6055424, 'bne', 6055852), (6055436, 'ble', 6055848), (6055524, 'bne', 6055848), (6055536, 'ble', 6055768), (6055624, 'bne', 6055768), (6055764, 'b', 6055844), (6055844, 'b', 6055848), (6055848, 'b', 6055852), (6055948, 'blo', 6056016), (6056016, 'b', 6056020)],
        semantics=('[World markCircumNavigateX:] (imp 0x005c6414, 289w): the circum-navigate marker - calls x11 + br x15.\n'),
    ),
    dict(
        name='wd_13',
        method='World -[renderingTeaserFrames]',
        types='c8@0:4',
        start=6116660,
        end=6116740,
        disasm='disasm_worldtileloader_wd_13.txt',
        base_add=6116668,
        base_literal=6116736,
        boundary='ARM.exidx end 0x005d5584 (listing bound); next ObjC IMP 0x005d5584 World -[customRules]',
        selectors={},
        imports={},
        ivars={
                 0x5d557c: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068),
        },
        classes={},
        instructions=[(6116660, 'sub sp, sp, 8'), (6116736, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[World renderingTeaserFrames] (imp 0x005d5534, 20w): the teaser-frames flag.\n'),
    ),
]


def signed(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)
    elf = ELFFile(io.BytesIO(data))

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in elf.iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)
    relocs = {}
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        syms = elf.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            if r['r_info_sym']:
                relocs[r['r_offset']] = syms.get_symbol(r['r_info_sym']).name

    methods = []
    for spec in SPECS:
        text = (NATIVE / spec['disasm']).read_text()
        words = verify_disassembly(memory, text, spec['start'], spec['end'])
        rows = {}
        for mm in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
            rows[int(mm.group(1), 16)] = mm.group(2).split(';')[0].strip()

        base = None
        if spec['base_add'] is not None:
            base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
            if base != EXPECTED_BASE:
                raise ValueError(f"{spec['name']}: PIC base drift {base:#x}")

        selectors = {}
        for cell, (expected_slot, expected_name) in spec['selectors'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: selector cell {cell:#x} -> {slot:#x}")
            got = cstr(memory.word(slot))
            if got != expected_name:
                raise ValueError(f"{spec['name']}: selector drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            if entry is None:
                got = relocs.get(slot, '')
                if got != expected_symbol:
                    raise ValueError(f"{spec['name']}: class reloc drifted at {cell:#x}: {got!r}")
                selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                              'route': 'ABS32 relocation symbol'}
                continue
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                          'route': 'dynsym entry at slot word'}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            route = 'PLT/GOT relocation (R_ARM_JUMP_SLOT / GLOB_DAT)'
            if got is None:
                got = relocs.get(slot)
                route = 'ABS32 relocation symbol'
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r} ({route})")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got, 'route': route}

        ivars = {}
        for cell, (expected_slot, expected_symbol, expected_offset) in spec['ivars'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: ivar cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            symbol = dynsym.get(entry, '')
            offset = memory.word(entry)
            if symbol != expected_symbol or offset != expected_offset:
                raise ValueError(f"{spec['name']}: ivar {cell:#x} drifted: {symbol!r}@{offset}")
            ivars[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'symbol': symbol, 'offset': offset}

        inrange = {a: ins for a, ins in rows.items() if spec['start'] <= a < spec['end']}
        listed = {a for a, ins in inrange.items() if re.match(r'^blx?\s', ins)}
        expected_sites = {site for site, _ in spec['calls']}
        if listed != expected_sites:
            raise ValueError(f"{spec['name']}: call set drifted: {sorted(listed ^ expected_sites)}")
        calls = []
        for site, route in spec['calls']:
            if rows[site] != route:
                raise ValueError(f"{spec['name']}: route drifted at {site:#x}: {rows[site]!r}")
            target = None
            if route.startswith('bl '):
                target = bl_target(site, memory.word(site))
                expected = ROUTE_TARGETS.get(route)
                if expected is None or target != expected:
                    raise ValueError(f"{spec['name']}: bl target drifted at {site:#x}: {target:#x}")
            calls.append({'site': f'0x{site:08x}', 'route': route,
                          'callee': f'0x{target:08x}' if target else None})

        listed_branches = set()
        disjoint = []
        for a, ins in inrange.items():
            m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
            if not m or m.group(1) in ('bl', 'blx'):
                continue
            dest = int(m.group(2), 16)
            if spec['start'] <= dest < spec['end']:
                listed_branches.add((a, m.group(1), dest))
            else:
                disjoint.append({'address': f'0x{a:08x}', 'mnemonic': m.group(1),
                                 'destination': f'0x{dest:08x}'})
        expected_branches = {(a, mn, dest) for a, mn, dest in spec['branches']}
        if listed_branches != expected_branches:
            raise ValueError(f"{spec['name']}: branch set drifted: {sorted(listed_branches ^ expected_branches)}")

        for address, expected_text in spec['instructions']:
            if rows.get(address) != expected_text:
                raise ValueError(f"{spec['name']}: instruction drifted at {address:#x}: "
                                 f"{rows.get(address)!r} != {expected_text!r}")

        methods.append({
            'name': spec['name'],
            'method': spec['method'],
            'types': spec['types'],
            'imp': f"0x{spec['start']:08x}",
            'boundary_end': f"0x{spec['end']:08x}",
            'boundary': spec['boundary'],
            'verified_words': words,
            'pic_base': f'0x{base:08x}' if base else None,
            'selectors': selectors,
            'ivars': ivars,
            'calls': calls,
            'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                          'destination': f'0x{d:08x}'}
                         for a, mn, d in spec['branches']],
            'disjoint_branch_rows': disjoint,
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'World renderer (E102): the 29808w draw giant and the load/zoom family; 14 bodies',
        'claim': ('a static bounded-body map with per-instruction anchors; the wire-format markers, the '
                  'NSLog key strings, the C++ container member layouts and the packet helper at 0x8b84c8 are '
                  'outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_render.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_render.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
