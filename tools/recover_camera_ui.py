#!/usr/bin/env python3
"""Hash-gated recovery of the CameraUI photo-mode domain.

21 bodies, 3024 instruction words total, from the pinned original libApplication.so (1.7.6, armeabi-v7a):
CameraUI (initWithWorld:windowInfo:cache: 1080w, dealloc 64w, windowInfoChanged: 469w, render:translation:pinchScale: 268w,
touchIsInViewAtAll: 32w, touchIsInUI: 78w, startTouch:tapCount: 99w, moveTouch: 66w, endTouch: 66w, cancelButton: 26w, takePhotoButton: 26w);
UIManager showCameraUI / dismissCameraUI / setDismissCameraUI: (28/15/17w); World doCameraScreenshot (354w), startUsingCamera (59w),
takePhotoButtonTapped (43w), cancelTakePhotoButtonTapped (93w), takingPhoto (33w), sharePhotoFinished (93w), hasJustTakenPhoto (15w).
Every instruction word is re-verified; tool refuses to emit on drift.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl 0x9d522c': 0X009D522C,
    'bl 0x9d5384': 0X009D5384,
    'bl loc.imp.objc_msgSend': 0X001C281C,
    'bl loc.imp.objc_msgSendSuper2': 0X001C29FC,
    'bl sym.UIImageWriteToSavedPhotosAlbum': 0X00256560,
    'bl sym.imp.CGColorSpaceCreateDeviceRGB': 0X001C311C,
    'bl sym.imp.CGColorSpaceRelease': 0X001C2F18,
    'bl sym.imp.CGDataProviderCreateWithData': 0X001C3428,
    'bl sym.imp.CGDataProviderRelease': 0X001C3FBC,
    'bl sym.imp.CGImageCreate': 0X001C3434,
    'bl sym.imp.__wrap_free': 0X001C2E64,
    'bl sym.imp.__wrap_glDisable': 0X001C2C48,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0X001C3D58,
    'bl sym.imp.__wrap_glEnable': 0X001C2B04,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0X001C2D5C,
    'bl sym.imp.__wrap_glReadPixels': 0X001C3FE0,
    'bl sym.imp.__wrap_malloc': 0X001C2E58,
    'bl sym.imp.memcpy': 0X001C2894,
    'bl sym.texCoordsForItemType_ItemType_': 0X004D6040,
}

SPECS = [
    dict(
        name='cam_init',
        method='CameraUI -[initWithWorld:windowInfo:cache:]',
        types='@20@0:4@8^{WindowInfo=ffffffff}12@16',
        start=10305868,
        end=10310188,
        disasm='disasm_cameraui_initwithworld.txt',
        base_add=10305888,
        base_literal=10309780,
        boundary='body 0x009d414c..0x009d522c; helpers 0x009d522c / 0x009d5384 (IMP gap, out of body) pinned as call targets',
        selectors={10309788: (15221824, 'init'), 10310040: (15221836, 'alloc'), 10310060: (15221832, 'shaderNamed:attributes:uniforms:'), 10310072: (15221828, 'arrayWithObjects:'), 10310096: (15221860, 'setTarget:action:'), 10310100: (15221856, 'cancelButton:'), 10310108: (15221852, 'setBackgroundSelectedTexture:'), 10310116: (15221844, 'textureNamed:'), 10310120: (15221848, 'setBackgroundTexture:'), 10310140: (15221840, 'initWithFrame:cache:windowInfo:title:'), 10310164: (15221868, 'setGlyphTexture:minTexX:maxTexX:minTexY:maxTexY:'), 10310172: (15221864, 'takePhotoButton:'), 10310180: (15221872, 'setGlyphFrame:')},
        imports={10309784: (17151900, 'objc_msgSendSuper2'), 10310036: (17151904, 'objc_msgSend')},
        ivars={10310032: (17163864, 'OBJC_IVAR_$_CameraUI.windowInfo', 96), 10310048: (17163868, 'OBJC_IVAR_$_CameraUI.orthoMatrix', 32), 10310052: (17163872, 'OBJC_IVAR_$_CameraUI.borderLineShader', 24), 10310084: (17163876, 'OBJC_IVAR_$_CameraUI.cache', 100), 10310088: (17163880, 'OBJC_IVAR_$_CameraUI.world', 20), 10310104: (17163884, 'OBJC_IVAR_$_CameraUI.cancelButton', 104), 10310144: (17163888, 'OBJC_IVAR_$_CameraUI.takePhotoButton', 108)},
        classes={10309792: (15252988, 'OBJC_CLASS_$_CameraUI'), 10310044: (15248656, 'OBJC_CLASS_$_MJButton')},
        instructions=[(10305868, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10305972, 'blx r5'), (10306612, 'bl 0x9d522c'), (10306988, 'bl 0x9d5384'), (10306724, 'bl sym.imp.memcpy'), (10310024, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Photo-mode UI construction: objc_msgSendSuper2 init; nil guard; stores World@20 / windowInfo@96 / cache@100 / owner; creates the border-line shader via [X shaderNamed:attributes:uniforms:] (borderLineShader@24) and the two buttons via initWithFrame:cache:windowInfo:title: (cancelButton@104 / takePhotoButton@108) with textureNamed: / setBackgroundTexture: / setBackgroundSelectedTexture:; computes the button geometry (helpers 0x9d522c + 0x9d5384, constant family +/-1000 / -125 / 120 / 40 bounds); memcpy 0x40 bytes; return self.'),
        calls=[(10305972, 'blx r5'), (10306356, 'blx ip'), (10306404, 'blx lr'), (10306448, 'blx lr'), (10306612, 'bl 0x9d522c'), (10306724, 'bl sym.imp.memcpy'), (10306756, 'blx r3'), (10306988, 'bl 0x9d5384'), (10307136, 'bl 0x9d5384'), (10307588, 'bl loc.imp.objc_msgSend'), (10307676, 'blx lr'), (10307708, 'blx r3'), (10307776, 'blx lr'), (10307808, 'blx r3'), (10307856, 'blx lr'), (10307888, 'blx r3'), (10308120, 'bl 0x9d5384'), (10308276, 'bl 0x9d5384'), (10308476, 'bl loc.imp.objc_msgSend'), (10308816, 'blx r5'), (10308848, 'blx r3'), (10309160, 'blx r8'), (10309192, 'blx r3'), (10309240, 'blx lr'), (10309252, 'bl sym.texCoordsForItemType_ItemType_'), (10309404, 'blx ip'), (10309496, 'blx ip'), (10309772, 'bl 0x9d5384'), (10309952, 'bl 0x9d5384'), (10310004, 'bl loc.imp.objc_msgSend')],
        branches=[(10306000, 'bne', 10306016), (10306012, 'b', 10310016), (10306800, 'bmi', 10306860), (10306856, 'bpl', 10307004), (10306992, 'b', 10307140), (10307932, 'bmi', 10307992), (10307988, 'bpl', 10308136), (10308124, 'b', 10308280), (10308588, 'bmi', 10308656), (10308944, 'bmi', 10309012), (10309560, 'bmi', 10309620), (10309616, 'bpl', 10309796), (10309776, 'b', 10309956)],
    ),
    dict(
        name='cam_dealloc',
        method='CameraUI -[dealloc]',
        types='v8@0:4',
        start=10310608,
        end=10310864,
        disasm='disasm_cameraui_dealloc.txt',
        base_add=10310624,
        base_literal=10310860,
        boundary='consecutive IMPs: [windowInfoChanged:] follows at 0x009d54d0',
        selectors={10310836: (15221880, 'dealloc'), 10310848: (15221876, 'release')},
        imports={10310832: (17151900, 'objc_msgSendSuper2'), 10310844: (17151904, 'objc_msgSend')},
        ivars={10310852: (17163884, 'OBJC_IVAR_$_CameraUI.cancelButton', 104), 10310856: (17163888, 'OBJC_IVAR_$_CameraUI.takePhotoButton', 108)},
        classes={10310840: (15252988, 'OBJC_CLASS_$_CameraUI')},
        instructions=[(10310608, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10310744, 'blx r5'), (10310780, 'blx r3'), (10310820, 'blx r2'), (10310828, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Teardown: message chain releasing the view objects (ivars eb78 / eb7c) then objc_msgSendSuper2(super, dealloc).'),
        calls=[(10310744, 'blx r5'), (10310780, 'blx r3'), (10310820, 'blx r2')],
        branches=[],
    ),
    dict(
        name='cam_wininfo',
        method='CameraUI -[windowInfoChanged:]',
        types='v12@0:4^{WindowInfo=ffffffff}8',
        start=10310864,
        end=10312740,
        disasm='disasm_cameraui_windowinfochanged.txt',
        base_add=10310884,
        base_literal=10312736,
        boundary='consecutive IMPs: [render:translation:pinchScale:] follows at 0x009d5c24',
        selectors={10312716: (15221884, 'setFrame:'), 10312728: (15221872, 'setGlyphFrame:')},
        imports={},
        ivars={10312696: (17163864, 'OBJC_IVAR_$_CameraUI.windowInfo', 96), 10312700: (17163884, 'OBJC_IVAR_$_CameraUI.cancelButton', 104), 10312704: (17163868, 'OBJC_IVAR_$_CameraUI.orthoMatrix', 32), 10312712: (17163888, 'OBJC_IVAR_$_CameraUI.takePhotoButton', 108)},
        classes={},
        instructions=[(10310864, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10311084, 'bl 0x9d522c'), (10311424, 'bl 0x9d5384'), (10311172, 'bl sym.imp.memcpy'), (10311672, 'bl loc.imp.objc_msgSend'), (10312688, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('windowInfoChanged: stores the new WindowInfo@eb64; reads the size floats; recomputes the four button rects (helper 0x9d522c once + 0x9d5384 x4 with constants +/-1000, -125, 120, 49, -52, 64, 5, -60); memcpy 0x40 bytes from WindowInfo; applies the layout via objc_msgSend.'),
        calls=[(10311084, 'bl 0x9d522c'), (10311172, 'bl sym.imp.memcpy'), (10311424, 'bl 0x9d5384'), (10311564, 'bl 0x9d5384'), (10311672, 'bl loc.imp.objc_msgSend'), (10311924, 'bl 0x9d5384'), (10312076, 'bl 0x9d5384'), (10312184, 'bl loc.imp.objc_msgSend'), (10312460, 'bl 0x9d5384'), (10312628, 'bl 0x9d5384'), (10312680, 'bl loc.imp.objc_msgSend')],
        branches=[(10311236, 'bmi', 10311296), (10311292, 'bpl', 10311432), (10311428, 'b', 10311568), (10311736, 'bmi', 10311796), (10311792, 'bpl', 10311936), (10311928, 'b', 10312080), (10312248, 'bmi', 10312308), (10312304, 'bpl', 10312472), (10312464, 'b', 10312632)],
    ),
    dict(
        name='cam_render',
        method='CameraUI -[render:translation:pinchScale:]',
        types='v24@0:4f8{Vector2=[2f]}12f20',
        start=10312740,
        end=10313812,
        disasm='disasm_cameraui_render.txt',
        base_add=10312836,
        base_literal=10313784,
        boundary='consecutive IMPs: [touchIsInViewAtAll:] follows at 0x009d6054',
        selectors={10313788: (15221888, 'render:translation:pinchScale:'), 10313804: (15221892, 'renderFrame:projectionMatrix:')},
        imports={},
        ivars={10313792: (17163884, 'OBJC_IVAR_$_CameraUI.cancelButton', 104), 10313800: (17163868, 'OBJC_IVAR_$_CameraUI.orthoMatrix', 32), 10313808: (17163888, 'OBJC_IVAR_$_CameraUI.takePhotoButton', 108)},
        classes={10313780: (15252988, 'OBJC_CLASS_$_CameraUI')},
        instructions=[(10312740, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10312888, 'bl loc.imp.objc_msgSendSuper2'), (10312908, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (10312920, 'movw r0, 0xbe2'), (10313752, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (10313776, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('objc_msgSendSuper2(super, render:translation:pinchScale:); then GL work: glEnableVertexAttribArray(0) / (1), glEnable(GL_BLEND 0xbe2); submits two 16-float _GLKMatrix4 uniform packets (shader objects from ivars eb78 / eb7c via the ffe24990 selector) with objc_msgSend x2; glDisableVertexAttribArray x2 + glDisable(GL_BLEND) restore.'),
        calls=[(10312888, 'bl loc.imp.objc_msgSendSuper2'), (10312908, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (10312916, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (10312924, 'bl sym.imp.__wrap_glEnable'), (10313356, 'bl loc.imp.objc_msgSend'), (10313744, 'bl loc.imp.objc_msgSend'), (10313752, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (10313760, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (10313768, 'bl sym.imp.__wrap_glDisable')],
        branches=[],
    ),
    dict(
        name='cam_tiview',
        method='CameraUI -[touchIsInViewAtAll:]',
        types='c16@0:4{CGPoint=ff}8',
        start=10313812,
        end=10313940,
        disasm='disasm_cameraui_touchisinviewatall.txt',
        base_add=10313824,
        base_literal=10313936,
        boundary='consecutive IMPs: [touchIsInUI:] follows at 0x009d60d4',
        selectors={},
        imports={},
        ivars={10313932: (17163864, 'OBJC_IVAR_$_CameraUI.windowInfo', 96)},
        classes={},
        instructions=[(10313812, 'push {r4, lr}'), (10313880, 'vsub.f32 s0, s0, s2'), (10313928, 'pop {r4, pc}')],
        semantics=('touchIsInViewAtAll: computes (touch - view.origin) deltas (view object from ivar eb64 chain; floats at +8 / +0xc) and returns YES unconditionally.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='cam_tiui',
        method='CameraUI -[touchIsInUI:]',
        types='c16@0:4{CGPoint=ff}8',
        start=10313940,
        end=10314252,
        disasm='disasm_cameraui_touchisinui.txt',
        base_add=10313988,
        base_literal=10314232,
        boundary='consecutive IMPs: [startTouch:tapCount:] follows at 0x009d620c',
        selectors={10314240: (15221896, 'touchIsInUI:')},
        imports={},
        ivars={10314228: (17163864, 'OBJC_IVAR_$_CameraUI.windowInfo', 96), 10314236: (17163884, 'OBJC_IVAR_$_CameraUI.cancelButton', 104), 10314244: (17163888, 'OBJC_IVAR_$_CameraUI.takePhotoButton', 108)},
        classes={},
        instructions=[(10313940, 'push {fp, lr}'), (10314100, 'bl loc.imp.objc_msgSend'), (10314224, 'pop {fp, pc}')],
        semantics=('touchIsInUI: = deltas then [cancelButton touchIsInUI:pt] || [takePhotoButton touchIsInUI:pt] (same-selector forwards to the two button objects).'),
        calls=[(10314100, 'bl loc.imp.objc_msgSend'), (10314184, 'bl loc.imp.objc_msgSend')],
        branches=[(10314120, 'bne', 10314208)],
    ),
    dict(
        name='cam_start',
        method='CameraUI -[startTouch:tapCount:]',
        types='c20@0:4{CGPoint=ff}8i16',
        start=10314252,
        end=10314648,
        disasm='disasm_cameraui_starttouch.txt',
        base_add=10314268,
        base_literal=10314644,
        boundary='consecutive IMPs: [moveTouch:] follows at 0x009d6398',
        selectors={10314632: (15221900, 'startTouch:')},
        imports={},
        ivars={10314620: (17163864, 'OBJC_IVAR_$_CameraUI.windowInfo', 96), 10314624: (17163884, 'OBJC_IVAR_$_CameraUI.cancelButton', 104), 10314636: (17163888, 'OBJC_IVAR_$_CameraUI.takePhotoButton', 108)},
        classes={},
        instructions=[(10314252, 'push {r4, r5, fp, lr}'), (10314492, 'strb r0, [fp, -0x1d]'), (10314616, 'pop {r4, r5, fp, pc}')],
        semantics=('startTouch:tapCount: = deltas then two-stage [cancelButton startTouch:...] / [takePhotoButton startTouch:...] acceptance; returns the OR.'),
        calls=[(10314456, 'bl loc.imp.objc_msgSend'), (10314572, 'bl loc.imp.objc_msgSend')],
        branches=[(10314392, 'bne', 10314480), (10314508, 'bne', 10314596)],
    ),
    dict(
        name='cam_move',
        method='CameraUI -[moveTouch:]',
        types='v16@0:4{CGPoint=ff}8',
        start=10314648,
        end=10314912,
        disasm='disasm_cameraui_movetouch.txt',
        base_add=10314692,
        base_literal=10314896,
        boundary='body trimmed to next IMP [endTouch:] 0x009d64a0 (exidx over-covered 0x009d65a8)',
        selectors={10314904: (15221904, 'moveTouch:')},
        imports={},
        ivars={10314892: (17163864, 'OBJC_IVAR_$_CameraUI.windowInfo', 96), 10314900: (17163884, 'OBJC_IVAR_$_CameraUI.cancelButton', 104), 10314908: (17163888, 'OBJC_IVAR_$_CameraUI.takePhotoButton', 108)},
        classes={},
        instructions=[(10314648, 'push {fp, lr}'), (10314820, 'bl loc.imp.objc_msgSend'), (10314888, 'pop {fp, pc}')],
        semantics=('moveTouch: = forwards the delta pair via the moveTouch: selector to both button objects (2x objc_msgSend).'),
        calls=[(10314820, 'bl loc.imp.objc_msgSend'), (10314880, 'bl loc.imp.objc_msgSend')],
        branches=[],
    ),
    dict(
        name='cam_end',
        method='CameraUI -[endTouch:]',
        types='v16@0:4{CGPoint=ff}8',
        start=10314912,
        end=10315176,
        disasm='disasm_cameraui_endtouch.txt',
        base_add=10314956,
        base_literal=10315160,
        boundary='consecutive IMPs: [cancelButton:] follows at 0x009d65a8',
        selectors={10315168: (15221908, 'endTouch:')},
        imports={},
        ivars={10315156: (17163864, 'OBJC_IVAR_$_CameraUI.windowInfo', 96), 10315164: (17163884, 'OBJC_IVAR_$_CameraUI.cancelButton', 104), 10315172: (17163888, 'OBJC_IVAR_$_CameraUI.takePhotoButton', 108)},
        classes={},
        instructions=[(10314912, 'push {fp, lr}'), (10315084, 'bl loc.imp.objc_msgSend'), (10315152, 'pop {fp, pc}')],
        semantics=('endTouch: = the same forward pattern via the endTouch: selector (2x objc_msgSend).'),
        calls=[(10315084, 'bl loc.imp.objc_msgSend'), (10315144, 'bl loc.imp.objc_msgSend')],
        branches=[],
    ),
    dict(
        name='cam_cancel',
        method='CameraUI -[cancelButton:]',
        types='v12@0:4@8',
        start=10315176,
        end=10315280,
        disasm='disasm_cameraui_cancelbutton.txt',
        base_add=10315192,
        base_literal=10315276,
        boundary='consecutive IMPs: [takePhotoButton:] follows at 0x009d6610',
        selectors={10315268: (15221912, 'cancelTakePhotoButtonTapped')},
        imports={10315264: (17151904, 'objc_msgSend')},
        ivars={10315272: (17163880, 'OBJC_IVAR_$_CameraUI.world', 20)},
        classes={},
        instructions=[(10315176, 'push {r4, sl, fp, lr}'), (10315252, 'blx ip'), (10315260, 'pop {r4, sl, fp, pc}')],
        semantics=('cancelButton: = single forward: [[World] cancelTakePhotoButtonTapped] (World cancel flow).'),
        calls=[(10315252, 'blx ip')],
        branches=[],
    ),
    dict(
        name='cam_takebtn',
        method='CameraUI -[takePhotoButton:]',
        types='v12@0:4@8',
        start=10315280,
        end=10315384,
        disasm='disasm_cameraui_takephotobutton.txt',
        base_add=10315296,
        base_literal=10315380,
        boundary='consecutive IMPs: [.cxx_construct] follows at 0x009d6678 (out of batch)',
        selectors={10315372: (15221916, 'takePhotoButtonTapped')},
        imports={10315368: (17151904, 'objc_msgSend')},
        ivars={10315376: (17163880, 'OBJC_IVAR_$_CameraUI.world', 20)},
        classes={},
        instructions=[(10315280, 'push {r4, sl, fp, lr}'), (10315356, 'blx ip'), (10315364, 'pop {r4, sl, fp, pc}')],
        semantics=('takePhotoButton: = single forward: [[World] takePhotoButtonTapped].'),
        calls=[(10315356, 'blx ip')],
        branches=[],
    ),
    dict(
        name='ui_show',
        method='UIManager -[showCameraUI]',
        types='v8@0:4',
        start=11389308,
        end=11389420,
        disasm='disasm_uimanager_showcameraui.txt',
        base_add=11389316,
        base_literal=11389416,
        boundary='consecutive IMPs: next method follows at 0x00adc9ec',
        selectors={},
        imports={},
        ivars={11389408: (17165216, 'OBJC_IVAR_$_UIManager.cameraUI', 100), 11389412: (17165252, 'OBJC_IVAR_$_UIManager.showCameraUITapped', 151)},
        classes={},
        instructions=[(11389308, 'sub sp, sp, 0xc'), (11389396, 'strb r0, [r1]'), (11389404, 'bx lr')],
        semantics=('showCameraUI: when the camera-UI field (global ivar chain) == 0 -> set the active flag byte (second global chain) = 1.'),
        calls=[],
        branches=[(11389364, 'bne', 11389400)],
    ),
    dict(
        name='ui_dismiss',
        method='UIManager -[dismissCameraUI]',
        types='c8@0:4',
        start=11396080,
        end=11396140,
        disasm='disasm_uimanager_dismisscameraui.txt',
        base_add=11396088,
        base_literal=11396136,
        boundary='consecutive IMPs: [setDismissCameraUI:] follows at 0x00ade42c',
        selectors={},
        imports={},
        ivars={11396132: (17165248, 'OBJC_IVAR_$_UIManager.dismissCameraUI', 147)},
        classes={},
        instructions=[(11396080, 'sub sp, sp, 8'), (11396120, 'ldrsb r0, [r0]'), (11396128, 'bx lr')],
        semantics=('dismissCameraUI = byte getter (ldrsb) over the dismiss-flag global ivar chain.'),
        calls=[],
        branches=[],
    ),
    dict(
        name='ui_setdismiss',
        method='UIManager -[setDismissCameraUI:]',
        types='v12@0:4c8',
        start=11396140,
        end=11396208,
        disasm='disasm_uimanager_setdismisscameraui.txt',
        base_add=11396168,
        base_literal=11396204,
        boundary='body trimmed to next IMP 0x00ade470 (accessor family follows; exidx over-covered 0x00ade608)',
        selectors={},
        imports={},
        ivars={11396200: (17165248, 'OBJC_IVAR_$_UIManager.dismissCameraUI', 147)},
        classes={},
        instructions=[(11396140, 'sub sp, sp, 0xc'), (11396180, 'dmb ish'), (11396184, 'strb r2, [r0, r1]'), (11396196, 'bx lr')],
        semantics=('setDismissCameraUI: stores the byte through the dismiss-flag ivar chain with dmb ish barriers before and after (flagged atomic write).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='w_screenshot',
        method='World -[doCameraScreenshot]',
        types='v8@0:4',
        start=6042232,
        end=6043648,
        disasm='disasm_world_docamerascreenshot.txt',
        base_add=6042248,
        base_literal=6043644,
        boundary='body 0x005c3278..0x005c3800; IMP gap 0x005c3800..0x005c3d24 excluded',
        selectors={6043544: (15197848, 'isPermissionGranted:'), 6043556: (15197852, 'requestPermission:withRationaleMessage:'), 6043560: (15197860, 'rotate:'), 6043564: (15197200, 'imageWithCGImage:'), 6043580: (15935836, '\x04'), 6043584: (15197856, 'render:'), 6043600: (15197868, 'presentSavedToCameraRollAlert'), 6043604: (15197864, 'sharePhotoFinished'), 6043608: (15197872, 'presentShareUIForImage:'), 6043612: (15197876, 'displayCameraFlash'), 6043616: (15196764, 'worldUI'), 6043624: (15195664, 'play'), 6043632: (15195660, 'multiSoundNamed:'), 6043636: (15195544, 'instance')},
        imports={6043540: (17151904, 'objc_msgSend')},
        ivars={6043572: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068), 6043588: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152), 6043620: (17155956, 'OBJC_IVAR_$_World.uiManager', 240)},
        classes={6043548: (15245520, 'OBJC_CLASS_$_NoodlePermissionGranter'), 6043568: (15245476, 'OBJC_CLASS_$_UIImage'), 6043640: (15245280, 'OBJC_CLASS_$_MJSoundManager')},
        instructions=[(6042232, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6042676, 'bl sym.imp.__wrap_glReadPixels'), (6042896, 'bl sym.imp.CGImageCreate'), (6043080, 'bl sym.UIImageWriteToSavedPhotosAlbum'), (6043528, 'bl sym.imp.__wrap_free'), (6043536, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('doCameraScreenshot: permission gate = [NoodlePermissionGranter isPermissionGranted:...]; not granted -> [granter requestPermission:withRationaleMessage:...] and return. Granted path: photo-state = 2 + sub-flag = 1; w/h = floats x scale (vcvt.s32); __wrap_malloc(w*h*4); glReadPixels(0, 0, w, h, GL_RGBA 0x1908, GL_UNSIGNED_BYTE 0x1401, buf); [UIImage imageWithCGImage:] over CGImageCreate (8 bpc / 32 bpp / w*4 stride from CGDataProviderCreateWithData + CGColorSpaceCreateDeviceRGB), rotate: applied; flag == 0 -> UIImageWriteToSavedPhotosAlbum else the share path; state restore; CGColorSpaceRelease + CGDataProviderRelease + __wrap_free.'),
        calls=[(6042304, 'blx ip'), (6042392, 'blx lr'), (6042500, 'bl loc.imp.objc_msgSend'), (6042628, 'bl sym.imp.__wrap_malloc'), (6042676, 'bl sym.imp.__wrap_glReadPixels'), (6042712, 'bl loc.imp.objc_msgSend'), (6042740, 'bl sym.imp.CGDataProviderCreateWithData'), (6042776, 'bl sym.imp.CGColorSpaceCreateDeviceRGB'), (6042896, 'bl sym.imp.CGImageCreate'), (6042988, 'blx r3'), (6043024, 'blx r3'), (6043080, 'bl sym.UIImageWriteToSavedPhotosAlbum'), (6043148, 'blx ip'), (6043184, 'blx r3'), (6043260, 'blx r3'), (6043416, 'blx sl'), (6043436, 'blx r3'), (6043452, 'blx r2'), (6043488, 'blx r3'), (6043504, 'blx r2'), (6043512, 'bl sym.imp.CGColorSpaceRelease'), (6043520, 'bl sym.imp.CGDataProviderRelease'), (6043528, 'bl sym.imp.__wrap_free')],
        branches=[(6042316, 'bne', 6042400), (6042396, 'b', 6043532), (6043048, 'bne', 6043192), (6043188, 'b', 6043264)],
    ),
    dict(
        name='w_startcam',
        method='World -[startUsingCamera]',
        types='v8@0:4',
        start=6044964,
        end=6045200,
        disasm='disasm_world_startusingcamera.txt',
        base_add=6044980,
        base_literal=6045196,
        boundary='consecutive IMPs: [takePhotoButtonTapped] follows at 0x005c3e10',
        selectors={6045184: (15197556, 'pauseUpdates'), 6045188: (15197880, 'showCameraUI')},
        imports={6045180: (17151904, 'objc_msgSend')},
        ivars={6045172: (17156716, 'OBJC_IVAR_$_World.hasJustTakenPhoto', 3080), 6045176: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068), 6045192: (17155956, 'OBJC_IVAR_$_World.uiManager', 240)},
        classes={},
        instructions=[(6044964, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6045092, 'blx r5'), (6045160, 'strb ip, [r0]'), (6045168, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('startUsingCamera: [pauseUpdates] + [UIManager showCameraUI] + photo-state field = 1 + flag byte = 0 - enters photo mode.'),
        calls=[(6045092, 'blx r5'), (6045112, 'blx r2')],
        branches=[],
    ),
    dict(
        name='w_taketap',
        method='World -[takePhotoButtonTapped]',
        types='v8@0:4',
        start=6045200,
        end=6045372,
        disasm='disasm_world_takephotobuttontapped.txt',
        base_add=6045216,
        base_literal=6045368,
        boundary='consecutive IMPs: [cancelTakePhotoButtonTapped] follows at 0x005c3ebc',
        selectors={6045356: (15197604, 'reportAchievementWithIdentifier:'), 6045360: (15197884, 'doCameraScreenshot')},
        imports={6045352: (17151904, 'objc_msgSend')},
        ivars={6045364: (17156716, 'OBJC_IVAR_$_World.hasJustTakenPhoto', 3080)},
        classes={},
        instructions=[(6045200, 'push {r4, r5, r6, r7, fp, lr}'), (6045288, 'strb r6, [r0]'), (6045312, 'blx ip'), (6045344, 'pop {r4, r5, r6, r7, fp, pc}')],
        semantics=('takePhotoButtonTapped: [reportAchievementWithIdentifier:] + [self doCameraScreenshot] + request flag byte = 1.'),
        calls=[(6045312, 'blx ip'), (6045336, 'blx r3')],
        branches=[],
    ),
    dict(
        name='w_canceltap',
        method='World -[cancelTakePhotoButtonTapped]',
        types='v8@0:4',
        start=6045372,
        end=6045744,
        disasm='disasm_world_canceltakephotobuttontapped.txt',
        base_add=6045388,
        base_literal=6045740,
        boundary='consecutive IMPs: [takingPhoto] follows at 0x005c4030',
        selectors={6045712: (15195680, 'sendHeartbeatData'), 6045720: (15195676, 'setPaused:'), 6045728: (15935836, '\x04'), 6045732: (15197888, 'setDismissCameraUI:')},
        imports={6045708: (17151904, 'objc_msgSend')},
        ivars={6045716: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068), 6045724: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416), 6045736: (17155956, 'OBJC_IVAR_$_World.uiManager', 240)},
        classes={},
        instructions=[(6045372, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6045676, 'str r2, [r0]'), (6045608, 'blx ip'), (6045704, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('cancelTakePhotoButtonTapped: [sendHeartbeatData] + [setPaused:] + [UIManager setDismissCameraUI:] + clears the photo-state flag (structural twin of sharePhotoFinished).'),
        calls=[(6045564, 'blx r3'), (6045608, 'blx ip'), (6045652, 'blx ip'), (6045696, 'blx ip')],
        branches=[],
    ),
    dict(
        name='w_taking',
        method='World -[takingPhoto]',
        types='c8@0:4',
        start=6045744,
        end=6045876,
        disasm='disasm_world_takingphoto.txt',
        base_add=6045760,
        base_literal=6045872,
        boundary='consecutive IMPs: [sharePhotoFinished] follows at 0x005c40b4',
        selectors={6045864: (15197892, 'cameraUI')},
        imports={6045860: (17151904, 'objc_msgSend')},
        ivars={6045868: (17155956, 'OBJC_IVAR_$_World.uiManager', 240)},
        classes={},
        instructions=[(6045744, 'push {r4, sl, fp, lr}'), (6045840, 'movne r0, 1'), (6045856, 'pop {r4, sl, fp, pc}')],
        semantics=('takingPhoto = [self cameraUI] != 0 (sxtb-normalised).'),
        calls=[(6045824, 'blx ip')],
        branches=[],
    ),
    dict(
        name='w_sharefin',
        method='World -[sharePhotoFinished]',
        types='v8@0:4',
        start=6045876,
        end=6046248,
        disasm='disasm_world_sharephotofinished.txt',
        base_add=6045892,
        base_literal=6046244,
        boundary='consecutive IMPs: next method follows at 0x005c4228',
        selectors={6046216: (15195680, 'sendHeartbeatData'), 6046224: (15195676, 'setPaused:'), 6046232: (15935836, '\x04'), 6046236: (15197888, 'setDismissCameraUI:')},
        imports={6046212: (17151904, 'objc_msgSend')},
        ivars={6046220: (17155980, 'OBJC_IVAR_$_World.hideUIType', 3068), 6046228: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416), 6046240: (17155956, 'OBJC_IVAR_$_World.uiManager', 240)},
        classes={},
        instructions=[(6045876, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6046180, 'str r2, [r0]'), (6046112, 'blx ip'), (6046208, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('sharePhotoFinished: same shape as cancelTakePhotoButtonTapped: [sendHeartbeatData] + [setPaused:] + [UIManager setDismissCameraUI:] + flag clear.'),
        calls=[(6046068, 'blx r3'), (6046112, 'blx ip'), (6046156, 'blx ip'), (6046200, 'blx ip')],
        branches=[],
    ),
    dict(
        name='w_justtook',
        method='World -[hasJustTakenPhoto]',
        types='c8@0:4',
        start=6137344,
        end=6137404,
        disasm='disasm_world_hasjusttakenphoto.txt',
        base_add=6137352,
        base_literal=6137400,
        boundary='consecutive IMPs: next method follows at 0x005da63c',
        selectors={},
        imports={},
        ivars={6137396: (17156716, 'OBJC_IVAR_$_World.hasJustTakenPhoto', 3080)},
        classes={},
        instructions=[(6137344, 'sub sp, sp, 8'), (6137384, 'ldrsb r0, [r0]'), (6137392, 'bx lr')],
        semantics=('hasJustTakenPhoto = ldrsb of the photo-state byte (global ivar chain).'),
        calls=[],
        branches=[],
    ),]

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

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in ELFFile(io.BytesIO(data)).iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)

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

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

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

        listed_branches = {(a, m.group(1), int(m.group(2), 16))
                           for a, ins in inrange.items()
                           for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                           if m and m.group(1) not in ('bl', 'blx')}
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
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'CameraUI photo-mode domain: CameraUI (init/dealloc/windowInfoChanged/render/touch family/buttons, 11 bodies), UIManager camera-UI trio, World photo chain (doCameraScreenshot glReadPixels->CGImage->UIImage->SavePhotosAlbum, startUsingCamera, take/cancel tapped, takingPhoto, sharePhotoFinished, hasJustTakenPhoto)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'camera_ui.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale camera_ui.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
