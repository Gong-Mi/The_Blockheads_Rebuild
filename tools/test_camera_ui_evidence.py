#!/usr/bin/env python3
"""Contract test for the CameraUI photo-mode domain batch.

Pins doc and JSON to each other and to the recovered semantics: the CameraUI
init/render/touch/button family (same-selector forwards), the UIManager
camera-flag trio, and the World photo chain (permission gate, glReadPixels ->
CGImage -> UIImage -> SavePhotosAlbum / share, pause/UI toggles).
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/CAMERA_UI.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/camera_ui.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cam_init', 'cam_dealloc', 'cam_wininfo', 'cam_render', 'cam_tiview',
         'cam_tiui', 'cam_start', 'cam_move', 'cam_end', 'cam_cancel',
         'cam_takebtn', 'ui_show', 'ui_dismiss', 'ui_setdismiss',
         'w_screenshot', 'w_startcam', 'w_taketap', 'w_canceltap', 'w_taking',
         'w_sharefin', 'w_justtook']

def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == [
        '0x009d414c', '0x009d53d0', '0x009d54d0', '0x009d5c24', '0x009d6054',
        '0x009d60d4', '0x009d620c', '0x009d6398', '0x009d64a0', '0x009d65a8',
        '0x009d6610', '0x00adc97c', '0x00ade3f0', '0x00ade42c',
        '0x005c3278', '0x005c3d24', '0x005c3e10', '0x005c3ebc', '0x005c4030',
        '0x005c40b4', '0x005da600']
    assert [BY[n]['boundary_end'] for n in NAMES] == [
        '0x009d522c', '0x009d54d0', '0x009d5c24', '0x009d6054', '0x009d60d4',
        '0x009d620c', '0x009d6398', '0x009d64a0', '0x009d65a8', '0x009d6610',
        '0x009d6678', '0x00adc9ec', '0x00ade42c', '0x00ade470',
        '0x005c3800', '0x005c3e10', '0x005c3ebc', '0x005c4030', '0x005c40b4',
        '0x005c4228', '0x005da63c']
    words = [BY[n]['verified_words'] for n in NAMES]
    assert words == [1080, 64, 469, 268, 32, 78, 99, 66, 66, 26, 26,
                     28, 15, 17, 354, 59, 43, 93, 33, 93, 15]
    assert sum(words) == 3024
    for needle in ('3024', '0x009d414c', '0x009d5c24', '0x005c3278',
                   'glReadPixels', 'CGImageCreate', 'UIImageWriteToSavedPhotosAlbum',
                   '0xbe2', 'dmb ish', 'texCoordsForItemType',
                   '0x009d522c', '0x009d5384', 'NoodlePermissionGranter',
                   'pauseUpdates', 'showCameraUI', 'sendHeartbeatData',
                   'reportAchievementWithIdentifier:', 'doCameraScreenshot',
                   'cameraUI', 'setDismissCameraUI:'):
        assert needle in DOC, needle

def test_anchor_counts():
    counts = {n: (len(BY[n]['selectors']), len(BY[n]['ivars']),
                  len(BY[n]['calls']), len(BY[n]['branches'])) for n in NAMES}
    assert counts == {
        'cam_init': (17, 7, 30, 13), 'cam_dealloc': (5, 2, 3, 0),
        'cam_wininfo': (2, 4, 11, 9), 'cam_render': (3, 3, 9, 0),
        'cam_tiview': (0, 1, 0, 0), 'cam_tiui': (1, 3, 2, 1),
        'cam_start': (1, 3, 2, 2), 'cam_move': (1, 3, 2, 0),
        'cam_end': (1, 3, 2, 0), 'cam_cancel': (2, 1, 1, 0),
        'cam_takebtn': (2, 1, 1, 0), 'ui_show': (0, 2, 0, 1),
        'ui_dismiss': (0, 1, 0, 0), 'ui_setdismiss': (0, 1, 0, 0),
        'w_screenshot': (18, 3, 23, 4), 'w_startcam': (3, 3, 2, 0),
        'w_taketap': (3, 1, 2, 0), 'w_canceltap': (5, 3, 4, 0),
        'w_taking': (2, 1, 1, 0), 'w_sharefin': (5, 3, 4, 0),
        'w_justtook': (0, 1, 0, 0),
    }

def test_touch_forwards():
    assert BY['cam_tiui']['selectors']['0x009d6200'] == {'slot': '0x00e84488', 'selector': 'touchIsInUI:'}
    assert BY['cam_start']['selectors']['0x009d6388'] == {'slot': '0x00e8448c', 'selector': 'startTouch:'}
    assert BY['cam_move']['selectors']['0x009d6498'] == {'slot': '0x00e84490', 'selector': 'moveTouch:'}
    assert BY['cam_end']['selectors']['0x009d65a0'] == {'slot': '0x00e84494', 'selector': 'endTouch:'}
    assert BY['cam_cancel']['selectors']['0x009d6604'] == {'slot': '0x00e84498', 'selector': 'cancelTakePhotoButtonTapped'}
    assert BY['cam_takebtn']['selectors']['0x009d666c'] == {'slot': '0x00e8449c', 'selector': 'takePhotoButtonTapped'}

def test_cameraui_ivars_and_init():
    ci = BY['cam_init']
    assert ci['ivars']['0x009d5190'] == {'slot': '0x0105e658', 'symbol': 'OBJC_IVAR_$_CameraUI.windowInfo', 'offset': 96}
    assert ci['ivars']['0x009d51a4']['offset'] == 24     # borderLineShader
    assert ci['ivars']['0x009d51c4']['offset'] == 100    # cache
    assert ci['ivars']['0x009d51c8']['offset'] == 20     # world
    assert ci['ivars']['0x009d51d8']['offset'] == 104    # cancelButton
    assert ci['ivars']['0x009d5200']['offset'] == 108    # takePhotoButton
    assert ci['selectors']['0x009d51ac'] == {'slot': '0x00e84448', 'selector': 'shaderNamed:attributes:uniforms:'}
    assert ci['selectors']['0x009d51fc'] == {'slot': '0x00e84450', 'selector': 'initWithFrame:cache:windowInfo:title:'}
    assert ci['selectors']['0x009d51e4'] == {'slot': '0x00e84454', 'selector': 'textureNamed:'}
    callees = {c['route']: c['callee'] for c in ci['calls'] if c['callee']}
    assert callees['bl 0x9d522c'] == '0x009d522c'
    assert callees['bl 0x9d5384'] == '0x009d5384'
    assert callees['bl sym.texCoordsForItemType_ItemType_'] == '0x004d6040'
    wn = BY['cam_wininfo']
    assert wn['ivars']['0x009d5c00']['offset'] == 32     # orthoMatrix
    assert wn['ivars']['0x009d5c08']['offset'] == 108    # takePhotoButton

def test_ui_flags_and_taking():
    assert BY['ui_show']['ivars']['0x00adc9e0'] == {'slot': '0x0105eba0', 'symbol': 'OBJC_IVAR_$_UIManager.cameraUI', 'offset': 100}
    assert BY['ui_show']['ivars']['0x00adc9e4']['offset'] == 151    # showCameraUITapped
    assert BY['ui_dismiss']['ivars']['0x00ade424'] == {'slot': '0x0105ebc0', 'symbol': 'OBJC_IVAR_$_UIManager.dismissCameraUI', 'offset': 147}
    assert BY['ui_setdismiss']['ivars']['0x00ade468']['offset'] == 147
    assert 'dmb ish' in BY['ui_setdismiss']['semantics']
    assert BY['w_taking']['selectors']['0x005c40a8'] == {'slot': '0x00e7e6c4', 'selector': 'cameraUI'}
    assert BY['w_justtook']['ivars']['0x005da634'] == {'slot': '0x0105ca6c', 'symbol': 'OBJC_IVAR_$_World.hasJustTakenPhoto', 'offset': 3080}

def test_screenshot_and_photo_chain():
    ws = BY['w_screenshot']
    assert ws['selectors']['0x005c3798'] == {'slot': '0x00e7e698', 'selector': 'isPermissionGranted:'}
    assert ws['selectors']['0x005c379c'] == {'slot': '0x00e8a0d0', 'class': 'OBJC_CLASS_$_NoodlePermissionGranter'}
    assert ws['selectors']['0x005c37a4'] == {'slot': '0x00e7e69c', 'selector': 'requestPermission:withRationaleMessage:'}
    assert ws['selectors']['0x005c37ac'] == {'slot': '0x00e7e410', 'selector': 'imageWithCGImage:'}
    callees = {c['route']: c['callee'] for c in ws['calls'] if c['callee']}
    assert callees['bl sym.imp.__wrap_glReadPixels'] == '0x001c3fe0'
    assert callees['bl sym.imp.CGImageCreate'] == '0x001c3434'
    assert callees['bl sym.UIImageWriteToSavedPhotosAlbum'] == '0x00256560'
    sem = ws['semantics']
    for needle in ('isPermissionGranted:', 'requestPermission:withRationaleMessage:',
                   'GL_RGBA 0x1908', 'GL_UNSIGNED_BYTE 0x1401', 'imageWithCGImage:',
                   'UIImageWriteToSavedPhotosAlbum', 'w*h*4'):
        assert needle in sem, needle
    sc = BY['w_startcam']
    assert sc['selectors']['0x005c3e00'] == {'slot': '0x00e7e574', 'selector': 'pauseUpdates'}
    assert sc['selectors']['0x005c3e04'] == {'slot': '0x00e7e6b8', 'selector': 'showCameraUI'}
    tt = BY['w_taketap']
    assert tt['selectors']['0x005c3eac'] == {'slot': '0x00e7e5a4', 'selector': 'reportAchievementWithIdentifier:'}
    assert tt['selectors']['0x005c3eb0'] == {'slot': '0x00e7e6bc', 'selector': 'doCameraScreenshot'}
    ct = BY['w_canceltap']
    assert ct['selectors']['0x005c4010'] == {'slot': '0x00e7de20', 'selector': 'sendHeartbeatData'}
    assert ct['selectors']['0x005c4018'] == {'slot': '0x00e7de1c', 'selector': 'setPaused:'}
    assert ct['selectors']['0x005c4024'] == {'slot': '0x00e7e6c0', 'selector': 'setDismissCameraUI:'}
    sf = BY['w_sharefin']
    assert sf['selectors']['0x005c4208']['selector'] == 'sendHeartbeatData'
    assert sf['selectors']['0x005c4210']['selector'] == 'setPaused:'
    assert sf['selectors']['0x005c421c']['selector'] == 'setDismissCameraUI:'

def test_hashes_and_claim():
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_touch_forwards()
    test_cameraui_ivars_and_init()
    test_ui_flags_and_taking()
    test_screenshot_and_photo_chain()
    test_hashes_and_claim()
    print('camera ui contract: OK')
