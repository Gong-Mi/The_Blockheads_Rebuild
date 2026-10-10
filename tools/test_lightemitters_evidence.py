#!/usr/bin/env python3
"""Contract test for the light-emission parameter trio batch.

Pins doc and JSON to each other and to the recovered semantics: the ten
bodies, the colour tables (Torch item-type -> RGB, Fire constant, Glow
delegation), the position dispatch (chandelier / flatOnSideAndBottom /
connectionType chains) and the glow flags.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/LIGHT_EMITTERS.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/lightemitters.json').read_text())

def test_bodies():
    m = {c['name']: c for c in DATA['classes']}
    assert len(m) == 10
    assert sum(c['verified_words'] for c in DATA['classes']) == 1301
    assert m['torch_getlightrgb']['verified_words'] == 261
    assert m['torch_lightpos']['verified_words'] == 803
    assert m['torch_isdownlight']['verified_words'] == 20
    assert m['torch_isuplight']['verified_words'] == 21
    assert m['al_lightcolor']['imp'] == '0x00a93bbc'
    assert m['torch_lightpos']['imp'] == '0x004be0d4'
    for needle in ('1301', '0x00a93bbc', '0x004be0d4', '0x004bedec',
                   '0x004bee3c', '0x004bee90'):
        assert needle in DOC, needle

def test_anchor_counts():
    m = {c['name']: c for c in DATA['classes']}
    assert len(m['torch_getlightrgb']['branches']) == 39
    assert len(m['torch_lightpos']['calls']) == 64
    assert len(m['torch_lightpos']['branches']) == 84
    assert len(m['glow_getlightrgb']['calls']) == 2
    assert len(m['glow_lightpos']['calls']) == 3
    assert len(m['torch_lightpos']['ivars']) == 5

def test_semantics():
    s = {c['name']: c['semantics'] for c in DATA['classes']}
    for needle in ('Vector((float)maxRed', 'vcvt.f32.s32'):
        assert needle in s['al_lightcolor'], needle
    for needle in ('128.0f, 64.0f, 1.0f',):
        assert needle in s['fire_getlightrgb'], needle
    for needle in ('@selector(lightColor)', 'memset(out, 0, 0x10)',
                   'objc_msgSend_stret'):
        assert needle in s['glow_getlightrgb'], needle
    for needle in ('floatPos.y + 5.0f',):
        assert needle in s['glow_lightpos'], needle
    for needle in ('tileType@60', '!= 0x4d'):
        assert needle in s['glow_glowquadcount'], needle
    for needle in ('itemType@64', '!= 0x9d'):
        assert needle in s['torch_glowquadcount'], needle
    for needle in ('== 0xfe',):
        assert needle in s['torch_isdownlight'], needle
    for needle in ('== 0x102',):
        assert needle in s['torch_isuplight'], needle
    for needle in ('Default (no match) = (253, 150, 55)',
                   '0x4b -> (220,0,0)', '0x58 -> (200,255,255)',
                   '0x96 / 0xfe / 0x102 -> (300,300,170)'):
        assert needle in s['torch_getlightrgb'], needle
    for needle in ('chandelier@78', 'flatOnSideAndBottom@77',
                   'connectionType@60', 'x + 0.45', 'y = floatPos.y + 0.9',
                   'x += 2'):
        assert needle in s['torch_lightpos'], needle
    for needle in ('253, 150, 55', '200, 255, 255', '0.45', '0.9',
                   'chandelier', 'flatOnSideAndBottom', 'connectionType',
                   '5.0', '0x1c2918'):
        assert needle in DOC, needle

def test_anchor_samples():
    m = {c['name']: c for c in DATA['classes']}
    assert m['glow_getlightrgb']['selectors']['0x00ca83c8'] == {
        'slot': '0x00e87b14', 'selector': 'lightColor'}
    assert m['glow_getlightrgb']['ivars']['0x00ca83cc']['offset'] == 56
    assert m['glow_glowquadcount']['ivars']['0x00ca9554']['offset'] == 60
    assert m['torch_getlightrgb']['ivars']['0x004b52a4']['offset'] == 64
    tv = m['torch_lightpos']['ivars']
    assert tv['0x004bed38']['offset'] == 78   # chandelier
    assert tv['0x004bed40']['offset'] == 77   # flatOnSideAndBottom
    assert tv['0x004bed48']['offset'] == 60   # connectionType
    assert tv['0x004bed3c']['offset'] == 24   # floatPos
    callees = {c['route']: c['callee'] for c in m['glow_getlightrgb']['calls'] if c['callee']}
    assert callees['bl loc.imp.objc_msgSend_stret'] == '0x001c2918'
    assert callees['bl sym.imp.memset'] == '0x001c2924'
    for needle in ('0xe87b14', 'self.light@56', 'GlowBlock.tileType',
                   'Torch.itemType', 'Torch.connectionType', 'Torch.chandelier',
                   'DynamicObject.floatPos'):
        assert needle in DOC, needle

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_semantics()
    test_anchor_samples()
    print('light emitters contract: OK')
