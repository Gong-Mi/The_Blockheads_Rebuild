# Torch class — E72 (electricity line)

The Torch: the world's **primitive artificial light**. The full 34-body class —
the block-type sub-state derivation, the light-color table, the save/net
lifecycle, the dynamic-object quad reload, the water reaction, the
light-placement solver, the quad emitter and the light position selector.
**34 bodies, 10130 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_torch.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/torch.json`.

| body | imp | words | content |
|---|---|---:|---|
| t_adddrawquad | 0x004b8fd0 | 4762 | quad emitter (23 arms) |
| t_worldcontents | 0x004b7bd4 | 991 | light-placement solver |
| t_lightpos | 0x004be0d4 | 803 | light position selector |
| t_ctor_placed | 0x004b5300 | 578 | placed ctor |
| t_draw | 0x004b71d8 | 382 | draw gates |
| t_ctor_save | 0x004b5d38 | 318 | saveDict ctor |
| t_initsubderived | 0x004b4a20 | 286 | block-type sub-state |
| t_getsavedict | 0x004b65b8 | 266 | getSaveDict |
| t_getlightrgb | 0x004b4e98 | 261 | light color table |
| t_ctor_net | 0x004b6230 | 217 | netData ctor |
| t_creationdata | 0x004b6a34 | 204 | creation record |
| t_waterchanged | 0x004b78bc | 198 | water reaction |
| t_renderimageidx | 0x004b8cd0 | 182 | sprite map (12-arm table) |
| t_rmmacro | 0x004b6ff4 | 121 | removal + quad reload |
| t_dealloc | 0x004b6ed0 | 73 | dealloc |
| t_remoteupdate | 0x004b77d0 | 59 | remote update |
| t_setneedsremoved | 0x004b8be8 | 58 | removed flag |
| t_isdownlight | 0x004bedec | 48 | downlight test |
| t_worldchanged | 0x004b8b50 | 38 | worldChanged forwarder |
| t_fbdataa | 0x004b5cc0 | 30 | dataA accessor |
| t_addartistlightcont | 0x004beeac | 29 | light contribution |
| t_isuplight | 0x004bee3c | 28 | uplight test |
| t_glowquadcount | 0x004bed90 | 23 | glow quad count |
| t_objecttype | 0x004b5c1c | 22 | type = 17 |
| t_updatenet | 0x004b69e0 | 21 | net update forwarder |
| t_fbsavedict | 0x004b5c74 | 19 | saveDict accessor |
| t_setdataa | 0x004bef5c | 18 | dmb-fenced store |
| t_setdatab | 0x004befe0 | 18 | dmb-fenced store |
| t_fbitemtype | 0x004b5c38 | 15 | item type |
| t_dataa | 0x004bef20 | 15 | dataA read |
| t_datab | 0x004befa4 | 15 | dataB read |
| t_fbdatab | 0x004b5cfc | 15 | dataB accessor |
| t_staticquadcount | 0x004b8fa8 | 10 | 1 quad |
| t_occupiesfg | 0x004bee90 | 7 | = 1 |

## Load-bearing findings

- **The block-type universe**: the torch family is the world-format codes
  **0x91..0x9d (145..157)** (the `initSubDerivedItems` chain 0x94/0x93/0x92/0x91
  + the 12-arm sprite table at 0x4b8e04 = `sub r1, r0, 0x91; cmp r1, 0xc;
  bhi`), plus **0x2f ('/')**, **0x4b/0x4c ('K'/'L')**, **0x56-0x58
  ('V'/'W'/'X')**, **0xb6/0xb7 (182/183)**, **0xfe (254)**, **0x102 (258)**.
- **Light colors** (`getLightRGB`): 0x2f → (0x7f, 0xff, 0x37-family); **0xb7
  → (0xdc, 0x64, 0xc) = (220, 100, 12) the orange flame**; 0x96/0xfe/0x102 →
  (0xaa, 0x12c, ...).
- **Light classes**: `isDownlight` = **block 0xfe**; `isUplight` = **block
  0x102**; `lightGlowQuadCount` = **0 for 0x9d** (157) else 1 - the glow
  exception type.
- **The placement solver** (`worldContentsChanged:`): the ±2 neighbourhood
  scan + `tileAtWorldPositionLoaded`/`tileIsSolid`/`tileContainsDoor`/
  `tileIsHalfDepth` classify the neighbours into the light-placement codes
  stored via ffffc8bc: **-2** none / **2** half-depth / **0** solid-at-y−1 /
  **3** tile byte +0xb == 0x64 ('d') / **1** solid+door / **-1** x−1
  solid+door; if no arm fits, the tail creates a new torch (the spreading
  call with the uxth'd dataA/dataB frame).
- **The quad emitter** (`addDrawQuadData:`): a 0x1800-byte aligned frame;
  **23× helper 0x4bdac0 + 23× memcpy(0x40)** = the per-code quad arms
  (double-buffered record swap), **12× helper 0x4bdca8**, and **2×
  `fillQuadBuffer(...)`** at the emit tail — the same quad-fill family as the
  E41/E44 draw passes; `clamp_float`/`__modsi3`/`__aeabi_idiv` + the flame
  constants **-1.4125f, ±0.48f, ±0.1f, ±0.3f, ±0.4f, -0.7f, -0.9f, -0.05f**.
- **Removal re-ties the render**: `removeFromMacroBlock` calls
  **`reloadDrawBlockDynamicObjectQuadsForTile`** — the dynamic-object quad
  reload (sibling of the GlowBlock's light-glow reload in E68).
- **Atomic halfword data**: `setDataA:`/`setDataB:` store under **`dmb ish`
  barriers**; dataA/dataB are u16 (ldrh accessors).
- **Water reaction**: `waterContentChanged:` gates on the ffffc898 submerged
  flag then exits for the fire-family types 0x96/0xfe/0x102 - the quenching
  contract.
- **Lifecycle**: the placed ctor stores type/dataA/dataB (strh) via the
  ffffc88c/a4/a8 cells; the save ctor binds the **save-key pool
  fff13984/f13994/f139a4/f139b4/f139c4**; net ctors use the **0x20-byte
  record**; `creationNetDataForClient:` packs the 0x20-byte record from a
  0x18-byte stret base.

## Boundaries (honest)

- uncl 49/49 resolve as PIC base anchors (clean).
- The helpers 0x4bdac0/0x4bdca8/0x4bda38 stay opaque (the quad-record
  builders); the t_adddrawquad per-arm detail continues in the listing
  (structural census given: 23+12 arms, 2 fillQuadBuffer calls); the
  ffe1d6xx/ffe2a3xx call-chain identities stay opaque; t_lightpos's per-code
  offsets read from the 64 Vector-op calls without listing every constant.
