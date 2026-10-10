# Workbench true closure — E84

The Workbench's final 11 bodies: the two geometry emitters, the full placed
ctor, the derived-state key family, the light-glow removal and the last
tables. With this batch the **Workbench class completes: 96/96 static ledger rows** (the ledger's 97th
entry is the recovered-method-module differential record for the same
saveDict ctor - `workbench_init_with_world` under Unicorn, O0/O2 bit-exact).
**11 bodies, 10326 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wbfinal.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_final.json`.

| body | imp | words | content |
|---|---|---:|---|
| wz_adddrawcube | 0x00b05f90 | 4847 | cube emitter (texCoords x9) |
| wz_adddrawquad | 0x00b02608 | 3631 | quad emitter (fillQuadBuffer x15) |
| wz_ctor_placed | 0x00ae42c0 | 774 | the full placed ctor |
| wz_initsubderived | 0x00ae3634 | 394 | derived state (key family) |
| wz_staticquadcount | 0x00b0222c | 247 | quad count (level+1) |
| wz_rmmacro | 0x00b0aec0 | 231 | removal + light-glow reload |
| wz_lightpos | 0x00b0b51c | 75 | light position |
| wz_staticcubecount | 0x00b05ec4 | 51 | cube counts 4/9/9 |
| wz_hurrycost | 0x00b0bc24 | 32 | ceil(remaining/10) |
| wz_addartistlight | 0x00b0b664 | 29 | light contribution |
| wz_craftableitems | 0x00afb128 | 15 | the owned array |

## Load-bearing findings

- **The geometry emitters**: `addDrawQuadData:` runs **15x
  `fillQuadBuffer(...)`** + the helper 0xaf9850 x10 (the E80 draw giant's
  helper!) with the -0.99/-0.98 pool; `addDrawCubeData:` runs 22x objc +
  **9x `texCoordsForImageIndex(int)`** (the SteamTrain's E69 symbol!) with
  the cube-corner pool (+/-0.2/0.05/0.1/-1.2/0.6/0.3/-0.7/0.35/-0.35/0.8).
- **The light-glow reload triple**: `removeFromMacroBlock` calls
  **`reloadDrawBlockLightGlowQuadsForTile`** (@0xb0afb8) - with the E77
  ctor and setNeedsRemoved hits, the glow symbol is pinned at three
  workbench sites (the class is thoroughly a light contributor).
- **The cube counts**: `staticGeometryDrawCubeCount` = **4 for type 0x18,
  9 for 0x1a/0x1d** (matching rendersDynamicObjectCubes' set); the quad
  count = **level + 1** for type 3 when level > 0.
- **The hurry cost**: **`ceil(remaining / 10)`** (`sub 1` / `__aeabi_idiv`
  by 0xa / `add 1`).
- **The owned array**: `craftableItems` reads the **fffff11c** pointer -
  the same one initLevelStuff mallocs (E79) and dealloc frees (E77).
- **The third key family**: `initSubDerivedItems` binds
  **fff3bea4/be74/be84/beb4/be54/be64/be94/be44** (sibling of E77's bf5x/7x
  and E78's c074).
- **The placed ctor**: the 8-arg super2 frame; the type rides fffff120 and
  **fffff140** receives the flipped byte.

## Boundaries (honest)

- uncl 42/44: two cells share 0xffdb8c2c (below the window, shared code).
- The emitter arms are characterized by census (fillQuadBuffer/texCoords
  counts + float pools); the helper bodies 0xaf9850/0xaf98c4/0xaf9c5c/
  0xafa040 stay opaque; the derived-state consequences read from the call
  chain.
