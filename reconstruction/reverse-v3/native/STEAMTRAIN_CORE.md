# SteamTrain core cluster — E69 (electricity line)

The electricity line continues with the SteamTrain class core: the derived
geometry build, the placed/net constructors, the creation record pack, the
dealloc ivar wall, the remote update and the station search.
**7 bodies, 4243 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_steamtrain.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/steamtrain_core.json`.

| body | imp | words | content |
|---|---|---:|---|
| st_searchstations | 0x00d1a510 | 1371 | station search |
| st_loadderived | 0x00d170b0 | 883 | derived geometry |
| st_ctor_pos | 0x00d17e98 | 615 | placed ctor |
| st_remoteupdate | 0x00d19b84 | 611 | remote update |
| st_creationnetdata | 0x00d19188 | 361 | creation record |
| st_ctor_net | 0x00d18b04 | 215 | netData ctor |
| st_dealloc | 0x00d19898 | 187 | dealloc |

## Load-bearing findings

- **Geometry**: `texCoordsForImageIndex(int)` with image index **0x243 (579)**
  + the corner pair-folds (origin + size) + the packed ~13-float append frame;
  the float pool 0xd174e0.. carries the train's geometry constants
  (1.2f/0.8f/1.0f/1.5f/1.3f...).
- **Placement ctor**: super2 + the **fffffcbc/fcc0/fcc4/fcc8 ivar-cell byte
  writes** + the saveDict decode chain + the `for i in 0..2` consist loop
  (the train's cars).
- **Net ctors/record**: the net ctor dequantizes the position
  (`vcvt.f32.s32; vdiv.f32`) and writes the decoded bytes; the creation
  record is a **0x68 (104)-byte stret** (memset + `__aeabi_memcpy` + the
  `vmul/vcvt.s32` quantized position + booleanized flag bytes via
  `ldrsb; cmp; movne 1; moveq 0`).
- **Dealloc ivar oracle**: the **fffffc8c..fca8** cell wall (twelve+ ivars)
  + the ffe28abc/ffe28ac0 cache-removal chain - a cross-check oracle for the
  class layout.
- **Remote update**: position dequantization + the float range checks
  (`vcmpe; bgt/bmi/bpl` movement bounds) + the ffffcacc world gate + the
  ffffe110/ffe28ac8 per-blockhead notify.
- **Station search**: gated by the fffffcb8 flag; **8 probe steps** with
  `makeIntpair` + `tileAtWorldPositionLoaded` probes; the tile byte **+0xb ==
  0x62 ('b') = the station/rail marker** with the ±1 neighbour probes (y−1 /
  x+1 / x−1) and the tile+3 == 0x30 ('0') station-side arm.

## Boundaries (honest)

- uncl 32/32 resolve as PIC base anchors (clean).
- The sprite index, the loop bounds (8 steps, 2 cars), the record size 0x68
  and the marker bytes are pinned immediates; the geometry-append callees and
  the save-decode key identities stay opaque; the station-arm consequence
  tails continue in the listing.
