# Tree ctor family — E86 (plants line)

The ten fruit trees' placed constructors plus the pine's save-dict ctor: the
10-arg super2 frame, the growth-vigor call and its standalone-path
exceptions, the shared soil set, the modsi3 clamp and the 99999 max-age
sentinel.
**11 bodies, 6331 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_treectors.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/tree_ctors.json`.

## Load-bearing findings

- **The ctor contract** (all ten): super2 with the wide 10-arg frame
  (maxHeight/growthRate sxth-normalized + the two noise-function blocks +
  adultTree byte + adultMaxAge halfword), the nil gate, the position growth
  math (`vcvt.f32.u32` / `vdiv.f32` + `vmul/vadd/vcvt.s32`), the **shared soil set {0x30/31/32}**
  (tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}), the **adultTree gate** + **`__modsi3` random clamp (>=1)**, and
  the **0x1869f (99999) max-age sentinel** (the pool word; non-adult trees
  grow to 99999).
- **The vigor family**: Apple/Coffee/Lime/Orange/Cherry/Mango/Maple call
  **`growthVigorForTreeTypeAtPos(TreeType, intpair, World*)`**; three trees
  take standalone paths: **CoconutTree** (helper 0xa99938), **CactusTree**
  (helper 0xb533ac + the **0x3fffffff half-max pool word**), **PineTree**
  (helper 0xb64f38 + makeIntpair) - the vigor is per-tree specializable.
- **Per-class constants**: lime/orange/mango 0x3f00 + 0x7f; cactus
  0xff/0x63/0x20/**0x384 (900)**; pine 0xff/0x7f; cherry/maple 0x7f; etc.
- **The pine save ctor**: super2 + the decode chain binding the pine save
  keys **fff3e324/e314** + fffff454 + ffe271b0/b4/b8/bc.

## Boundaries (honest)

- uncl 30/41: the eleven 0x1869f/0x3fffffff pool words (the sentinels) are
  data, not code - recorded rather than resolved; the per-ctor helper bodies
  (0x9bd3a0 etc.) stay opaque.
- The frame arg roles read from the stores; the noise-function block
  identities stay caller-side.
