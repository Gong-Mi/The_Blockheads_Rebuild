# DynamicWorld .cxx_construct member chain — E66

The compiler-generated member-constructor chain of DynamicWorld: **1 body,
866 words, fully read** (the earlier "~15,050-word boundary artifact"
classification came from a LISTING-TEXT word count — ~17 tokens per listing
line over 871 lines — not from the instruction count; the body is 866
instructions and has now been recovered in full). From the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_cxxconstruct.py` (hash-gated; `--check`
reproduces the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/cxx_construct.json`.

| body | imp | words | content |
|---|---|---:|---|
| .cxx_construct | 0x00907218 | 866 | member-constructor chain (full read) |

## Member-constructor inventory (anchored)

Every C++ container member receives its constructor in declaration order;
numeric/flag members receive the scalar defaults (1.0f via `vmov.f32 s0, 1`,
the `movw ..., 1` / `movw ..., 0` immediates):

1. the **three 65-segment map families**: the `std::__1::__tree` map
   constructors run in 0x30c (12-byte × 65) loops for the **ffffe54c**
   (@0x907280), **ffffe550** (@0x9072ec) and **ffffe554** (@0x907354)
   members — mirroring E29's destructor loops (0x30c/12 = 65);
2. the **ffffe588** `map<u64, set<DynamicObject*>>` tree ctor (@0x9073b0) —
   the free-block registry;
3. the ffffe584 region with the scalar defaults and the ffffe5cc ctor
   (@0x9073b8+);
4. the ffffe58c member's 0x30c loop (@0x907890+);
5. the **ffffe56c / ffffe57c / ffffe580 / ffffe574 / ffffe5b8** members
   (@0x907938-0x907ae8; each the 8-byte empty-head vector/tree ctor pattern);
6. the **ffffe578** member's 0x30c loop plus **ffffe5dc / ffffe5c4 /
   ffffe5c0** (@0x907bf0+; ffffe5c0 carries the +0x180 slice marker seen in
   E23/E42);
7. the ffffe5d0 member and the **ffffe570** member vector (@0x907e10+);
8. the final **`Vector::Vector()`** member (@0x907ea8);
9. the **ffffe5c8** member (the list family from E29's destructor)
   (@0x907eb8+).
Epilogue @0x907f44. No calls besides the STL constructors and
`Vector::Vector()`; no branches besides the segment loops.

## Note: filename collision handled

An earlier batch had a **WorldTileLoader .cxx_construct** listing
(0x00868fd8, a 7-word empty stub) under the colliding slug
`disasm_worldtileloader_cxx_construct.txt` (referenced by wtl_closure.json).
This batch's listing is stored as
**`disasm_dynamicworld_cxx_construct.txt`**; the WTL file was restored from
git untouched.

## Coverage

With this batch the DynamicWorld class reaches **210/210 rows touched** and
the world line reaches **262/262 rows touched** — with the `draw:` composite
(E44) as its structural pass and this body now fully read. The earlier
closure document (WORLD_LINE_CLOSURE.md) is superseded on its two
"remaining" entries: `compressBlocks` was landed in E65 (empty stub) and
`.cxx_construct` here (full read).

## Boundaries (honest)

- Generated code: no behavioural claims beyond the member-constructor
  semantics; member identities are the offsets pinned across E22-E44.
- The scalar-default constants are read from the immediates; which member
  each default belongs to is partially ambiguous inside the generated chain.
