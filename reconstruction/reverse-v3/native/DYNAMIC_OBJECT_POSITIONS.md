# DynamicObject position getter bounded recovery

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

The two getters use the same `objc_copyStruct` pattern but different proven
ivars:

| method | IMP | boundary | ivar | offset | returned bytes |
|---|---:|---:|---|---:|---:|
| `pos` | `0x0083cfcc` | `0x0083d02c` | `DynamicObject.pos` | 16 | 8-byte `{int,int}` |
| `floatPos` | `0x0083d02c` | `0x0083d08c` | `DynamicObject.floatPos` | 24 | 8-byte `Vector2` |

Each body has 22 executable words followed by a two-word literal pool. The
extractor verifies the ARM bytes, PIC base `0x0105faf4`, ivar storage symbols,
ivar offsets, and the `objc_copyStruct` target at `0x001c2888`.

This proves the field layout and getter copy contract only. It does not prove
which dynamic-object save-dict keys populate these fields, object-type-specific
fields, entity construction, or runtime/renderer equivalence.
