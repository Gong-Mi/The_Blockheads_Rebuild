# DynamicObject -[uniqueID] bounded recovery

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

- IMP: `0x0083d08c`
- code end: `0x0083d0e8`
- ARM.exidx boundary: `0x0083d0f0`
- code: 23 ARM words
- PIC base: `0x0105faf4`
- ivar cell: `0x0083d0e8`
- resolved ivar: `OBJC_IVAR_$_DynamicObject.uniqueID`
- ivar storage: `0x00f33e38`
- ivar offset: 40 bytes
- body SHA-256: `831fceffcdffd9958d6ecb165b42060c017574d01ac6315eb533442c2e92360d`

The getter copies an 8-byte value from `self + 40` and returns it as the
`uint64` result. The two words at `0x0083d0e8..0x0083d0f0` are the literal
pool used by the code and are not counted as executable instructions.

This is static bounded evidence for the identity field only. It does not prove
which plist key creates the object, dynamic object type-specific fields,
entity construction, or original-app/runtime equivalence.

The neighboring `DynamicObject -[objectType]` getter is tracked separately. Its
7-word body returns the constant `0x41`; it does not read an object field. This
base-class constant must not be substituted for the concrete type stored in a
serialized dynamic-object record.
