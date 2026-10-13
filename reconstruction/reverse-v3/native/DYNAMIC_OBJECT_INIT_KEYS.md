DynamicObject init saveDict key-to-field pairings

Original ELF SHA-256:

`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Method boundary:

```text
IMP:        0x00839f7c
code end:   0x0083a368
bounded end:0x0083a3c0
PIC base:   0x0105faf4
```

Four pairings are directly bounded from the ARM32 instruction stream:

```text
key       constant-string object  conversion path                 destination
uniqueID  0x00f920d8               unsignedLongValue               self + 40
pos_x     0x00f920e8               intValue                         self + 16
pos_y     0x00f920f8               intValue                         self + 20
floatPos  0x00f92108               objectAtIndex:0/1 -> floatValue self + 24
```

The constant string objects point to these ELF cstrings:

```text
0x00f50df3  uniqueID
0x00f571a3  pos_x
0x00f571a9  pos_y
0x00f571af  floatPos
```

The writes agree with the recovered ivar pool:

```text
pos       self + 16, 8-byte int pair
floatPos  self + 24, 8-byte Vector2
uniqueID  self + 40, uint64
```

This establishes four key/value/field pairings for the initializer only. It does not establish `ownerID`, the complete save schema, dynamic entity construction, APK integration, or runtime equivalence.
