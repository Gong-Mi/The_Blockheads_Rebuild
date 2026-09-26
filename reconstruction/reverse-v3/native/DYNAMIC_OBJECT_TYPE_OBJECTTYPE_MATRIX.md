DynamicObjectType matrix → objectType IMP reconciliation

Original ELF SHA-256:

`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

The native `classForDynamicObjectType(int)` jump table resolves all 64 IDs to class names. This batch cross-checks those names against the ObjC method map and verifies each direct class-level `objectType` implementation's ARM32 immediate return.

Results:

```text
64 native type IDs
56 classes with direct objectType override
  all 56 returned constants match the matrix type ID
8 classes without a direct override
```

The no-direct-override set is:

```text
13 Dodo
25 DropBear
28 Donkey
35 ClownFish
36 Shark
39 CaveTroll
51 Scorpion
63 Yak
```

These are NPC-family classes and are recorded as shared/inherited `objectType` paths pending, not as missing type IDs.

This is static class/IMP evidence. It does not prove entity construction, save decoding, runtime dispatch, APK integration, or device behavior.
