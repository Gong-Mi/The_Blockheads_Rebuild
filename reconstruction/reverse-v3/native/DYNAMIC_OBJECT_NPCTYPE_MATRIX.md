NPCType → DynamicObjectType shared mapping

Original ELF SHA-256:

`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Function:

```text
_Z27dynamicObjectTypeForNPCType7NPCType
IMP: 0x006495a0
jump table: 0x006495cc
```

Recovered switch:

```text
NPCType 0 -> DynamicObjectType 0
NPCType 1 -> 13 Dodo
NPCType 2 -> 25 DropBear
NPCType 3 -> 28 Donkey
NPCType 4 -> 35 ClownFish
NPCType 5 -> 36 Shark
NPCType 6 -> 39 CaveTroll
NPCType 7 -> 51 Scorpion
NPCType 8 -> 63 Yak
```

This closes the eight classes that have no direct class-level `objectType`
override in the ObjC method map. The shared NPC dispatch path supplies their
DynamicObjectType values.

This remains static native evidence; it does not prove NPC entity construction,
save decoding, runtime dispatch, APK integration, or device behavior.
