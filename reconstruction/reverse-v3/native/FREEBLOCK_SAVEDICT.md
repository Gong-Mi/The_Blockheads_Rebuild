# FreeBlock -[getSaveDict] bounded static inventory

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

Method boundary:

```text
IMP:         0x00629804
code end:    0x0062a410
literal end: 0x0062a4b8
next method: 0x0062a4bc
PIC base:    0x0105faf4
```

The method begins by dispatching the inherited save path:

```text
objc_msgSendSuper2(self, getSaveDict)
```

The bounded selector inventory proves these additional routes:

```text
setObject:forKey:
numberWithBool:
numberWithDouble:
numberWithInt:
numberWithFloat:
countByEnumeratingWithState:objects:count:
array
itemType
addObject:
saveData
uniqueID
```

The instruction stream contains 33 register-indirect `blx` sites and one direct
`objc_msgSend` call at `0x0062a3ac`. The indirect calls are not promoted to selector-level
claims merely from proximity; the report records the selector/import cells and
leaves object-key pairings unresolved until each data flow is bounded.

The recovered semantic inventory is:

```text
DynamicObject getSaveDict
  -> box FreeBlock scalar fields
  -> enumerate a contained array
  -> read itemType and saveData
  -> append serialized objects to an array
  -> write additional values into the inherited dictionary
```

This is static native evidence only. It does not yet establish the exact
FreeBlock save keys, every ivar offset, complete schema, replacement code,
APK integration, or original-runtime equivalence.
