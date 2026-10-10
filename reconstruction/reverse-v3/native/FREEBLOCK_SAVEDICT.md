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

## Key/value pairings (recovery: tools/recover_freeblock_save_keys.py)

The bounded forward register/stack trace promoted twelve keys, each re-checked
against instruction words, CFString payloads, and ivar symbols:

```text
key                        conversion          value source (ivar @ offset)
bounceTimer                numberWithFloat:    FreeBlock.bounceTimer @68
fallSpeed                  numberWithFloat:    FreeBlock.fallSpeed @72
floatPos[VX]               numberWithFloat:    DynamicObject.floatPos @24 (+0)
floatPos[VY]               numberWithFloat:    DynamicObject.floatPos @24 (+4)
itemType                   numberWithInt:      FreeBlock.itemType @56
dataA                      numberWithInt:      FreeBlock.dataA @60
dataB                      numberWithInt:      FreeBlock.dataB @62
creationTime               numberWithDouble:   FreeBlock.creationTime @80
hovers                     numberWithBool:     FreeBlock.hovers @64
subItems                   (array route)       FreeBlock.subItems @112
dynamicObjectSaveDict      (direct object)     FreeBlock.dynamicObjectSaveDict @140
priorityBlockheadUinqueID  numberWithInt:      FreeBlock.priorityBlockhead @136
```

`priorityBlockheadUinqueID` is serialized as an int: the FreeBlock ivar object
receives a `uniqueID` message at `0x0062a3ac` (selector cell `0x0062a4b4`,
direct `bl objc_msgSend`), and the returned identifier is boxed through
`numberWithInt:` at `0x0062a3e0`. The key name carries the original binary's
typo ("Uinque"); it is preserved verbatim as the plist key.

This is static native evidence only. It does not yet establish the subItems
element contract beyond itemType/saveData messages, complete cross-class
schema, replacement code, APK integration, or original-runtime equivalence.
