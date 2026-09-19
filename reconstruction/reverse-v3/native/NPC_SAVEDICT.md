# NPC -[getSaveDict] key/value pairings

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

Method boundary:

```text
IMP:         0x00645aac
code end:    0x0064667c
literal end: 0x00646734
next method: 0x00646738 (NPC -[dealloc])
PIC base:    0x0105faf4
```

Like FreeBlock, the dictionary starts from the inherited save path:

```text
objc_msgSendSuper2(self, getSaveDict)   @ 0x00645b00
```

## Pairings (recovery: tools/recover_npc_save_keys.py)

Sixteen keys promoted from the bounded forward register/stack trace, each
re-checked against instruction words, CFString payloads, selector cells, and
OBJC_IVAR symbols:

```text
key                         conversion          value source (ivar @ offset)
damage                      numberWithInt:      NPC.damage @54
breed                       numberWithInt:      NPC.breed @96
fullness                    numberWithFloat:    NPC.fullness @68
layTimer                    numberWithFloat:    NPC.layTimer @80
mateBreed                   numberWithInt:      NPC.mateBreed @98
tameCooldownTimer           numberWithFloat:    NPC.tameCooldownTimer @72
layCooldownTimer            numberWithFloat:    NPC.layCooldownTimer @84
mateCooldownTimer           numberWithFloat:    NPC.mateCooldownTimer @76
age                         numberWithFloat:    NPC.age @88
hasBred                     numberWithBool:     NPC.hasBred @100
hasBeenFedByBlockheadOrChest numberWithBool:    NPC.hasBeenFedByBlockheadOrChest @101
name                        (direct object)     NPC.name @92
saveTime                    numberWithFloat:    world worldTime @via DynamicObject.world +4
tameCountsByClientID        (direct object)     NPC.tameCountsByClientID @104
tamedClientID               (direct object)     NPC.tamedClientID @108
currentBlockheadIndex       numberWithInt:      rider/dynamicWorld loop @+8
```

`saveTime` is a derived value: the ivar `DynamicObject.world` (self+4) receives
the `worldTime` message at `0x00646220` and the result is boxed at
`0x00646244`.

`currentBlockheadIndex` is computed, not stored: when `NPC.rider` (self+132)
is non-nil, the method enumerates `dynamicWorld.blockheads`, skips entries
responding `needsRemoved`, and serializes the matching index (boxed at
`0x00646644`).

All scalar pairings record their boxed-value spill store and reload sites
between the conversion call and its `setObject:forKey:` call, matching the
DynamicObject/FreeBlock contract format.

This is static native evidence only. It does not establish the rider-match
loop semantics beyond the instruction path, subclass (Dodo/Shark/...) routes,
the read-back side (`loadValuesFromSaveDict:` @ 0x00643b20), replacement code,
APK integration, or original-runtime equivalence.
