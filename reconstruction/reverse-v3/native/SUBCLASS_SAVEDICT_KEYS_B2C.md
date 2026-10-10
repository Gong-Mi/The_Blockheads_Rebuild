# getSaveDict shapes — batch 2c (SnowSurfaceBlock, Window, Yak)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2c.py` →
`subclass_savedict_keys_b2c.json`. Listings:
`disasm_snowsurfaceblock_getsavedict.txt` (15w),
`disasm_window_getsavedict.txt` (112w),
`disasm_yak_getsavedict.txt` (113w).

```text
SnowSurfaceBlock 0x00d8da7c  CACHED-DICT ACCESSOR, no message send at all:
    ldr r3,[0x00d8dab0] ; ivar-offset storage saveDictCached = 64
    ldr r2,[r3,pic]; ldr r1,[r2]; add r0,self,r1; ldr r0,[r0]; bx lr
    -> return self->saveDictCached (@64). The override never touches super.

Window 0x00c98e80  [super getSaveDict] +
    numberWithInt: itemType @56   (conv 0x00c98f64 -> set 0x00c98f88)
    direct-object ownerID from INHERITED ivar OBJC_IVAR_$_DynamicObject.ownerID
    @36                            (set 0x00c99000, no boxing)

Yak 0x0095dee4  [super getSaveDict] +
    numberWithFloat: milk @1136   (conv 0x0095dfe4 -> set 0x0095e008)  FIRST
    numberWithFloat: hair @1140   (conv 0x0095e044 -> set 0x0095e068)
```

Process evidence (again): three raw words in the first draft of this
batch's table were transcribed from memory and the word gates rejected all
of them (Window.ownerID set site is `blx ip`, Yak.milk conv is `blx r7`,
Yak.hair conv is `blx lr`). Every corrected value is taken verbatim from
the annotated listing. Pool-order vs execution-order held for Yak (pool
lists hair's cells first; milk is boxed and set first).

New shape this batch: SnowSurfaceBlock proves a `getSaveDictCached`
caching pattern — some block classes keep a prebuilt dict instead of
resembling one, which the replacement save layer must mirror for cache
coherence, not just key sets.

Static level-A only; 37 overrides, read-back sides and save/roundtrip
behavior unresolved.
