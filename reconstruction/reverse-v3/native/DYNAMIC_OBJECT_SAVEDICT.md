# DynamicObject -[getSaveDict] bounded static inventory

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

- IMP: `0x0083a7ac`
- code end: `0x0083aa70`
- ARM.exidx boundary: `0x0083aabc`
- executable words: 177
- full bounded coverage including literal pool: 196 words
- body SHA-256: `817bee107a168228c4099457cb74d3df98e1d98296cddeb700d0e9418f0eb483`
- PIC base: `0x0105faf4`

The bounded body is an assembly path, not a simple field getter. It contains
nine direct `objc_msgSend` sites and two stack-indirect `blx` sites. Independently
resolved selector cells include:

```text
dictionary
numberWithFloat:
arrayWithObjects:
setObject:forKey:
numberWithUnsignedLong:
numberWithInt:
```

The body also reads proven DynamicObject fields:

```text
pos       self + 16
floatPos  self + 24
uniqueID  self + 40
```

The result is reloaded from `[fp-0x14]` at `0x0083aa64` after the assembly
sequence. The four proven key-to-dictionary-field routes are:

```text
floatPos  -> setObject:forKey: at 0x0083a930 -> self + 24
pos_x     -> setObject:forKey: at 0x0083a99c -> self + 16
pos_y     -> setObject:forKey: at 0x0083aa00 -> self + 20
uniqueID  -> indirect setObject route at 0x0083aa60 -> self + 40
```

Both indirect call targets are now resolved through the shared GOT cell at
`0x0083aa74`, which points to the `objc_msgSend` import:

```text
0x0083aa3c: blx r3 -> objc_msgSend
0x0083aa60: blx ip -> objc_msgSend
```

The surrounding ARM32 data flow further binds both calls:

```text
0x0083aa3c: objc_msgSend(NSNumber, numberWithUnsignedLong:, self->uniqueID)
0x0083aa60: objc_msgSend(dictionary, setObject:forKey:,
                          boxed_uniqueID, "uniqueID")
```

The first call boxes `self + 40`; the second inserts that boxed value under
the proven `uniqueID` constant string. This closes the previously unresolved
uniqueID serialization route, while leaving object-type-specific fields and
the exact complete save-dict schema unresolved.

## Value-side binding of the indirect sites (regenerated batch)

`recover_dynamic_object_getsavedict.py` now additionally pins, on the hash-gated
ELF `733d8210…`:

- the three `__objc_classrefs` cells consumed by the body,
  `0x0083AA80→OBJC_CLASS_$_NSMutableDictionary@0x00E8A84C`,
  `0x0083AA8C→OBJC_CLASS_$_NSArray@0x00E8A850`,
  `0x0083AA90→OBJC_CLASS_$_NSNumber@0x00E8A854`, each verified through its
  `R_ARM_ABS32` relocation to an undefined symbol with file word `0`
  (the pointer only exists after linkmap relocation at load time);
- the two `bl` sites `0x0083A868`/`0x0083A8B4` as direct calls to
  `_ZN7Vector2cvPfEv` (`Vector2::operator float*()`), target decoded from the
  `bl` immediate, not an objc dispatch — these feed the `numberWithFloat:`
  boxings of `floatPos.x` (`ldr r2,[r0]`) and `floatPos.y` (`ldr r2,[r0,4]`);
- 34 raw provenance instruction words proving the fp-slot chain that supplies
  runtime arguments to both indirect `blx` sites, e.g. receiver reload of the
  NSNumber class from `[fp,-0x3c]`+base at `0x0083A88C/0x0083A938`, and the
  delta literal `0xFFE2AD60` at `0x0083AA90` re-basing to `0x00E8A854`;
- both indirect sites' selector cells resolved through the fp slots to
  `numberWithUnsignedLong:` (`0x0083AA7C`) and `setObject:forKey:`
  (`0x0083AA78`).

Evidence level A for the static chain; the boxed `uniqueID` value itself is a
runtime number, and the object-type-specific extra keys plus the full plist
schema remain unresolved.

This evidence proves that DynamicObject save data is assembled through a real
multi-call path. It does not yet provide a field-complete plist schema, object
construction, replacement entity integration, or original-app runtime
validation.
