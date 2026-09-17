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
seven `objc_msgSend` sites and two unresolved indirect `blx` sites. Independently
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
sequence. Three objc_msgSend sites and both indirect calls remain unresolved;
serialized key names, object-type-specific fields, and the exact save-dict
schema are intentionally not inferred from selector names.

This evidence proves that DynamicObject save data is assembled through a real
multi-call path. It does not yet provide a field-complete plist schema, object
construction, replacement entity integration, or original-app runtime
validation.
