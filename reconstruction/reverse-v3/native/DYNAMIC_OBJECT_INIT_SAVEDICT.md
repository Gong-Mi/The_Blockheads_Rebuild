# DynamicObject saveDict initializer boundary

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

Method:

- `DynamicObject -[initWithWorld:dynamicWorld:saveDict:cache:]`
- IMP `0x00839f7c`
- code end `0x0083a368`
- ARM.exidx boundary `0x0083a3c0`
- 251 executable words / 273 full bounded words
- PIC base `0x0105faf4`

Entry ABI evidence stores:

```text
saveDict argument [fp+8]  -> [fp-0x30]
cache argument   [fp+12] -> [fp-0x34]
```

The bounded body resolves these selectors:

```text
init
initDerivedStuff:loadPhysicalBlockIfNeeded:
objectForKey:
objectAtIndex:
floatValue
intValue
unsignedLongValue
```

Dispatch imports are separately resolved as `objc_msgSendSuper2` and
`objc_msgSend`. A nil saveDict gate returns before the field initialization
path. Numeric conversion selectors prove that saveDict values are consumed,
but this slice does not assign their key names or claim the complete field map.

The next method-specific work is to trace each `objectForKey:` key argument to
its CFString/data source and pair it with the exact ivar write. Until that is
done, no plist field is promoted into the replacement entity model.
