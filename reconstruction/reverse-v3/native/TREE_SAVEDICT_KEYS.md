# Minimal tree subclass getSaveDict own-key pairings (batch 2a)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_tree_savedict_keys.py` → `tree_savedict_keys.json`.
Annotated listings (exact word coverage, gate-checked):
`disasm_appletree_getsavedict.txt` (78w), `disasm_pinetree_getsavedict.txt`
(79w), `disasm_gemtree_getsavedict.txt` (112w), emitted by the generalized
`tools/emit_annotated_method.py`.

Shape shared with DynamicObject: call `[super getSaveDict]` through the
`objc_msgSendSuper2` GOT slot, keep the returned dictionary, then insert
own keys as NSNumber boxes.

```text
AppleTree 0x009bd548  availableFood float  @136  (numberWithFloat:  0x009bd624 -> setObject:forKey: 0x009bd648)
PineTree  0x00b651bc  availableFood float  @136  (numberWithFloat:  0x00b65298 -> setObject:forKey: 0x00b652bc)
GemTree   0x0052922c  gemTreeType int      @136  (numberWithInt:    0x00529328 -> setObject:forKey: 0x0052934c)
                    fruitYear   int      @140  (numberWithInt:    0x00529388 -> setObject:forKey: 0x005293ac)
```

The availableFood float is loaded `vldr s0,[r8+ivar_offset]` from a
Tree-parent ivar at 136 in both Apple and Pine (dynsym-gated per class);
GemTree's two ints load `ldr rN,[rX+off]`. NSNumber classref cells are
ABS32-gated with zero file words.

Super-class identity gate: the classref literal re-bases to a
`__objc_classrefs` slot whose file word materialises the class struct, and
the name walk (`word(class+0x10)` ro, `word(ro+0x10)` cstr) returns the
class itself — under ARM32 `objc_msgSendSuper2` the super_data first class
pointer is the receiver's own class, so this is exactly the `[super ...]`
route, not a self-message.

One table value (GemTree super dispatch word) was written from a guess and
rejected by the raw-word gate; the listing shows `blx ip` (`3cff2fe1`).
Recorded as process evidence: the gate works.

Static level-A evidence only: the read-back (`loadSaveDictValues:` family)
for these keys, the remaining 43 overrides, and all save/roundtrip behavior
stay unresolved.
