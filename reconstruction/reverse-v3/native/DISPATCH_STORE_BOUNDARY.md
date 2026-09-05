# Dispatch store boundary follow-up

Input: original libApplication.so SHA-256
733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7.

## Verified change

Non-writeback ARM strb/strh do not overwrite their input CPU registers.
The analyzer now retains register facts while invalidating saved stack words
conservatively. Writeback/post-indexed forms still invalidate all state.

Regression: ldr r3(import); ldr r1(selector); strb r0,[r2]; blx r3
was unknown before this change, now retains the selector candidate.
A byte store overlapping a saved word must not restore the stale selector.

Local tests: 12 synthetic dataflow tests plus one original ELF test pass.
Actual drawFrame output remains 11 calls / 2 candidates, not an increase:
0x00781b28 removeFromSuperview; 0x00781b4c release.

## Why later calls remain unknown

Instrumenting transfer states (diagnostic only, no source instrumentation committed)
shows 0x00781bc4 initially has objc_msgSend and a constant r1 on one predecessor.
After all predecessor states merge, those facts are removed.
The earlier path through 0x00781b64 (`str r2, [r0]`) invalidates saved stack facts,
including fp-0x34, the PIC base used at 0x00781b6c. The alternate path retains it.
The join therefore cannot retain a common PIC-base fact.

This is a precision boundary, not proof that the original call is dynamic.
Do not fix it by retaining every stack slot across arbitrary stores: an unknown
pointer can alias a local. Next work needs receiver/object-pointer provenance,
stack-address escape handling, or independent bounded native evidence proving
this particular destination cannot alias fp-0x34. The generic alias rule remains.

No runtime tracing, receiver recovery, game launch or device acceptance performed.

## Stack-word alias regressions

Two further false candidates were reproduced and fixed:

- A word stored at fp-0x1f partially overwrites a saved selector at fp-0x20.
  Invalidating only an exactly equal dictionary key retained stale bytes.
- A store through sp may alias an fp-relative slot when their base relation is
  not modelled. Treating the two key namespaces as disjoint was unsound.

Word stores now invalidate intersecting same-base four-byte intervals and all
slots using another unproven frame base. Non-overlapping same-base slots remain.
Local acceptance: 15 dependency-free tests plus the original ELF test pass;
original drawFrame remains 11 calls / 2 candidates.

Next precision work should canonicalize fp/sp to a proved stack coordinate,
including prologue adjustments, rather than deleting this alias invalidation.

## Bounded native destination recovered

`tools/recover_drawframe_background_store.py` has been executed against the pinned
original ELF. It validates 12 ARM instruction words before reporting:

- PIC base: 0x0105faf4
- ivar GOT slot: 0x0105d6cc (R_ARM_RELATIVE, nonzero file addend)
- ivar-offset symbol address: 0x00f33884
- symbol: OBJC_IVAR_$_EvolutionViewController.tempBackgroundView
- ivar byte offset: 44
- store at 0x00781b64: 32-bit zero to self + 44

The bounded path removes the temporary background view from its superview,
releases it, then clears the ivar. The zero is saved at fp-0x38 and restored
into r2 immediately before the store; the ivar-offset pointer is saved at fp-0x3c.

This supplies field semantics, NOT a generic proof of entry receiver/stack
non-aliasing. The analyzer's unknown-store invalidation remains unchanged.
In particular, a symbol name and known ivar offset cannot alone prove the
runtime address of self; do not turn the candidate chain into universal alias facts.

Reproduce (radare2 not required; pyelftools required):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_drawframe_background_store.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output "$TMPDIR/blockheads-background-store.json"
```
