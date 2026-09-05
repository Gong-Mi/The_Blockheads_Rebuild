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
