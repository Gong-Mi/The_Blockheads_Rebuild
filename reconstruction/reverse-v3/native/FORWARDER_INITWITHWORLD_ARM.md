# Forwarder convention — executed (level-B) ARM verification — batch b4c

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Third executed slice, after b4a (NPC) and b4b (Plant): the five 74-word
`-[initWithWorld:dynamicWorld:saveDict:cache:]` forwarders frozen statically in
b3f now run as original instructions.

- `reconstruction/recovered/object_forwarder_init.{h,cpp}` — class-agnostic
  recovered contract for the convention (CMake target
  `blockheads_recovered_forwarder`).
- `tools/test_object_forwarder_init.cpp` — CTest contract
  (`recovered_object_forwarder_init`), CI-visible without the ELF.
- `tools/object_forwarder_init_arm_bridge.cpp` — -O0/-O2 bridge exporting the
  trace bits.
- `tools/test_forwarder_arm.py` — executes all five entries × {super returns
  self, super returns nil}.
- `tools/test_forwarder_arm_evidence.py` — CI-safe guard (runs the differential
  when ELF+Unicorn exist; otherwise asserts the contract, the registrations and
  the b3f decode).

Result (Termux, Unicorn 2.1.4):

```text
entries  ClownFish 0x0078e420 · Shark 0x007c8918 · Scorpion 0x00893d58 ·
         Dodo 0x00a6b7dc · DonkeyLike 0x00ab0c3c
cases    10 (5 entries × {happy, nil-super})
match    true — arm_trace == cpp(O0) == cpp(O2) for every case
identical_traces_across_entries  true
```

Executed from the original binary: all five 74-word bodies in full (the shared
69-word skeleton plus each class's literal pool). The super stub asserts, per
entry, that the `objc_msgSendSuper2` struct is `{self, OBJC_CLASS_$_<that
class>}` — the class pointer is read from that entry's own
`__objc_superrefs` cell, so a wrong superref could not pass — that the selector
is the loader selector, and that the four forwarded arguments are the harness
pointers. The hook stub asserts the zero-argument `loadDerivedStuff` call on
`self`. Happy path: `super → hook → return self`; nil-super path: `super →
return nil` with **no hook call**.

Why this is more than a repeat of b4a: b3f proved the five bodies are
byte-identical modulo their literal cells *statically* (sha256 over the 69-word
skeleton); this batch is that claim's executed counterpart — five separate
entries, five different class objects and selector cells, producing identical
traces and identical returns. The convention
`[super …] → nil guard → [self hook] → self` is therefore verified by execution
for a whole family, not for one method.

Boundaries (unchanged): synthetic message graph — not Foundation, not the
original-app runtime, not device gameplay; the superclass initialiser and the
`loadDerivedStuff` body are stubs; results stay outside the repository
(`~/blockheads-work/methods-save/scratch/forwarder-arm-differential/`). CI runs
the C++ contract test and the evidence guard only.
