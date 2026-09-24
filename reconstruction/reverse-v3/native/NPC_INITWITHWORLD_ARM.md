# NPC loader — executed (level-B) ARM verification — batch b4a

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

This batch promotes the b3g decode of
`-[NPC initWithWorld:dynamicWorld:saveDict:cache:]` (0x00644b24, 95 words) from
static level-A to **executed** evidence:

- `reconstruction/recovered/npc_init_with_world.{h,cpp}` — the recovered
  contract (`npc_hunger_timer_seed`, `npc_init_with_world`), built by CMake as
  `blockheads_recovered_npc` with `-fno-fast-math -ffp-contract=off`.
- `tools/test_npc_init_with_world.cpp` — CTest contract
  (`recovered_npc_init_with_world`), runs in CI without the original ELF.
- `tools/npc_init_with_world_arm_bridge.cpp` — bridge built at **-O0 and -O2**
  exporting the timer bits and the call-order trace.
- `tools/test_npc_initwithworld_arm.py` — executes the **original ARM method**
  under Unicorn and compares against both C++ builds.
- `tools/test_npc_initwithworld_arm_evidence.py` — CI-safe guard: with the
  pinned ELF + Unicorn present it runs the differential, otherwise it asserts
  the contract, the shared case list, and the registrations.

Result of the executed differential (Termux, Unicorn 2.1.4, VFP enabled via
CPACR/FPEXC):

```text
method  initWithWorld:dynamicWorld:saveDict:cache:   class NPC   entry 0x00644b24
cases   15 (14 lrand48 values + the nil-super path)
match   true — arm_timer_bits == cpp(O0) == cpp(O2) for every case,
        call order == super → loadValuesFromSaveDict: → lrand48
```

What actually executed from the original binary: the whole 95-word body,
including the real `bl 0x006445d8` wrapper and the real ABI veneer
`0x001c2804` — only the veneer's final slot (`0x0105fb10`, imported `lrand48`)
is patched to a stub, so the wrapper chain is part of the evidence, not a
stub. `objc_msgSendSuper2` and `objc_msgSend` are synthetic: the super stub
asserts the struct is `{self, OBJC_CLASS_$_NPC}`, the selector is the loader
selector, and the four arguments are the harness pointers; the send stub only
answers `loadValuesFromSaveDict:` with the save-dict argument checked. The
nil-super run verifies the guard: return 0, no hook call, no `lrand48` call,
and the timer slot untouched.

**Finding that only execution could produce** — the decoded range is
`[1.0, 21.0]`, not `[1.0, 21.0)`: `(float)2147483647` rounds up to
`2147483648.0f`, so `lrand48` values at the top of the range (from about
`2^31 - 2^7`) land on exactly `21.0f`. The b3g JSON/MD and the contract test
were corrected accordingly; the ARM differential is what caught it.

Boundaries (unchanged honesty rules): this is emulated original ARM with a
synthetic message graph — **not** Foundation, **not** the original-app runtime,
**not** device gameplay; the superclass initialiser and the
`loadValuesFromSaveDict:` body are stubs, and results stay outside the
repository (`~/blockheads-work/methods-save/scratch/npc-arm-differential/`).
CI runs the C++ contract test and the evidence guard only.
