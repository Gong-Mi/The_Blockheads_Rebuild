# `-[World worldTime]` executed under Unicorn

Evidence grade: **B+** - the original's own ARM code runs and its result is checked against values the
harness plants, but two pieces are abstracted and are named here rather than glossed.

Artifact: `worldtime_getter_emulation.json`. Tool: `tools/emulate_worldtime_getter.py`
(+ `tools/test_emulate_worldtime_getter.py`).

## What ran

The getter (IMP `0x5d99a4`) was executed over the pinned ELF mapped at `vaddr + 0x10000000`, with a
fabricated World object, a stack and a return sentinel:

| planted at `self + 648` | returned | bit-exact |
|---|---|---|
| 900.0 | 900.0 | yes |
| 123.5 | 123.5 | yes |

So the original returns the double stored at `self + 648`, and it gets there through its own cell
arithmetic - `ldr r1,[pc,#k]` -> `*.got` slot whose contents are the cell VA -> `ldr` the cell's
runtime offset -> `add r1, self, r1`. That chain is what `IVAR_CELL_REFERENCES.md` maps statically;
this artifact shows it executing.

## The control that makes it evidence

A "returns what you planted" demo proves nothing on its own, so the cell is rewritten:

```text
cell := 640, self+640 = 42.25, self+648 = 999.0 (decoy)   ->  returned 42.25
cell := 648, self+648 = 7.5,   self+640 = 1234.0          ->  returned 7.5
```

The returned value follows the cell. A hard-coded 648 would have returned the decoy, and the first
version of this control was worthless for a different reason - it cleared the object and wiped its own
marker, so it could not have distinguished the two offsets at all (the artifact records the corrected
form, and the test refuses to pass without the decoy).

## The two abstractions

1. `bl 0x1c2888` is intercepted and served by a host memcpy. That address is a **lazy** trampoline
   chain (`0x1c2888` -> slot -> `0x1c27c0` -> a further lazy pointer) which the real loader fills at
   run time; the repo's own ARM bridges abstract the runtime the same way.
2. The double is read from the buffer the original's own code copied into, not from the ABI return
   path, because its epilogue is `vldr d0,[fp,#-8]` - a VFP instruction Unicorn's default ARM model
   rejects with `UC_ERR_INSN_INVALID`. The value is still produced by the original's code; what is not
   emulated is the VFP move.

## Why it matters beyond this method

`COVERAGE_AUDIT.md` records the 世界/主域 subsystem as 12 methods with **0 executed**. This is one of
them, executed and checked. It also gives the project a working recipe for the lens it has never had:
map the ELF at an offset, fabricate the receiver, intercept the lazy trampolines, and compare against
planted values - the same shape the repo's `*_arm_bridge.cpp` differentials use.
