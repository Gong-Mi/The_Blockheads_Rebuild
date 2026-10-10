# Three `World` getters executed under Unicorn, with failure-capable controls

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

## Second target: `-[World fastForward]` (a `char`, and a stronger control)

Chosen for what it tests that the double cannot: the value returns in `r0`, so **nothing has to be
abstracted** - there is no VFP epilogue to skip - and `ldrsb` means the result must be sign-extended:

| planted at `self + 934` | returned | expected |
|---:|---:|---:|
| `0x00` | 0 | 0 |
| `0x01` | 1 | 1 |
| `0x7F` | 127 | 127 |
| `0x80` | **-128** | -128 |
| `0xFF` | **-1** | -1 |

`0xFF -> -1` is the ivar's **encoding** verified by execution, not merely its offset - which is the
step before this one (the offset came from the cell) plus one more. Controls: with the cell rewritten
to 640 and `7` planted at `self + 640` (decoy `99` at `self + 934`) the getter returns 7; with the cell
back at 934 and `3` planted (decoy `-5` at `self + 640`) it returns 3.

## Third target: `-[World doubleTimeUnlocked]` (same 60-byte shape)

Added because it costs nothing and because its .got slot was DERIVED rather than guessed: the getter's
own pool word `0x5d9e98 ldr r3,[pc,#0x20]` gives `wA = 0xffffcde4`, and `wA + PIC base 0x105faf4 =
0x105c8d8` whose contents are this ivar's cell `0xf32a98`. Same controls, same result: `0x00 -> 0`,
`0x01 -> 1`, `0x7F -> 127`, `0x80 -> -128`, `0xFF -> -1`, with both cell-rewrite negatives holding.

## Which methods are worth this treatment

The recipe is mechanical, so the choice is too. Count the calls in the body and look for VFP:

| method | bytes | calls | external | VFP | verdict |
|---|---:|---:|---:|:--:|---|
| `worldTime` | 100 | 1 | 1 | yes | needs one abstraction (the copy stub) |
| `fastForward`, `doubleTimeUnlocked`, `isAdmin`, `serverMinorVersion` | 60 | 0 | 0 | no | **runs with no abstraction at all** |
| `serverClients`, `server`, `client`, `worldName`, `serverPassword`, `clientPassword`, `serverPrivacySetting` | 68 | 0 | 0 | no | same, slightly larger bodies |
| `startPortalPos` | 96 | 1 | 1 | no | needs abstraction |
| `serverFillReply` | 576 | 6 | 6 | no | needs a runtime |
| `clientDisconnected:wasKick:` | 972 | 11 | 11 | yes | needs a runtime |

That table is why `worldTime` was hard and `fastForward` was free - not luck.

## A limit on the static map's METHOD attribution (corrects an earlier claim)

`IVAR_CELL_REFERENCES.md` says `World.fastForward`'s cell has exactly one resolving site. That is
still true, and the tool itself marks its attribution `ambiguous` - because the one-line getters
(`startPortalPos`, `serverClients`, `server`, `client`, `fastForward`, `doubleTimeUnlocked`, ...) share
one enclosing body, so the prologue walk lands on `0x5d9d24` for all of them. What is reliable is the
CELL (the slot's contents equal the cell VA). Earlier I reported that single site as "its own getter",
which the map never claimed; the executed evidence here is what actually ties `0x5d9e50` to offset 934.

## Why it matters beyond this method

`COVERAGE_AUDIT.md` records the 世界/主域 subsystem as 12 methods with **0 executed**. This is one of
them, executed and checked. It also gives the project a working recipe for the lens it has never had:
map the ELF at an offset, fabricate the receiver, intercept the lazy trampolines, and compare against
planted values - the same shape the repo's `*_arm_bridge.cpp` differentials use.
