# A msgSend trace of a needs-runtime method

Target: `-DynamicWorld update:accurateDT:isSimulation:` at `0x8cbf40` (`v20@0:4f8f12c16`).
Tool: `tools/trace_msg_sends.py` (+ `dynworld_update_send_trace.json`).

## Grade, up front

**Executed, with a fabricated receiver and stubbed sends.** A recorded `(site, selector)` is a fact
about this body: the instruction really does reach the shared trampoline with that SEL. Nothing about
the callee and nothing about any return value is observed - returns are invented as 0 - so **every send
after the body first branches on a stubbed result is not shape-faithful**. This trace is the first
cycle; the repetition below it is an artifact of stubbing, not a property of the original.

## The first cycle

| site | selector | receiver |
|---|---|---|
| `0x8ce148` | `update:accurateDT:isSimulation:` | `0x0` |
| `0x8ce164` | `needsRemoved` | `0x0` |
| `0x8ce694` | `sendNetDataIfNeededForObject:isCreation:` | `0x30000000` |
| `0x8ce6b0` | `needsRemoved` | `0x0` |

Four sends, one of them **a send of the method's own selector** - the body reaches
`-update:accurateDT:isSimulation:` recursively - and one that lands on the fabricated receiver
(`0x8cbf40`'s self, i.e. the DynamicWorld) while the rest address a pointer that is 0 in this
run. The cycle repeats indefinitely because `needsRemoved` is stubbed to return 0, so the loop's exit
condition never changes. That repetition is the measurement's ceiling, not a finding.

## What it cost to get a selector name out

The SEL handed over is a **file VA, not a mapped address**: at the first send r1 is `0xef9dc7`, and the
bytes at that offset in the .so spell `update:accurateDT:isSimulation:`. Resolving the name therefore
needs the image bias added - reading at the raw value faults and every selector comes back unresolved.
That failure mode is worth remembering because it looks like "the trace has no selectors" rather than
"the resolver is missing a bias".

## What this run had to abstract away, all counted in the artifact

| abstraction | count | what it costs |
|---|---:|---|
| VFP instructions skipped | 16 | Unicorn's default ARM model rejects them (`UC_ERR_INSN_INVALID`), so float values are unobserved - this method opens with the x20 division |
| zero pages invented on unmapped reads | 3 | a fabricated receiver's pointer fields are 0, so the body walks into an object graph that is entirely zeroes |
| calls out of the loaded image | 23 | callees are stubbed with `r0 = 0`; the trace records where |
| unresolved selectors | 0 | should be 0 - a non-zero value means the bias fix regressed |
| instructions executed | 1999 | - |

## Boundary worth stating plainly

This produces structure, not semantics. It cannot tell you what `needsRemoved` returns, and a body that
branches on a stubbed value is only traced up to that branch. The reconstruction's open questions about
this method - where the x20 division sits relative to what - are not settled by it; what it does settle
is that the top-level body sends exactly these four selectors from these four sites.

## The gate the trace's loop kept calling, identified statically

The repeated cycle above calls `needsRemoved` twice per iteration. There is exactly **one**
implementation of that selector in the whole binary - `DynamicObject -[needsRemoved]` at `0x83d0f0` -
and it is the ordinary `char` getter shape, so it executes under the same harness as the world flags:

    slot 0x105c3c8 · cell 0xf33e44 · offset 48 · kind char
    0x00 -> 0, 0x01 -> 1, 0x7F -> 127, 0x80 -> -128, 0xFF -> -1, plus the cell-rewrite control

The field at offset 48 is named by the symbol table independently of the getter: needsRemoved
(cell `0xf33e44`). So the loop's exit condition is a one-byte ivar on the
DynamicObject, and the trace looping forever is fully explained by stubbing that getter to 0: nothing is
ever "removed", so the loop's condition never changes.

### The layout that explains it

Enumerating `DynamicObject`'s ivars by switching on each symbol's cell content shows a run of adjacent
**one-byte flags**, which is why this family's accessors all share the `ldrsb` shape:

| offset | ivar |
|---:|---|
| 4 | `world` |
| 8 | `dynamicWorld` |
| 12 | `macroTileOwner` |
| 16 | `pos` |
| 24 | `floatPos` |
| 32 | `cache` |
| 36 | `ownerID` |
| 40 | `uniqueID` |
| **48** | **`needsRemoved`** |
| 49 | `updateNeedsToBeSent` |
| 50 | `creationDataNeedsToBeSent` |
| 51 | `unreliableUpdateNeedsToBeSent` |
| 52 | `isNet` |

Five flags at 48..52, each one byte. One of them gates the update loop; the others are network-dirty
bits for an object that is `isNet` or not. That is a shape the reconstruction can use directly, and it
came from two independent sources - the getter's own cell and the symbol table - naming the same thing.
