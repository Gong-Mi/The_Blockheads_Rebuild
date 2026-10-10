# How much a trace depends on how the receiver was fabricated

The msgSend trace needed a receiver. `World:incrementalLoad` and friends produced no sends with an
all-zero one, so the obvious next move was a better fabrication: point every pointer-sized slot at its
own zeroed page, giving the body "an object that exists and is all zeroes" instead of "no object".

It did not produce a single send. It changed the shape of the run instead, and that is the result.

| target | all-zero receiver (instructions / call-outs / sends) | flat object graph |
|---|---|---|
| `World:incrementalLoad` | 445 / 21 / 0 | 90 / 0 / 0 |
| `DynamicWorld:simulate:` | 249 / 8 / 0 | 249 / 8 / 0 |
| `DynamicWorld:update:accurateDT:` | 34 / 1 / 0 | 34 / 1 / 0 |
| `World:update:accurateDT:pinchScale:dragInProgress:` | 1527 / 38 / 1 | 372 / 15 / 0 |

`World:incrementalLoad` goes from 445 instructions and 21 call-outs to 90 instructions and none - and
**both runs complete normally** (`stopped_by: None`). Same entry point, same selrefs, opposite-looking
behaviour, entirely because of how the receiver was invented.

## What this falsifies, and what it does not

It falsifies the hope behind the previous batch's plan: a better guess at the receiver does not turn
empty traces into structure. It also makes the earlier traces' status explicit - a structural claim read
off one fabricated receiver is **conditional on that fabrication**, and the census-style results (which
are static) are the ones that survive without a receiver.

It does not say which fabrication is closer to the truth. Both are inventions; the experiment measures
the inventions' influence, not the original's behaviour.

## Consequence for the next step

Real structure needs a receiver from **live state** - the original is running on the device, and the
project already has read-only live probes (`/proc/<pid>/maps` + `pread`) for exactly this. A receiver
copied from a live object graph, even one object deep, is a different kind of input from a page of
zeroes or a page of pointers: it is evidence rather than a choice.

## The sharpest case: the one send found earlier disappears

The previous batch's only successful trace was
`World:update:accurateDT:pinchScale:dragInProgress:` sending `setTranslation:` from 0x573548 after
1527 instructions under an all-zero receiver. Under the pointer-filled receiver the same method runs 372
instructions, makes 15 call-outs, and **sends nothing at all**.

So the receiver choice does not merely change how far the trace gets - it decides whether a send is
observed. That single data point is why no structural claim from these traces is stated as a property of
the original, and why the census results (static, receiver-free) are the ones carried forward.
