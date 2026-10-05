# Does any of these bodies write the clock fields? No - and what that does and does not mean

The static side says the clock/geometry fields have no writer **through the cell idiom**: `World.fastForward`
resolves to exactly one site and it is a read, `worldTime` to two reads and its own getter. A negative from
one method deserves a second, differently-shaped check, so this watches the fields for writes at run time.

Method: a write hook on the receiver watches offsets 624, 648, 660, 934, 3072, 3136, 3140, 3264 while each
method body executes. A hit would name the exact instruction that stores the field.

| method | instructions executed | field writes |
|---|---:|---:|
| `DynamicWorld:update:accurateDT:isSimulation:` | 1999 | 0 |
| `DynamicWorld:simulate:` | 249 | 0 |
| `DynamicWorld:update:accurateDT:` | 34 | 0 |
| `World:incrementalLoad` | 445 | 0 |
| `World:update:accurateDT:pinchScale:dragInProgress:` | 1527 | 0 |

Zero. And the observed run is not trivial - `DynamicWorld -[update:accurateDT:isSimulation:]` executes
1999 instructions under this receiver.

## What this does not exclude, stated before what it does

**(a)** The writes may happen inside callees, which this run **stubs** with `r0 = 0`. An executed watch on
the body cannot see a callee's stores. Not excluded.

**(b)** The fabricated receiver may send the body down an empty path so it never reaches a write. Not
excluded either.

## What it does exclude

These five bodies do **not** write these fields directly in their own instructions, under a receiver whose
pointer fields are zero. That is a narrow statement, and it is the honest size of this result.

## Why it is worth keeping anyway

It agrees with the static result through a completely different mechanism, and it turns "the static method
found no writer" into "two different methods found no writer" - so the remaining explanations narrow to a
stubbed callee, a live-only path, or an addressing form neither method models. Running the same watch
again would reproduce this, not advance it; the next step is a receiver from live state, which this
project is blocked on while the original app is not running.
