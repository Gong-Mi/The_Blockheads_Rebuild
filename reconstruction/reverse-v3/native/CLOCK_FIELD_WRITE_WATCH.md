# Who writes the clock/geometry fields? An empty watch, and the chain that explains it

The static side says these fields have no writer through the cell idiom except where a setter exists. A
negative from one method deserves a differently-shaped check, so the trace tool watches offsets for
WRITES while a body runs - including writes that land **inside a zero page the run invented** for a NULL
pointer field, because watching only "offset relative to the receiver" misses `otherObject->field`, which
is precisely the indirection a fabricated receiver creates.

| method | instructions | field writes | invented pages watched |
|---|---:|---:|---:|
| `DynamicWorld:update:accurateDT:isSimulation:` | 1999 | 0 | 3 |
| `World:update:accurateDT:pinchScale:dragInProgress:` | 1527 | 0 | 2 |
| `World:incrementalLoad` | 445 | 0 | 1 |
| `DynamicWorld:simulate:` | 249 | 0 | 0 |

Zero, with the indirection hole closed.

## The chain that explains it

1. **executed**: `World -[update:accurateDT:pinchScale:dragInProgress:]` sends **`setTranslation:`** from
   0x573548.
2. **static**: `World -[setTranslation:]` @0x5531d0 writes cell `0xf328d4` - and it is the **only** write
   site for `translation`, at 0x553204. It is reported as a write only because of the fused-store fix;
   before that fix it would have shown as unknown.
3. **field**: cell `0xf328d4` is `World.translation`, offset 624.
4. **executed**: the pinch body itself writes offset 624 zero times.

So the negative is explained rather than mysterious: **the write lives in a callee, and this run stubs
callees with `r0 = 0`.** Executed trace -> selector -> static setter -> write site -> field offset is a
complete chain, each link from a different instrument.

## What remains excluded, and what remains open

Excluded: these five bodies do not write these fields in their own instructions, nor one indirection into
an object the run invented. Open: a write inside a stubbed callee (the chain above shows this is not a
hypothetical), and any path a fabricated receiver never takes.

One more open item, recorded rather than chased: the corrected site scan reports **0** sites for cell
`0xf32b6c` (`World.sunDirection`) even though its own getter materialises it - so that scan's pattern or
window misses one shape, while the value-level tools derive it without trouble. That is a tool question,
not a fact about the binary.
