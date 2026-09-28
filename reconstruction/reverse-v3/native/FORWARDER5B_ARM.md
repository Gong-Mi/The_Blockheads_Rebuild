# forwarder5b — EXECUTED differential (Unicorn, five bodies)

Batch: the five shared-skeleton `initWithWorld:dynamicWorld:saveDict:cache:`
forwarders of `forwarder5b_initwithworld.json` (319 words total), executed
under Unicorn against the recovered contract
`reconstruction/recovered/object_forwarder_init.cpp` at -O0 and -O2.

Harness: `tools/test_forwarder5b_arm.py` (pinned ELF sha256
`733d8210…c94c7`); CI guard: `tools/test_forwarder5b_arm_evidence.py`
(registered as CTest `forwarder5b_arm_evidence` — constants in CI, full
differential with `--elf` on the host).

## Entries and cells (from the batch evidence json)

| class | type | IMP | words | superref cell | hook |
|---|---|---|---|---|---|
| SurfaceBlock | 22 | 0x00812E64 | 57 | 0x00E8BD70 | — |
| SnowSurfaceBlock | 29 | 0x00D8D89C | 71 | 0x00E8BF38 | initSubDerivedItems |
| HandCar | 41 | 0x00A4F564 | 60 | 0x00E8BE2C | — |
| PassengerCar | 44 | 0x0081BCC8 | 60 | 0x00E8BD78 | — |
| Mirror | 64 | 0x00A9F434 | 71 | 0x00E8BE5C | initSubDerivedItems |

## What the execution asserts (per class × {nil-super, happy})

- `objc_msgSendSuper2` receives the struct {self, own-class-from-the-superref-
  cell}, the loader selector, and the four live argument pointers.
- Super-only bodies never reach the hook dispatch; the two 71-word bodies call
  `initSubDerivedItems` on self exactly once after a non-nil super.
- Return register: self on happy, 0 on nil-super.
- The 128-byte instance window stays all-zero — the executed counterpart of
  the batch's "reads no CFString key and writes no own ivar" claim.
- Trace bits (bit0 super, bit1 hook, bit31 returned-nil) equal the contract
  at both optimisation levels; the three super-only traces are identical to
  each other, and the two hooked traces are identical to each other.

Result: 10/10 cases match (see the harness's
`forwarder5b-arm-result.json` for the per-row traces).

## Promotion effect

Types 22 / 29 / 41 / 44 / 64 stop being "listing-decoded forwarders" and
carry an executed differential for their own bodies; the record-domain
claims of the mid-tier and TrainCar modules (reason strings) point at this
harness. The super chain each body forwards into keeps its own grade:
DynamicObject base (executed), TrainCar chain (listing decode),
InteractionObject 352-word init (executed, its own differential).

Boundary: Unicorn with a synthetic ObjC graph — not Foundation, not the
original-app runtime, not device gameplay. The difference from the device
run (0.2-b5e all-types pass) is that this proves the *original* bodies'
behaviour, the device pass proves the recovered C++ loaders end to end.
