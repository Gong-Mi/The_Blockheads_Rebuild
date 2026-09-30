# Original inventory capacity methods

Original input: Android 1.7.6 ARMv7 `libApplication.so`, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## Recovered logical methods

- `Blockhead::canPickUpItemOfType:subItems:` @0x00c5d748: dynamic forwarding
  to the four-argument selector with unsigned-halfword defaults 0/0; integer
  return is forwarded without normalizing it into a bool.
- `Blockhead::canPickUpItemOfType:subItems:dataA:dataB:` @0x00c5d7b8:
  complete local decision tree in `inventory_capacity.cpp` with explicit
  dynamic receivers, field re-reads, message order and fast-enumeration boundary.
  Code/literal pools are separately bounded by `recover_inventory_capacity.py`.

The classification is 0 for invalid item or dragging, 1 for fit, -1 for exhaustion.
The pickup caller's `cmp r0,1` is therefore essential; nonzero is NOT acceptance.

The outer scan uses unsigned indexes 1 through 7, not the replacement Player's
30 flat slots. For each slot the ivar is read again. Empty arrays, matching
stacks below 99, existing carried containers and incoming containers have
separate ordered branches. Incoming containers first scan for empty subslots,
then enumerate again for merge opportunities; they are not one merged scan.
The incoming-container merge only checks dataB specially for type0x67, whereas
ordinary stackability has additional type/color restrictions. Arithmetic includes
an ARM32 unsigned count addition, preserved as uint32 rather than widened.

Money type0x12a acceptance depends on denomination and incoming A/B thresholds;
`itemTypeIsMoney` @0xc5ea38 and the slot-count helper @0xc5eaa8 are restored as
complete direct helpers. The other eight shared predicates/numerical functions
are in `inventory_rules.cpp`. Both liquid predicates are constant false in this
specific original build, not unimplemented stubs.

## Boundary

`Runtime` methods are mandatory and preserve object identity, nil dispatch,
count/object accesses, field re-reads and fast-enumeration mutation callbacks.
No production fake runtime is supplied. Tests intentionally implement synthetic
Foundation-like receivers; callback mutation tests are not real Foundation,
Objective-C ABI or concurrent execution acceptance.

The original game-wide pickup method, achievement/progression effects, original
World state and Android inventory UI are not supplied by this capacity module.
This cannot be substituted for `Player::addItem` merely because both concern
inventory. The original return is classification, not accepted item count.

## Executed verification

Parent reran the preserved child source after its 600-second timeout; timeout
was not interpreted as either no output or test success. The source executable
passes 23 named scenario groups, including slot boundaries, 98/99 limits,
mutable callback re-reads, money thresholds, existing/incoming containers,
separate enumeration passes, nil arrays, and unsigned count overflow.

`tools/test_inventory_capacity_arm.py` separately executes the original ARM
entry under Unicorn with a stated synthetic immutable ObjC message graph and
compares it to C++ O0 and O2. 3888 inputs matched, covering the flat/nil-subitems
domain, invalid/dragging/exhausted classifications and denomination boundaries.
It does not cover real Foundation, nested mutable collections, original-app
runtime or device gameplay. Results remain outside the repository:
`~/blockheads-work/gameplay-audit/capacity-arm-differential/`.

    python3 tools/recover_inventory_capacity.py --self-test --elf /absolute/original.so
    LIBUNICORN_PATH="$PREFIX/lib" python3 tools/test_inventory_capacity_arm.py \
      /absolute/original.so --output-dir /absolute/capacity-differential

On Termux the Python wheel's bundled Unicorn library was not loadable; the native
`unicorn` 2.1.4 package and its `LIBUNICORN_PATH` were used. Other platforms can
use their own working Unicorn installation. No original ELF is redistributed.
CI runs mandatory C++ contract tests and evidence guard tests without claiming
that its runner has the original input ELF.
