# FreightCar -[initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:] — executed differential (batch b4h)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Boundary from the pinned ObjC method map:

```text
IMP:      0x00a403e8
boundary: 0x00a40600 (next method IMP)
words:    134 (exact coverage asserted by the b3n listing)
types:    @@:@@@@@ (4th selector variant front member)
```

The b3n decode of this method (the 4th selector variant, constructing a child
Chest from the `chestSaveDict` argument) is now **executed**:
`tools/test_freight_car_init_arm.py` runs the original ARM body under Unicorn
with synthetic world/dynamicWorld/Chest objects and compares the resulting 256-byte
instance image and the full message trace against the recovered C++
contract `reconstruction/recovered/freight_car_init.{h,cpp}` at -O0 and -O2.
`tools/test_freight_car_init_arm_evidence.py` guards it in both host and CI modes;
CTest `recovered_freight_car_init` exercises the contract without the ELF.

## Harness topology (stated limits)

* `objc_msgSendSuper2` (GOT slot 0x0105B79C) is stubbed; it verifies the struct is
  `{self, OBJC_CLASS_$_FreightCar (0x00E919D0)}`, the forwarded selector is
  `initWithWorld:dynamicWorld:saveDict:cache:`, and the arguments `(world, dynamicWorld, saveDict, cache)` match.
* `objc_msgSend` (routed through veneer 0x001C281C via GOT slot 0x0105FB18, and 0x0105B7A0) is stubbed;
  it handles:
  - `[Chest alloc]` (receiver is `OBJC_CLASS_$_Chest` 0x00E92240)
  - `[chest initWithWorld:world dynamicWorld:dynamicWorld saveDict:chestSaveDict cache:cache]`
    where `world` is read from `self->world` @ +4
  - `[chest setProxyObjectOwner:self]` (receiver is chest, arg is self)
  - `[chest setFloatPosAndUpdatePosition:self->floatPos]` (receiver is chest,
    Vector2 floatPos read from `self->floatPos` @ +24: x in r2, y in r3)
* The two-level ivar-offset resolutions execute for real:
  - `OBJC_IVAR_$_DynamicObject.world` = 4
  - `OBJC_IVAR_$_DynamicObject.floatPos` = 24
  - `OBJC_IVAR_$_FreightCar.chest` = 220

## What execution confirmed

* **4th selector variant forwards only 4 arguments to super**: `chestSaveDict` is
  swallowed by FreightCar and fed exclusively into `[Chest initWithWorld:...]`.
* **Super-nil early exit**: if `objc_msgSendSuper2` returns nil, the method exits
  immediately returning nil; no child Chest is allocated, and `self->chest` is untouched.
* **Child Chest wiring**:
  - `[Chest alloc]` returns a freshly allocated chest token.
  - `[chest initWithWorld:dynamicWorld:saveDict:cache:]` receives FreightCar's own
    `world` (`self + 4`), `dynamicWorld` (`self + 8`), and `chestSaveDict` as its `saveDict`.
  - The initialized chest pointer is stored into `self->chest` at offset 220.
  - `[chest setProxyObjectOwner:self]` passes FreightCar `self` to the chest.
  - `[chest setFloatPosAndUpdatePosition:self->floatPos]` copies FreightCar's
    2D float coordinates (`self + 24` and `self + 28`) directly to the child chest.

## Case table (7 cases, all matched bit-exactly)

* `happy_path`: normal instantiation and child chest wiring.
* `nil_super`: super returns nil; verifies early exit and untouched ivars.
* `negative_coords`: negative floating-point coordinates.
* `origin_coords`: (0.0, 0.0) coordinates.
* `large_coords`: large coordinate values (65536.0, 32768.5).
* `subnormal_coords`: subnormal IEEE-754 floats bit-exact through `vstr`/`ldr`.
* `distinct_tokens`: unique token values for each pointer/object to prove strict parameter passing.

## Ledger state

- Persistence core: 149/149 closed at static level-A.
- Executed Level-B differentials: b4a (NPC loader) + b4b (Plant) + b4c (Forwarders) + b4d (Tree stage 1) + b4e (Tree fruit records) + b4f (NPC loadValues) + b4g (Tree growth stage 1) + **b4h (FreightCar 4th selector variant)**.
