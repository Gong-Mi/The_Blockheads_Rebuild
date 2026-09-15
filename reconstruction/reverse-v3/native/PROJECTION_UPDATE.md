# GameView projection update — full bounded recovery

## Scope and evidence

Recovered `GameView.pinchScaleChanged` at `0x0092ef38` (last instruction
`0x0092f14c`) and **every instruction** of matrix helper `0x0092f170` through
`0x0092f290`, plus both literal pools. `recover_projection_update.py` obtains
r2 disassembly and independently checks all **216 words** against the pinned
ELF, without interpreting rendered floating immediates as authoritative.
ELF SHA-256: `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

PIC literal/slot/exported-symbol chains establish these GameView fields:
`pinchScale=152`, embedded `windowInfo=208`, `projectionMatrix=48`, `cameraZ=112`.
The callback copies exactly 64 helper-result bytes to the matrix field and
stores the final float at cameraZ. The returned value is now consumed by the recovered
FrameRuntime::pinchScaleChanged wrapper, which writes the typed GameViewState
matrix and cameraZ. This method-module integration is not an Android game adapter.

**Naming boundary:** the recovered callback only proves `windowInfo` float
lanes at +0 and +4. It does not establish dimension units or the upstream
construction of those lanes. Therefore `ProjectionInput` uses `double
pinchScale; float lane0; float lane1;`, NOT speculative `windowWidth/Height`.
The caller must explicitly pass the original lanes.

## Exact arithmetic and branches

Let F denote binary32 rounding after each elementary operation and D binary64.
`scale = pinchScale < 1.0 ? pinchScale : 1.0` (VCMPE/BPL; unordered selects 1).
The literal at `0x92f150` is binary64 bits `0x3ff0c15240000000`, exactly
`1.0471975803375244` / `0x1.0c1524p+0`. This is the widened binary32
approximation of PI/3, **not** a fresh binary64 PI/3 computation.

```
angle = F(D(0x1.0c1524p+0 * scale))
if lane0 > lane1:                    # VCMPE/BLE skips for <= or unordered
    angle = F(angle * F(lane1/lane0))
aspect = F(lane0/lane1)
cot = F(1 / tanf(F(angle/2)))
near = 1; far = 2048
cameraZ = F(F(lane1 * 0x1.99999ap-6f) /
            F(2 * tanf(F(angle * 0.5f))))
```

The first multiplication alone is binary64; everything after its conversion
is binary32, including both **separate** tanf calls. Operand order and staging
are retained. Compile with `-fno-fast-math -ffp-contract=off`.
The pool float at `0x92f164` has bits `0x3ccccccd` (rounded 0.025).
VFP immediate at `0x92f094`, opcode `0xeeb60a00`, imm8 `0x60`, expands to
**0.5**, despite this r2 rendering `vmov.f32 s0, 5`. All seven VFP immediates
are decoded from bit fields and recorded with their words in the JSON.
Near/far arrive as core-register/stack float bits `0x3f800000/0x45000000`.

## Complete helper storage

The helper accepts output pointer r0, angle bits r1, aspect bits r2, near bits
r3, far bits at caller sp+0. No missing branches or unreviewed callee except
the platform `tanf` import. It writes all 16 consecutive floats:

| float index | exact value |
|---|---|
| 0 | F(cot/aspect) |
| 5 | cot |
| 10 | F(F(far+near)/F(near-far)) |
| 11 | -1 |
| 14 | F(F(F(2*far)*near)/F(near-far)) |
| 1,2,3,4,6,7,8,9,12,13,15 | positive zero |

This array is the conventional column-major perspective layout if consumed
by a column-vector API: -1 is at offset 44 and depth product at offset 56.
**Proved contract is exact memory order**, not a guessed transposition or a
proof of the eventual GLES upload/consumer convention. No external matrix
library/formula was substituted for the helper's reviewed stores.

## Exceptional inputs and fidelity limits

No lower scale clamp, dimension validation, error return, finite check, or
fallback exists in these bodies; none was added. Zero/negative dimensions,
negative scales, infinities and NaNs flow through IEEE arithmetic and tanf.
NaN pinch selects scale=1; NaN in either lane skips the aspect correction but
still propagates through subsequent lane divisions. Signed zeros are retained.
The tests compare all non-NaN results bitwise, including signed zero and
infinity, while accepting any NaN payload. Original ARMv7 vs current host libm
last-bit differences, FPSCR flush-to-zero/default-NaN modes, signaling-NaN
exceptions, fenv flags and errno are **not** established by this local test.
The full recovered update method now invokes this dependency (see GAMEVIEW_METHOD.md).
No original-runtime differential, game foreground interaction or Android gameplay
adapter integration is claimed by these numerical tests.

## Executed acceptance

Behavioral RED: a compilable zero-result implementation failed at
`helper must store -1 at float index 11` (exit 1), not at a missing header/API.
GREEN after full implementation: both local clang++ O0 and O2 returned:

```
PASS projection_update: 54405 checks (3200 inputs + anchors)
```

The 3200 inputs comprise 1200 combinations of exceptional/ordinary dimensions
and scales plus 2000 deterministic finite rounding probes. Anchors separately
check depth slots, FOV/cotangent, cameraZ and upper scale cap. The independent
reference models individual binary32 register operations with volatile
rounding barriers; this is a local recovered-contract test, not an oracle
executing the original ARM ELF.

Reproduction from repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python tools/recover_projection_update.py \
  ~/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so
for opt in 0 2; do
  clang++ -std=c++17 -Wall -Wextra -Werror -O$opt \
    -ffp-contract=off -fno-fast-math -I reconstruction/recovered \
    tools/test_projection_update.cpp reconstruction/recovered/projection_update.cpp \
    -o "$TMPDIR/test_projection_update_O$opt" && \
    "$TMPDIR/test_projection_update_O$opt" || exit
done
```

Owned output paths:
- `reconstruction/recovered/projection_update.h`
- `reconstruction/recovered/projection_update.cpp`
- `tools/test_projection_update.cpp`
- `tools/recover_projection_update.py`
- `reconstruction/reverse-v3/native/disasm_projection_update.txt`
- `reconstruction/reverse-v3/native/projection_update.json`
- `reconstruction/reverse-v3/native/PROJECTION_UPDATE.md`
